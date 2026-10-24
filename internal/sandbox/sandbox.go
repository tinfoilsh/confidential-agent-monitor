// Package sandbox attests sandbox boots, enrolls their Monitor identity and serves owner shells.
package sandbox

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"golang.org/x/crypto/ssh"
)

const (
	// BootstrapUser prefixes the SSH user a sandbox boot publishes its bootstrap route as.
	BootstrapUser = "sandbox-v2:"
	// WorkspaceKeyBytes is the length of an enrollment's disk_key.
	WorkspaceKeyBytes = 32
	// MaxRequestBytes bounds an enroll or shell request body.
	MaxRequestBytes = 1 << 18

	sandboxLoginUser           = "sandbox"
	sandboxAttestationURL      = "http://sandbox/.well-known/tinfoil-attestation"
	sandboxHostKeyID           = "host-ssh"
	sandboxAgentInfo           = "tinfoil monitor web sandbox agent v1"
	sandboxNameCharacters      = "abcdefghijklmnopqrstuvwxyz0123456789-_."
	maxSandboxNameBytes        = 128
	maxSandboxAttestationBytes = 32 << 20
	maxSandboxReplyBytes       = 1 << 12
	sandboxConnectTimeout      = 2 * time.Minute
	// Formatting a new workspace can take minutes.
	sandboxCommandTimeout = 10 * time.Minute
)

// Monitor is everything the sandbox package may use of the Monitor.
type Monitor interface {
	// Boot is the boot enrolled for an identity, or zero.
	Boot(name string) Boot
	HostKey() ssh.Signer
	DialSSH(hostKey ssh.PublicKey) (net.Conn, error)
	DialBootstrap(user string) (net.Conn, error)
	// CheckIdentity reports whether AddIdentity would accept the identity, without changing policy.
	CheckIdentity(name, key string, boot Boot) error
	AddIdentity(ctx context.Context, name, key string, boot Boot) error
}

// Verifier proves what a boot's attestation document endorses.
type Verifier func(doc, nonce []byte, source string) (*Evidence, error)

// Service holds the owner's open sandbox terminals by ID.
type Service struct {
	monitor Monitor
	verify  Verifier

	mu     sync.Mutex
	shells map[string]*shellSession
}

func New(m Monitor, verify Verifier) *Service {
	return &Service{monitor: m, verify: verify}
}

// access selects one sandbox boot and holds the seed of its measured owner key.
type access struct {
	OwnerSeed []byte `json:"owner_seed"`
	Boot
}

// Boot is what a boot must attest before the Monitor logs in to it. The source
// pins the config digest, which also measures the sandbox's owner key.
type Boot struct {
	Source     string `json:"source"`
	InstanceID string `json:"instance_id"`
}

// Evidence is what verified attestation proves about one sandbox boot.
type Evidence struct {
	HostKey ssh.PublicKey
	Expires time.Time
}

func (a access) validate(name string) error {
	if name == "" || len(name) > maxSandboxNameBytes || strings.Trim(name, sandboxNameCharacters) != "" {
		return fmt.Errorf("sandbox identity name must be 1-%d of %q", maxSandboxNameBytes, sandboxNameCharacters)
	}
	if len(a.OwnerSeed) != ed25519.SeedSize {
		return fmt.Errorf("owner_seed must be %d bytes", ed25519.SeedSize)
	}
	return a.Boot.Validate()
}

func (b Boot) Validate() error {
	if _, _, digest, err := verify.ParseReference(b.Source); err != nil || digest == "" {
		return errors.New("source must be a digest-pinned release reference")
	}
	if b.InstanceID == "" {
		return errors.New("instance_id is required")
	}
	return nil
}

// agentKey derives the sandbox's Monitor identity from its owner seed. The derivation is
// specific to web enrollment, so repeating it keeps one identity and CLI keys never change.
func (a access) agentKey() (ed25519.PrivateKey, ssh.PublicKey, error) {
	seed, err := hkdf.Key(sha256.New, a.OwnerSeed, nil, sandboxAgentInfo, ed25519.SeedSize)
	if err != nil {
		return nil, nil, err
	}
	defer clear(seed)
	private := ed25519.NewKeyFromSeed(seed)
	public, err := ssh.NewPublicKey(private.Public())
	return private, public, err
}

// connect attests the boot through its bootstrap route, then logs in with signer
// over the route of the endorsed SSH host key.
func (svc *Service) connect(ctx context.Context, boot Boot, signer ssh.Signer) (*ssh.Client, error) {
	ctx, cancel := context.WithTimeout(ctx, sandboxConnectTimeout)
	defer cancel()
	evidence, err := svc.attest(ctx, boot)
	if err != nil {
		return nil, err
	}
	client, err := svc.login(ctx, evidence.HostKey, signer)
	if err == nil && !time.Now().Before(evidence.Expires) {
		client.Close()
		err = errors.New("sandbox attestation expired during SSH login")
	}
	return client, err
}

// login logs in as the sandbox user over the route of its host key.
func (svc *Service) login(ctx context.Context, hostKey ssh.PublicKey, signer ssh.Signer) (*ssh.Client, error) {
	conn, err := svc.monitor.DialSSH(hostKey)
	if err != nil {
		return nil, fmt.Errorf("sandbox SSH: %w", err)
	}
	// SSH channels have no deadlines, so ending ctx closes a stalled handshake.
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	c, channels, requests, err := ssh.NewClientConn(conn, sandboxLoginUser, &ssh.ClientConfig{
		User: sandboxLoginUser, Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(hostKey),
	})
	if !stop() {
		err = errors.Join(err, context.Cause(ctx))
	}
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("sandbox SSH login: %w", err)
	}
	return ssh.NewClient(c, channels, requests), nil
}

// attest fetches fresh evidence through the unverified bootstrap route. Only a
// public nonce and the attestation cross it before verification pins the host key.
func (svc *Service) attest(ctx context.Context, a Boot) (*Evidence, error) {
	if svc.verify == nil {
		return nil, errors.New("sandbox attestation is unavailable")
	}
	nonce, err := document.RandomNonce()
	if err != nil {
		return nil, err
	}
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(context.Context, string, string) (net.Conn, error) {
		return svc.monitor.DialBootstrap(BootstrapUser + a.InstanceID)
	}}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, sandboxAttestationURL+"?nonce="+hex.EncodeToString(nonce), nil)
	if err != nil {
		return nil, err
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		return nil, fmt.Errorf("sandbox attestation: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sandbox attestation: %s", response.Status)
	}
	doc, err := io.ReadAll(io.LimitReader(response.Body, maxSandboxAttestationBytes+1))
	if err == nil && len(doc) > maxSandboxAttestationBytes {
		err = errors.New("attestation is too large")
	}
	if err != nil {
		return nil, fmt.Errorf("sandbox attestation: %w", err)
	}
	evidence, err := svc.verify(doc, nonce, a.Source)
	if err != nil {
		return nil, fmt.Errorf("verifying sandbox attestation: %w", err)
	}
	if !time.Now().Before(evidence.Expires) {
		return nil, errors.New("sandbox attestation has expired")
	}
	return evidence, nil
}

type EnrollInput struct {
	access
	DiskKey    []byte `json:"disk_key"`
	Initialize bool   `json:"initialize"`
}

const installSandboxMonitorCommand = `sudo -n sh -c '
set -eu
install -d -m 0750 -g sandbox /run/monitor
umask 077
cat > /run/monitor/identity
printf "monitor %s\n" "$1" > /run/monitor/known_hosts
printf "restrict,pty %s\n" "$1" > /run/monitor/authorized_keys
chmod 0600 /run/monitor/identity /run/monitor/known_hosts /run/monitor/authorized_keys
chown sandbox:sandbox /run/monitor/identity /run/monitor/known_hosts /run/monitor/authorized_keys
if [ -d /run/systemd/system ]; then
    systemctl restart monitor-network.service
fi
' sh`

// Enroll registers the sandbox's agent identity once the boot attests, installs it
// and unlocks the workspace over owner SSH, as the CLI does. Keys are cleared on return.
func (svc *Service) Enroll(ctx context.Context, name string, in EnrollInput) error {
	defer clear(in.OwnerSeed)
	defer clear(in.DiskKey)
	if err := in.validate(name); err != nil {
		return err
	}
	if len(in.DiskKey) != WorkspaceKeyBytes {
		return fmt.Errorf("disk_key must be %d bytes", WorkspaceKeyBytes)
	}
	agent, public, err := in.agentKey()
	if err != nil {
		return err
	}
	defer clear(agent)
	key := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(public)))
	if err := svc.monitor.CheckIdentity(name, key, in.Boot); err != nil {
		return err
	}
	owner := ed25519.NewKeyFromSeed(in.OwnerSeed)
	defer clear(owner)
	signer, err := ssh.NewSignerFromKey(owner)
	if err != nil {
		return err
	}
	client, err := svc.connect(ctx, in.Boot, signer)
	if err != nil {
		return err
	}
	defer client.Close()
	if err := svc.monitor.AddIdentity(ctx, name, key, in.Boot); err != nil {
		return err
	}
	block, err := ssh.MarshalPrivateKey(agent, "")
	if err != nil {
		return err
	}
	private := pem.EncodeToMemory(block)
	clear(block.Bytes)
	defer clear(private)
	ctx, cancel := context.WithTimeout(ctx, sandboxCommandTimeout)
	defer cancel()
	known := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(svc.monitor.HostKey().PublicKey())))
	if err := runCommand(ctx, client, installSandboxMonitorCommand+" '"+known+"'", private); err != nil {
		return fmt.Errorf("install Monitor credentials: %w", err)
	}
	command := "/usr/local/bin/workspace-unlock"
	if in.Initialize {
		command += " --initialize"
	}
	// A previous request may have opened the disk before its reply was lost.
	command = "if test -S /run/tinfoil/volumes/workspace/control.sock; then " + command + "; else findmnt -rn -M /mnt/disk -t ext4 -O rw >/dev/null; fi"
	if err := runCommand(ctx, client, command, in.DiskKey); err != nil {
		return fmt.Errorf("unlock workspace: %w", err)
	}
	return nil
}

// runCommand sends input on stdin and reports at most maxSandboxReplyBytes of stderr.
func runCommand(ctx context.Context, client *ssh.Client, command string, input []byte) error {
	// Closing the connection also ends a channel open the sandbox never answers.
	stop := context.AfterFunc(ctx, func() { client.Close() })
	defer stop()
	session, err := client.NewSession()
	if err != nil {
		return errors.Join(err, context.Cause(ctx))
	}
	defer session.Close()
	var reply limitedReply
	session.Stdin, session.Stderr = bytes.NewReader(input), &reply
	if err := session.Run(command); err != nil {
		return fmt.Errorf("%w: %s", errors.Join(err, context.Cause(ctx)), strings.TrimSpace(strings.ToValidUTF8(string(reply), "")))
	}
	return nil
}

type limitedReply []byte

func (b *limitedReply) Write(p []byte) (int, error) {
	*b = append(*b, p[:min(len(p), maxSandboxReplyBytes-len(*b))]...)
	return len(p), nil
}
