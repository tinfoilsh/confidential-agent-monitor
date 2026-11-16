// Package sandbox serves Tinfoil sandboxes: route publishers, reserved route hosts and the bootstrap relay.
package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/sshtransport"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
)

const (
	maxUntrustedPublishers = 128
	maxForwardAddresses    = 128
	forwardOpenTimeout     = 10 * time.Second
	// An identity publishes an OpenSSH SOCKS RemoteForward on this loopback port.
	socksPort = "1080"
	aliasPort = 443
	// Listeners on 127.0.0.1 do not accept this loopback alias; wildcard listeners do.
	wildcardHost = "127.0.0.2"
	forwardHost  = "127.0.0.1"
	// A negative claim refuses a target.
	unclaimed = -1

	routeSuffix = ".sandbox.invalid"
	// An identity reaches another enrolled identity, NAME, as NAME.sandbox.
	identitySuffix = ".sandbox"
	// bootstrapUser prefixes the SSH user a publisher announces its bootstrap route as.
	bootstrapUser = "sandbox-v2:"
	// fingerprintPrefix starts the SHA-256 key fingerprints that are the identity registry's key IDs.
	fingerprintPrefix = "SHA256:"
	Attribute         = "sandbox"
)

var (
	errRouteUnavailable  = errors.New("not connected to the Perimeter")
	ErrDirectUnavailable = fmt.Errorf("route %w", sshtransport.ErrUnavailable)
)

// routeName names a key's route by its fingerprint; a malformed fingerprint names no publisher.
func routeName(fingerprint string) string {
	digest, _ := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(fingerprint, fingerprintPrefix))
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest)) + routeSuffix
}

// bootstrapRoute names an unverified publisher by the instance it claims. Only its port
// 443 is reachable this way; callers verify what it serves, and the route grants no agent access.
func bootstrapRoute(instance string) string {
	digest := sha256.Sum256([]byte(bootstrapUser + instance))
	return "bootstrap-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])) + routeSuffix
}

func ReservedRoute(host string) bool {
	host = "." + strings.TrimSuffix(strings.ToLower(host), ".")
	return strings.HasSuffix(host, identitySuffix) || strings.HasSuffix(host, routeSuffix)
}

// routeAllowed reports whether a route pattern among hosts matches host, so * never reaches a route.
func routeAllowed(hosts []string, host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return slices.ContainsFunc(hosts, func(pattern string) bool {
		ok, _ := path.Match(strings.ToLower(pattern), host)
		return ok && ReservedRoute(pattern)
	})
}

// publisher names an authenticated peer and an optional discovery alias.
// Trusted publishers are exempt from the limit on untrusted connections.
type publisher struct {
	Name, Alias string
	Trusted     bool
}

type forwardPeer struct {
	publisher
	conn     *ssh.ServerConn
	forwards *sshtransport.Forwards
}

// Forwarder serves virtual TCP forwards without binding sockets on the server.
// Each authenticated name owns one connection; aliases must resolve uniquely.
type Forwarder struct {
	mu    sync.Mutex
	peers map[string]*forwardPeer
}

// servePublisher replaces a peer's previous connection immediately and owns its
// registrations until disconnect. Callers supply names from authentication.
// Only explicit ports (1-65535) are accepted; no local sockets are bound.
func (f *Forwarder) servePublisher(conn *ssh.ServerConn, channels <-chan ssh.NewChannel, requests <-chan *ssh.Request, identity publisher) {
	defer conn.Close()
	if identity.Name == "" {
		return
	}
	f.mu.Lock()
	unknown := 0
	for name, peer := range f.peers {
		if name != identity.Name && !peer.Trusted {
			unknown++
		}
	}
	if !identity.Trusted && unknown >= maxUntrustedPublishers {
		f.mu.Unlock()
		return
	}
	previous := f.peers[identity.Name]
	peer := &forwardPeer{publisher: identity, conn: conn, forwards: sshtransport.NewForwards(conn, maxForwardAddresses, forwardOpenTimeout)}
	if f.peers == nil {
		f.peers = map[string]*forwardPeer{}
	}
	f.peers[identity.Name] = peer
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.peers[identity.Name] == peer {
			delete(f.peers, identity.Name)
		}
	}()
	if previous != nil {
		previous.conn.Close()
	}
	go func() {
		for channel := range channels {
			channel.Reject(ssh.Prohibited, "publisher connections cannot open client channels")
		}
	}()
	peer.forwards.Serve(requests)
}

// DialContext opens a publisher's virtual loopback forward at address, a peer name or
// unambiguous alias with a port. Addresses are scoped to the publisher, so peers can publish the
// same ports. Aliases expose only port 443; key-derived names may use any port.
func (f *Forwarder) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	host, service, err := net.SplitHostPort(address)
	port, invalid := strconv.ParseUint(service, 10, 16)
	if err != nil || invalid != nil || port == 0 {
		return nil, errRouteUnavailable
	}
	name := strings.TrimSuffix(strings.ToLower(host), ".")
	f.mu.Lock()
	peer := f.peers[name]
	if peer == nil && name != "" && port == aliasPort {
		for _, candidate := range f.peers {
			if candidate.Alias == name && candidate.forwards.Has(forwardHost, uint32(port)) {
				if peer != nil {
					f.mu.Unlock()
					return nil, errRouteUnavailable
				}
				peer = candidate
			}
		}
	}
	f.mu.Unlock()
	if peer == nil {
		return nil, errRouteUnavailable
	}
	conn, err := peer.forwards.Dial(forwardHost, uint32(port))
	if err != nil {
		return nil, errRouteUnavailable
	}
	return conn, nil
}

type dialFunc = func(ctx context.Context, network, address string) (net.Conn, error)

// RouteDial dials reserved route hosts that hosts name through f, and every other address
// through next. keysOf lists the key fingerprints an identity's name holds.
func (f *Forwarder) RouteDial(hosts []string, keysOf func(name string) []string, next dialFunc) dialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || !ReservedRoute(host) {
			return next(ctx, network, address)
		}
		name, named := strings.CutSuffix(strings.TrimSuffix(strings.ToLower(host), "."), identitySuffix)
		keys := keysOf(name)
		if !routeAllowed(hosts, host) || !named || len(keys) != 1 {
			return nil, errRouteUnavailable
		}
		// The SOCKS server is the publisher's own ssh client, reached over an SSH channel, not a socket.
		server := net.JoinHostPort(routeName(keys[0]), socksPort)
		socks, err := proxy.SOCKS5(network, server, nil, nil)
		if err != nil {
			return nil, err
		}
		conn, err := f.DialContext(ctx, network, server)
		if err != nil {
			return nil, err
		}
		// The handshake runs on the channel itself, so callers keep its half-close and closure.
		if _, err := socks.(interface {
			DialWithConn(context.Context, net.Conn, string, string) (net.Addr, error)
		}).DialWithConn(ctx, conn, network, net.JoinHostPort(wildcardHost, port)); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}
}

// RouteClaim keeps a connection from being chosen for a reserved route host its hosts do not name.
func RouteClaim(hosts []string, claim func(string, uint32) int) func(string, uint32) int {
	if claim == nil {
		return nil
	}
	return func(host string, port uint32) int {
		if ReservedRoute(host) && !routeAllowed(hosts, host) {
			return unclaimed
		}
		return claim(host, port)
	}
}

// Publisher returns the reverse-tunnel publisher session that user announces with key, or nil
// for any other user. Key probes never enroll or restore an identity. trusted reports whether
// a fingerprint is an identity's, or refuses the publisher.
func (f *Forwarder) Publisher(user string, key ssh.PublicKey, trusted func(fingerprint string) (bool, error)) (sshtransport.Session, error) {
	instance, announced := strings.CutPrefix(user, bootstrapUser)
	if !announced {
		return nil, nil
	}
	if instance == "" {
		return nil, errors.New("a publisher instance is required")
	}
	fingerprint := ssh.FingerprintSHA256(key)
	p := publisher{Name: routeName(fingerprint), Alias: bootstrapRoute(instance)}
	var err error
	if p.Trusted, err = trusted(fingerprint); err != nil {
		return nil, err
	}
	return func(conn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
		f.servePublisher(conn, chans, reqs, p)
	}, nil
}

// Boot is the sandbox boot an identity belongs to. Its persisted JSON matches the
// existing identity.sandbox source and owner API representation.
type Boot struct {
	Source     string `json:"source"`
	InstanceID string `json:"instance_id"`
}

// ValidateBoot checks the integration-owned portion of an identity before
// the host commits it. An absent boot is valid for ordinary agent identities.
func ValidateBoot(raw json.RawMessage) error {
	var b Boot
	if len(raw) == 0 {
		return nil
	}
	if err := facts.DecodeNumbers(raw, &b); err != nil || b == (Boot{}) {
		return err
	}
	if _, _, digest, err := verify.ParseReference(b.Source); err != nil || digest == "" {
		return errors.New("source must be a digest-pinned release reference")
	}
	if b.InstanceID == "" {
		return errors.New("instance_id is required")
	}
	return nil
}

const (
	RelayRoute    = "POST /sandboxes/relay"
	MaxRelayBytes = 1 << 20

	maxRelayAttestationBytes = 32 << 20
	relayHopTimeout          = 30 * time.Second
	relayIdleTimeout         = time.Minute
	relayIdleConns           = 4
	// AttestationPath serves attestation evidence for a ?nonce=, on enclaves and bunkers alike.
	AttestationPath       = "/.well-known/tinfoil-attestation"
	sandboxAttestationURL = "http://sandbox" + AttestationPath + "?nonce="
	sandboxOwnerPath      = "/owner/ws"
	bootstrapPort         = "443"
)

var (
	instancePattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hex32Pattern    = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	errRelayInput   = errors.New("a relay needs a bunker instance_id and an attestation nonce")
)

type badGateway struct{ error }

func (badGateway) HTTPStatus() int { return http.StatusBadGateway }

// Transport keeps each bunker's bootstrap connections open between relayed requests, so a
// request does not wait for a new forwarded channel.
func (f *Forwarder) Transport() *http.Transport {
	return &http.Transport{DisableCompression: true, MaxIdleConnsPerHost: relayIdleConns, IdleConnTimeout: relayIdleTimeout, DialContext: f.DialContext}
}

// RelayInput selects a bunker boot by its measured instance.
type RelayInput struct {
	InstanceID string `json:"instance_id"`
	Nonce      string `json:"nonce"`
}

type relayReply struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
}

// Relay fetches one attestation over a bunker's bootstrap route and returns the response
// bytes unchanged. That route is unverified and grants no agent access.
func Relay(ctx context.Context, relays http.RoundTripper, in RelayInput) (relayReply, error) {
	if !instancePattern.MatchString(in.InstanceID) || !hex32Pattern.MatchString(in.Nonce) {
		return relayReply{}, errRelayInput
	}
	request, err := http.NewRequest(http.MethodGet, sandboxAttestationURL+in.Nonce, nil)
	if err != nil {
		return relayReply{}, err
	}
	// An empty User-Agent is omitted, so the bunker receives no client headers.
	request.Header = http.Header{"User-Agent": {""}}
	// Connections are pooled per route; the bunker still sees its own Host.
	request.URL.Host = net.JoinHostPort(bootstrapRoute(in.InstanceID), bootstrapPort)
	ctx, cancel := context.WithTimeout(ctx, relayHopTimeout)
	defer cancel()
	response, err := relays.RoundTrip(request.WithContext(ctx))
	if err != nil {
		return relayReply{}, badGateway{errors.New("bunker relay: " + err.Error())}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxRelayAttestationBytes+1))
	if err == nil && len(body) > maxRelayAttestationBytes {
		err = errors.New("the response is too large")
	}
	if err != nil {
		return relayReply{}, badGateway{errors.New("bunker relay: " + err.Error())}
	}
	return relayReply{Status: response.StatusCode, Body: base64.RawURLEncoding.EncodeToString(body)}, nil
}

// DialOwner opens a bunker boot's owner socket over its bootstrap route.
func DialOwner(ctx context.Context, relays http.RoundTripper, instance string) (*websocket.Conn, error) {
	if !instancePattern.MatchString(instance) {
		return nil, errRelayInput
	}
	client := &http.Client{Transport: relays, Timeout: relayHopTimeout}
	conn, _, err := websocket.Dial(ctx, "ws://"+net.JoinHostPort(bootstrapRoute(instance), bootstrapPort)+sandboxOwnerPath, &websocket.DialOptions{HTTPClient: client})
	return conn, err
}
