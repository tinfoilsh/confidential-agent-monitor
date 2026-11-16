// A standalone composition: static SSH identities, native Cedar decisions and TCP.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strconv"
	"time"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/tcp"
	"github.com/tinfoilsh/confidential-agent-monitor/core"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/netx"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/sshtransport"
	"golang.org/x/crypto/ssh"
)

func main() {
	keyPath := flag.String("host-key", "host.key", "SSH host private key file")
	identityPath := flag.String("identity-key", "alice.pub", "public key for the static alice identity")
	address := flag.String("listen", "127.0.0.1:2224", "SSH listener")
	upstream := flag.String("upstream", "database.internal:5432", "TCP endpoint named database")
	flag.Parse()
	if err := runCommand(*keyPath, *identityPath, *address, *upstream); err != nil {
		log.Fatal(err)
	}
}

func runCommand(keyPath, identityPath, address, upstream string) error {
	private, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	host, err := ssh.ParsePrivateKey(private)
	clear(private)
	if err != nil {
		return err
	}
	public, err := os.ReadFile(identityPath)
	if err != nil {
		return err
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey(public)
	if err != nil {
		return err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return serveStatic(ctx, listener, host, key, upstream)
}

func serveStatic(ctx context.Context, listener net.Listener, host ssh.Signer, key ssh.PublicKey, upstream string) error {
	hostname, portText, err := net.SplitHostPort(upstream)
	if err != nil {
		return err
	}
	port, err := strconv.ParseUint(portText, 10, 16)
	if err != nil || port == 0 {
		return errors.New("upstream needs a TCP port between 1 and 65535")
	}
	raw, err := json.Marshal(struct {
		Hosts []string `json:"hosts"`
		Ports []uint32 `json:"ports"`
	}{[]string{hostname}, []uint32{uint32(port)}})
	if err != nil {
		return err
	}
	connection, err := tcp.Parse(raw)
	if err != nil {
		return err
	}
	policies, err := cedar.NewPolicySetFromBytes("inline.cedar", []byte(`
permit(principal == User::"alice", action == Action::"connect", resource == Service::"database");
`))
	if err != nil {
		return err
	}
	identities := map[string]facts.Principal{ssh.FingerprintSHA256(key): {Key: ssh.FingerprintSHA256(key), Name: "alice"}}
	lookup := func(key string) (facts.Principal, bool) { p, ok := identities[key]; return p, ok }
	hold := func(parent context.Context, key string) (context.Context, context.CancelFunc, bool) {
		if _, ok := lookup(key); !ok {
			return nil, nil, false
		}
		held, cancel := context.WithCancel(parent)
		stop := context.AfterFunc(ctx, cancel)
		return held, func() { stop(); cancel() }, true
	}
	check := func(ctx context.Context, p facts.Principal, name string) error {
		current, ok := lookup(p.Key)
		if !ok || !current.Same(p) {
			return errors.New("unknown identity")
		}
		return evaluateCedar(ctx, policies, p, name)
	}
	table := core.New(
		func(ctx context.Context, p facts.Principal, name string) bool { return check(ctx, p, name) == nil },
		func(ctx context.Context, p facts.Principal, request core.Request) (core.Watch, error) {
			if !request.Valid() {
				return nil, errors.New("connection changed")
			}
			if err := check(ctx, p, request.Connection); err != nil {
				return nil, err
			}
			return func(stream context.Context, _ func()) (core.Gate, bool) {
				if !request.Valid() || check(stream, p, request.Connection) != nil {
					return nil, false
				}
				return func(op context.Context, event facts.Event) error {
					if _, err := event.Decode(); err != nil {
						return err
					}
					if !request.Valid() {
						return errors.New("connection changed")
					}
					return check(op, p, request.Connection)
				}, true
			}, nil
		},
		func(host string, port uint32, candidates []core.Candidate) (string, bool, bool) {
			for _, candidate := range candidates {
				if candidate.Claim != nil && candidate.Claim(host, port) >= 0 {
					return candidate.Name, false, true
				}
			}
			return "", false, false
		}, time.Minute)
	defer table.Close()
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	table.Stage("database", connection.Claim, false, func(context.Context) (core.Connector, error) {
		return core.Connector{Serve: connection.Handler(dialer.DialContext, func(ctx context.Context, a, b net.Conn) { netx.Relay(ctx, a, b, 10*time.Second) })}, nil
	})
	table.Start()
	if state := table.Connections()["database"]; state.State != core.Ready {
		return fmt.Errorf("database setup: %s", state.Error)
	}
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	var serveErr error
	sshtransport.Serve(listener, func() ssh.Signer { return host }, sshtransport.Limits{MaxAuthTries: 3, MaxHandshakes: 64, HandshakeTimeout: 10 * time.Second},
		func(_ ssh.ConnMetadata, public ssh.PublicKey) (sshtransport.Session, func() error, error) {
			p, ok := lookup(ssh.FingerprintSHA256(public))
			if !ok {
				return nil, nil, errors.New("unknown identity")
			}
			return func(conn *ssh.ServerConn, channels <-chan ssh.NewChannel, requests <-chan *ssh.Request) {
				stop := context.AfterFunc(ctx, func() { conn.Close() })
				defer stop()
				sshtransport.ServeDirect(channels, requests, func(stream context.Context, host string, port uint32, accept func() (net.Conn, error)) error {
					held, cancel, ok := hold(stream, p.Key)
					if !ok {
						return errors.New("unknown identity")
					}
					defer cancel()
					return table.Open(held, p, host, port, accept)
				})
			}, nil, nil
		}, func(err error) { serveErr = err })
	return serveErr
}

// evaluateCedar intentionally refuses diagnostics even if another policy allowed
// the request. Each command owns its request mapping and decision interpretation.
func evaluateCedar(ctx context.Context, policies *cedar.PolicySet, principal facts.Principal, connection string) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	decision, diagnostics := cedar.Authorize(policies, nil, cedar.Request{
		Principal: cedar.NewEntityUID("User", cedar.String(principal.Name)),
		Action:    cedar.NewEntityUID("Action", "connect"),
		Resource:  cedar.NewEntityUID("Service", cedar.String(connection)),
		Context:   cedar.NewRecord(cedar.RecordMap{}),
	})
	if decision != cedar.Allow || len(diagnostics.Errors) != 0 {
		return errors.New("connection refused")
	}
	return nil
}
