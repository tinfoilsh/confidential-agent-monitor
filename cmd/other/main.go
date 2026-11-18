package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	cedar "github.com/cedar-policy/cedar-go"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/postgres"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/tcp"
	"github.com/tinfoilsh/confidential-agent-monitor/core"
	"github.com/tinfoilsh/confidential-agent-monitor/core/admission"
	"github.com/tinfoilsh/confidential-agent-monitor/core/certificates"
	"github.com/tinfoilsh/confidential-agent-monitor/core/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/sshtransport"
	"golang.org/x/crypto/ssh"
)

const (
	connectAction  = "connect"
	dialTimeout    = 10 * time.Second
	relayDrain     = 10 * time.Second
	connectTimeout = 30 * time.Second
	openTimeout    = time.Minute
)

var (
	errRefused     = errors.New("policy does not permit this request")
	errCertificate = errors.New("sign in with an expiring user certificate from the identity CA that carries a key ID")
	decisions      = slog.New(slog.NewJSONHandler(os.Stdout, nil))
	sshLimits      = sshtransport.Limits{MaxAuthTries: 3, MaxHandshakes: 64, HandshakeTimeout: 10 * time.Second}
)

type service struct {
	TCP        json.RawMessage `json:"tcp"`
	Postgres   json.RawMessage `json:"postgres"`
	Attributes cedar.Record    `json:"attributes"`
}

type admitted struct {
	principal facts.Principal
	request   core.Request
}

type perimeter struct {
	policies atomic.Pointer[cedar.PolicySet]
	services cedar.EntityMap
	mu       sync.Mutex
	live     admission.Set[admitted]
}

func main() {
	keyPath := flag.String("host-key", "host.key", "SSH host private key file")
	caPath := flag.String("identity-ca", "ca.pub", "SSH CA public key file; its expiring user certificates sign in the person their key ID names, with their principals as groups")
	address := flag.String("listen", "127.0.0.1:2224", "SSH listener")
	servicesPath := flag.String("services", "services.json", "JSON file of the services people reach at their own addresses, each with tcp or postgres settings and the attributes policy sees")
	policyPath := flag.String("policy", "policy.cedar", "Cedar policy file, read again on SIGHUP")
	secrets := flag.String("secrets", "secrets", "directory holding each Postgres service's password in a file named after the service")
	flag.Parse()
	if err := runCommand(*keyPath, *caPath, *address, *servicesPath, *policyPath, *secrets); err != nil {
		log.Fatal(err)
	}
}

func runCommand(keyPath, caPath, address, servicesPath, policyPath, secrets string) error {
	private, err := os.ReadFile(keyPath)
	if err != nil {
		return err
	}
	host, err := ssh.ParsePrivateKey(private)
	clear(private)
	if err != nil {
		return err
	}
	public, err := os.ReadFile(caPath)
	if err != nil {
		return err
	}
	ca, _, _, _, err := ssh.ParseAuthorizedKey(public)
	if err != nil {
		return err
	}
	raw, err := os.ReadFile(servicesPath)
	if err != nil {
		return err
	}
	var services map[string]service
	if err := facts.DecodeNumbers(raw, &services); err != nil {
		return err
	}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	defer listener.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serve(ctx, listener, host, ca, services, policyPath, secrets)
}

func serve(ctx context.Context, listener net.Listener, host ssh.Signer, ca ssh.PublicKey, services map[string]service, policyPath, secrets string) error {
	pm := &perimeter{services: cedar.EntityMap{}}
	pm.live.L = &pm.mu
	table := core.New(func(context.Context, facts.Principal, string) bool { return true }, pm.admit, core.BestClaim, openTimeout)
	defer table.Close()
	dialer := &net.Dialer{Timeout: dialTimeout}
	// The SSH tunnel already protects the stream, so databases are served inside it without TLS.
	plaintext := func(context.Context, string) *tls.Config { return nil }
	for name, s := range services {
		uid := cedar.NewEntityUID("Service", cedar.String(name))
		pm.services[uid] = cedar.Entity{UID: uid, Attributes: s.Attributes}
		var claim func(connector.Target) int
		var handler connector.Serve
		switch {
		case s.Postgres != nil:
			db, err := postgres.Parse(s.Postgres)
			if err != nil {
				return fmt.Errorf("service %s: %w", name, err)
			}
			claim = func(target connector.Target) int {
				if strings.EqualFold(target.Host, db.Hosts()[0]) {
					return len(target.Host)
				}
				return -1
			}
			handler = db.Handler(dialer.DialContext, func(context.Context) (string, error) {
				password, err := os.ReadFile(filepath.Join(secrets, name))
				return strings.TrimRight(string(password), "\r\n"), err
			}, plaintext, connectTimeout)
		case s.TCP != nil:
			connection, err := tcp.Parse(s.TCP)
			if err != nil {
				return fmt.Errorf("service %s: %w", name, err)
			}
			claim = connection.Claim
			handler = connection.Handler(dialer.DialContext, relayDrain)
		default:
			return fmt.Errorf("service %s needs tcp or postgres settings", name)
		}
		table.Stage(name, "tcp", claim, func(context.Context) (connector.Instance, error) {
			return connector.Instance{Serve: handler}, nil
		})
	}
	table.Start()
	if err := pm.load(policyPath); err != nil {
		return err
	}
	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	go func() {
		for range reload {
			if err := pm.load(policyPath); err != nil {
				log.Printf("policy not reloaded: %v", err)
			}
		}
	}()
	stop := context.AfterFunc(ctx, func() { listener.Close() })
	defer stop()
	var serveErr error
	sshtransport.Serve(listener, func() ssh.Signer { return host }, sshLimits,
		func(_ ssh.ConnMetadata, public ssh.PublicKey) (sshtransport.Session, func() error, error) {
			cert, ok := public.(*ssh.Certificate)
			if !ok {
				return nil, nil, errCertificate
			}
			p, err := certificates.SSHUser(ca, cert)
			if err != nil {
				return nil, nil, err
			}
			return func(conn *ssh.ServerConn, channels <-chan ssh.NewChannel, requests <-chan *ssh.Request) {
				stop := context.AfterFunc(ctx, func() { conn.Close() })
				defer stop()
				defer time.AfterFunc(time.Until(time.Unix(int64(cert.ValidBefore), 0)), func() { conn.Close() }).Stop()
				sshtransport.ServeDirect(channels, requests, table.Open(p))
			}, nil, nil
		}, func(err error) { serveErr = err })
	return serveErr
}

func (pm *perimeter) load(path string) error {
	source, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	policies, err := cedar.NewPolicySetFromBytes(path, source)
	if err != nil {
		return err
	}
	pm.mu.Lock()
	defer pm.mu.Unlock()
	pm.policies.Store(policies)
	pm.live.Recheck(func(a admitted) bool { return pm.connect(a) == nil })
	return nil
}

func (pm *perimeter) connect(a admitted) error {
	return pm.authorize(a.principal, connectAction, a.request.Connection, map[string]any{"host": a.request.Target.Host, "port": a.request.Target.Port})
}

func (pm *perimeter) admit(_ context.Context, p facts.Principal, request core.Request) (core.Watch, error) {
	a := admitted{p, request}
	seen := pm.policies.Load()
	if err := pm.connect(a); err != nil {
		return nil, err
	}
	return func(stream context.Context, end func()) (connector.Gate, bool) {
		pm.mu.Lock()
		pm.live.Hold(stream, a, end)
		pm.mu.Unlock()
		// A reload before the stream joined the live set did not recheck it.
		if pm.policies.Load() != seen && pm.connect(a) != nil {
			return nil, false
		}
		return func(_ context.Context, event facts.Event) error {
			o, err := event.Decode()
			if err != nil {
				return err
			}
			if o.Operation == nil {
				return errRefused
			}
			return pm.authorize(p, o.Operation.Action, request.Connection, o.Parameters)
		}, true
	}, nil
}

func (pm *perimeter) authorize(p facts.Principal, action, service string, parameters map[string]any) error {
	record, err := facts.JSON[cedar.Record](parameters)
	if err != nil {
		return err
	}
	user := cedar.NewEntityUID("User", cedar.String(p.Name))
	groups := make([]cedar.EntityUID, len(p.Groups))
	for i, group := range p.Groups {
		groups[i] = cedar.NewEntityUID("Group", cedar.String(group))
	}
	entities := pm.services.Clone()
	entities[user] = cedar.Entity{UID: user, Parents: cedar.NewEntityUIDSet(groups...)}
	decision, diagnostic := cedar.Authorize(pm.policies.Load(), entities, cedar.Request{Principal: user, Action: cedar.NewEntityUID("Action", cedar.String(action)),
		Resource: cedar.NewEntityUID("Service", cedar.String(service)), Context: record})
	// Cedar skips a policy that fails to evaluate, which could silence a forbid, so any error refuses.
	allowed := decision == cedar.Allow && len(diagnostic.Errors) == 0
	decisions.Info("decision", "user", p.Name, "groups", p.Groups, "action", action, "service", service, "context", parameters, "allowed", allowed, "policies", diagnostic)
	if !allowed {
		return errRefused
	}
	return nil
}
