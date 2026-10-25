// Package monitor owns authorization transactions, connection runtime and the owner and agent APIs.
package monitor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/internal/audit"
	"github.com/tinfoilsh/monitor/internal/config"
	"github.com/tinfoilsh/monitor/internal/store"
	"github.com/tinfoilsh/monitor/internal/supervisor"
	"github.com/tinfoilsh/monitor/internal/tinfoil/sandbox"
	"github.com/tinfoilsh/monitor/internal/tinfoil/sandboxroute"
	"github.com/tinfoilsh/monitor/internal/worker"
	"gocloud.dev/blob"
	"golang.org/x/crypto/ssh"
)

// state is the atomically published configuration and policy snapshot.
// Connections own their runtime lifecycle; mutable device labels live in the committed document.
type state struct {
	*config.Snapshot
	connections map[string]*connection
	connector.Env
}

// A connection binds a compiled specification to credentials and runtime resources.
// Reconciliation starts its server only after the candidate has been persisted.
type connection struct {
	config.ConnectionSpec
	Secrets map[string]*credential.Value
	Server  connector.Server
	supervisor.Conn
}

type Options struct {
	Bucket         *blob.Bucket
	BucketURL      string
	OwnerPublicKey ed25519.PublicKey
	HostKey        ssh.Signer
	Connectors     map[string]connector.Definition
	Workers        worker.Launcher
	EmbeddedFiles  http.Handler // Serves /app/ assets, including over owner SSH.
}

type monitor struct {
	workers worker.Launcher
	kinds   map[string]connector.Definition
	live    atomic.Pointer[state]
	mu      sync.Mutex
	store   store.Store
	running map[string]*supervisor.Conn
	audit   audit.Log[*record]

	ownerPublicKey ed25519.PublicKey
	sshHostKey     ssh.Signer
	embeddedFiles  http.Handler
	ownerAPI       http.Handler
	// bucket is the storage URL that binds owner RPC envelopes to this Monitor.
	bucket    string
	sandboxes *sandbox.Service

	routes sandboxroute.Table

	// mu owns authorization transactions, including documents, records and streams.
	streams map[*connector.Stream]string
	records []*record
	// signIns holds the finish of each started sign-in, keyed by its state.
	signIns sync.Map
}

func New(o Options) *monitor {
	if o.EmbeddedFiles == nil {
		o.EmbeddedFiles = http.NotFoundHandler()
	}
	m := &monitor{store: store.Store{Bucket: o.Bucket}, audit: audit.Log[*record]{Bucket: o.Bucket}, ownerPublicKey: o.OwnerPublicKey, sshHostKey: o.HostKey, bucket: o.BucketURL, kinds: o.Connectors, workers: o.Workers, embeddedFiles: o.EmbeddedFiles}
	m.sandboxes = sandbox.New(sandboxMonitor{m}, &m.routes, sandbox.Verify)
	m.ownerAPI = m.ownerHandler(true, nil)
	return m
}

func (m *monitor) generation() (uint64, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.store.Doc.Generation, m.live.Load() != nil
}

// The first unlock of an empty store makes its secret the owner's.
func (m *monitor) unlock(ctx context.Context, key []byte, minimum uint64, initialize bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ownerPublicKey != nil && len(key) != store.OwnerKeyBytes {
		return store.ErrOwner
	}
	if m.live.Load() != nil {
		if !m.store.IsOwner(key) {
			return store.ErrOwner
		}
		if m.store.Doc.Generation < minimum {
			return fmt.Errorf("live generation %d is older than %d", m.store.Doc.Generation, minimum)
		}
		return nil
	}
	next, err := m.store.Load(ctx, key, minimum, initialize)
	if err != nil {
		return err
	}
	var env connector.Env
	if env.TLS, err = connectionTLS(&next.Doc.Keys); err != nil {
		return err
	}
	env.HostKey = m.sshHostKey
	if env.HostKey == nil {
		if env.HostKey, err = next.Doc.Keys.HostSigner(); err != nil {
			return err
		}
	}
	s, err := m.build(ctx, &next.Doc, env, nil)
	if err != nil {
		return err
	}
	previous := m.store
	m.store = next
	m.audit.SealWith(next.Sealer)
	if err := m.activate(ctx, next.Doc, s); err != nil {
		m.store = previous
		return err
	}
	return nil
}

// candidate validates source without publishing anything.
func (m *monitor) candidate(ctx context.Context, source string, secrets store.Secrets) (store.Document, *state, error) {
	next := m.store.Doc
	next.Policy = source
	next.Secrets = secrets
	if secrets == nil {
		next.Secrets = m.store.Doc.Secrets
	}
	st, err := m.build(ctx, &next, m.live.Load().Env, m.live.Load())
	return next, st, err
}

// build validates without starting anything or mutating live credentials.
func (m *monitor) build(ctx context.Context, document *store.Document, env connector.Env, old *state) (*state, error) {
	snapshot, specs, err := config.Compile(ctx, document.Policy)
	if err != nil {
		return nil, err
	}
	s := &state{Snapshot: snapshot, connections: map[string]*connection{}, Env: env}
	s.Dialer = connector.NewDialer(snapshot.Config.AllowNetworks)
	secrets := document.Secrets.Clone()
	for name, spec := range specs {
		definition, ok := m.kinds[spec.Protocol]
		if !ok {
			return nil, fmt.Errorf("connection %s has unknown kind %s", name, spec.Protocol)
		}
		server := definition.NewConfig()
		if err := connector.Decode(spec.Config, server); err != nil {
			return nil, fmt.Errorf("connection %s: %w", name, err)
		}
		c := &connection{ConnectionSpec: spec, Server: server}
		if owner, ok := server.(connector.SecretHolder); ok {
			c.Secrets = owner.SecretValues()
			for _, value := range c.Secrets {
				if value != nil && value.Raw() != nil {
					return nil, errors.New("set credentials through account settings")
				}
			}
			preset := snapshot.Config.Resolved[snapshot.Config.Accounts[c.Account].Preset]
			fields, err := preset.Catalog.CredentialFields()
			if err != nil {
				return nil, err
			}
			for _, paths := range fields {
				for _, path := range paths {
					if path.Connection == c.Key && path.Protocol == c.Protocol && c.Secrets[path.Secret] == nil {
						c.Secrets[path.Secret] = new(credential.Value)
					}
				}
			}
			for name, value := range c.Secrets {
				if value == nil {
					c.Secrets[name] = new(credential.Value)
				}
			}
		}
		s.connections[name] = c
	}
	for id, raw := range secrets {
		c := s.connections[config.ConnectionName(id.Account, id.Connection)]
		if c == nil || c.Account != id.Account || c.Key != id.Connection || c.Secrets == nil {
			delete(secrets, id)
			continue
		}
		value := new(credential.Value)
		if err := value.UnmarshalJSON(raw); err != nil {
			return nil, fmt.Errorf("credential %v: %w", id, err)
		}
		c.Secrets[id.Name] = value
	}
	client := s.Client()
	for name, c := range s.connections {
		if old != nil && slices.Equal(old.Config.AllowNetworks, snapshot.Config.AllowNetworks) {
			previous := old.connections[name]
			if previous != nil && previous.Account == c.Account && previous.Protocol == c.Protocol && bytes.Equal(previous.Config, c.Config) &&
				maps.EqualFunc(m.store.Doc.Secrets.Connection(c.Account, c.Key), secrets.Connection(c.Account, c.Key), slices.Equal[json.RawMessage]) {
				s.connections[name] = previous
				continue
			}
		}
		for name, value := range c.Secrets {
			id := store.SecretID{Account: c.Account, Connection: c.Key, Name: name}
			value.Placeholder = placeholder(document.Keys, id)
			value.Client = client
			value.Save = func(ctx context.Context, before, after json.RawMessage) error {
				return m.replaceValue(ctx, c, id, before, after)
			}
		}
	}
	document.Secrets = secrets
	return s, nil
}

// activate persists a candidate prepared under the same lock, then publishes it.
func (m *monitor) activate(ctx context.Context, next store.Document, s *state) error {
	old := m.live.Load()
	next.Enrolled = maps.Clone(next.Enrolled)
	if next.Enrolled == nil {
		next.Enrolled = map[string]bool{}
	}
	for key := range s.Principals {
		next.Enrolled[key] = true
	}
	next.Labels = maps.Clone(next.Labels)
	maps.DeleteFunc(next.Labels, func(key string, _ facts.Label) bool { _, ok := s.Principals[key]; return !ok })
	if err := m.store.Commit(ctx, next); err != nil {
		return err
	}
	if !s.Config.AllowSandboxSSH {
		m.sandboxes.CloseShells()
	}
	if old == nil {
		m.streams, m.running = map[*connector.Stream]string{}, map[string]*supervisor.Conn{}
	}
	for stream, key := range m.streams {
		if !s.sameStreamAuthority(old, key, stream) {
			stream.Close()
		}
	}
	m.reconcile(s)
	m.live.Store(s)
	// Pending decisions belong to the configuration that requested them.
	m.refusePending(errChanged)
	return nil
}

func (m *monitor) reconcile(s *state) {
	next := make(map[string]*supervisor.Conn, len(s.connections))
	for name, c := range s.connections {
		next[name] = &c.Conn
	}
	supervisor.Reconcile(m.running, next, func(name string) (connector.Server, connector.Env) {
		c := s.connections[name]
		def, env := m.kinds[c.Protocol], s.Env
		if !def.HostKey {
			env.HostKey = nil
		}
		if m.workers != nil {
			return &worker.Proxy{Definition: def, Kind: c.Protocol, Config: c.Config, Secrets: c.Secrets, Launcher: m.workers}, env
		}
		return c.Server, env
	})
}

// connectionTLS supplies the admitted target when an in-process client omits SNI.
// Worker certificate requests resolve and validate their target in the broker.
func connectionTLS(keys *store.Keys) (*tls.Config, error) {
	config, err := keys.TLS()
	if err != nil {
		return nil, err
	}
	issue := config.GetCertificate
	config.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if stream, ok := hello.Conn.(*connector.Stream); ok && hello.ServerName == "" {
			copy := *hello
			copy.ServerName = stream.Host
			hello = &copy
		}
		return issue(hello)
	}
	return config, nil
}

var errLocked = errors.New("the monitor is locked")
