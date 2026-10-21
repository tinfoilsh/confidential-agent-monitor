package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/rpc"
	"github.com/tinfoilsh/monitor/facts"
	"golang.org/x/crypto/ssh"
)

// state is the atomically published configuration and policy snapshot.
// Connections own their runtime lifecycle; mutable device labels live in the committed document.
type state struct {
	cfg         *config
	connections map[string]*connection
	principals  map[string]principal
	query       rego.PreparedEvalQuery
	program     string
	catalog     map[string]catalogEntry
	catalogID   string
	connector.Env
}

type monitor struct {
	workers rpc.Launcher
	live    atomic.Pointer[state]
	mu      sync.Mutex
	store   stateStore
	running map[string]*connection

	ownerPublicKey ed25519.PublicKey
	sshHostKey     ssh.Signer

	// routesMu keeps SSH admission and routing independent of mu's policy commits.
	// sessions records whether each connection's key had an identity when admitted.
	routesMu sync.Mutex
	routes   map[string]*routeSession
	sessions map[*ssh.ServerConn]bool

	// mu owns authorization transactions, including documents, records and streams.
	streams map[*connector.Stream]string
	records []*record
	audit   []byte // Settled records awaiting upload, as JSON lines.
	// auditMu serializes uploads, which run without mu; it is taken before mu.
	auditMu sync.Mutex
	// signIns holds the finish of each started sign-in, keyed by its state.
	signIns sync.Map
}

// The first unlock of an empty store makes its secret the owner's.
func (m *monitor) unlock(ctx context.Context, key []byte, minimum uint64, initialize bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ownerPublicKey != nil && len(key) != ownerKeyBytes {
		return errOwner
	}
	if m.live.Load() != nil {
		if subtle.ConstantTimeCompare(key, m.store.owner) != 1 {
			return errOwner
		}
		if m.store.doc.Generation < minimum {
			return fmt.Errorf("live generation %d is older than %d", m.store.doc.Generation, minimum)
		}
		return nil
	}
	next, err := m.store.load(ctx, key, minimum, initialize)
	if err != nil {
		return err
	}
	var env connector.Env
	if env.TLS, err = loadCA(&next.doc.Keys); err != nil {
		return err
	}
	env.HostKey = m.sshHostKey
	if env.HostKey == nil {
		if env.HostKey, err = loadHostKey(&next.doc.Keys); err != nil {
			return err
		}
	}
	s, err := m.build(ctx, next.doc, env, nil)
	if err != nil {
		return err
	}
	previous := m.store
	m.store = next
	if err := m.activate(ctx, next.doc, s); err != nil {
		m.store = previous
		return err
	}
	return nil
}

// activate persists a candidate prepared under the same lock, then publishes it.
func (m *monitor) activate(ctx context.Context, next sealed, s *state) error {
	old := m.live.Load()
	next.Enrolled = maps.Clone(next.Enrolled)
	if next.Enrolled == nil {
		next.Enrolled = map[string]bool{}
	}
	for key := range s.principals {
		next.Enrolled[key] = true
	}
	next.Labels = maps.Clone(next.Labels)
	maps.DeleteFunc(next.Labels, func(key string, _ facts.Label) bool { _, ok := s.principals[key]; return !ok })
	if err := m.store.commit(ctx, next); err != nil {
		return err
	}
	if old == nil {
		m.streams, m.running = map[*connector.Stream]string{}, map[string]*connection{}
	}
	for stream, key := range m.streams {
		if !s.sameStreamAuthority(old, key, stream) {
			stream.Close()
		}
	}
	m.reconcile(s)
	m.live.Store(s)
	// Pending decisions belong to the configuration that requested them.
	for _, r := range m.records {
		if r.State == statePending {
			r.State, r.Deny = stateRefused, []string{errChanged.Error()}
			close(r.answered)
		}
	}
	return nil
}

// build validates without starting anything or mutating live credentials.
func (m *monitor) build(ctx context.Context, sl sealed, env connector.Env, old *state) (*state, error) {
	cfg, definitions, err := compileSource(sl.Policy, sl.Secrets)
	if err != nil {
		return nil, err
	}
	s := &state{cfg: cfg, connections: definitions, principals: map[string]principal{}, Env: env}
	s.Dialer = connector.NewDialer(cfg.AllowNetworks)
	client := s.Client()
	for name, definition := range definitions {
		if old != nil && slices.Equal(old.cfg.AllowNetworks, cfg.AllowNetworks) {
			previous := old.connections[name]
			if previous != nil && previous.account == definition.account && previous.protocol == definition.protocol && bytes.Equal(previous.config, definition.config) &&
				maps.EqualFunc(m.store.doc.Secrets[definition.account][definition.key], sl.Secrets[definition.account][definition.key], slices.Equal[json.RawMessage]) {
				s.connections[name] = previous
				continue
			}
		}
		for name, value := range definition.Secrets {
			id := secretID{definition.account, definition.key, name}
			value.Placeholder = sl.Keys.placeholder(id)
			value.Client = client
			value.Save = func(ctx context.Context, before, after json.RawMessage) error {
				return m.replaceValue(ctx, definition, id, before, after)
			}
		}
	}
	for name, id := range cfg.Identities {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(id.Key))
		if err != nil {
			return nil, fmt.Errorf("identity %s: %w", name, err)
		}
		fingerprint := ssh.FingerprintSHA256(key)
		if _, exists := s.principals[fingerprint]; exists {
			return nil, fmt.Errorf("identity %s shares another identity's public key", name)
		}
		s.principals[fingerprint] = principal{Key: fingerprint, Name: name, identity: id}
	}
	if s.query, s.program, err = preparePolicy(ctx, cfg); err != nil {
		return nil, err
	}
	if err := s.buildCatalog(); err != nil {
		return nil, err
	}
	return s, nil
}

// Provider writes preserve the connector and publish only after persistence.
func (m *monitor) replaceValue(ctx context.Context, c *connection, id secretID, before, after json.RawMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.live.Load().connections[c.name] != c || !bytes.Equal(m.store.doc.Secrets.get(id), before) {
		return errors.New("credential changed; start again")
	}
	next := m.store.doc
	next.Secrets = next.Secrets.clone()
	next.Secrets.set(id, bytes.Clone(after))
	return m.store.commit(ctx, next)
}
