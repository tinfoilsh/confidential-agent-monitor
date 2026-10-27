// Package monitor owns authorization transactions, connector lifetimes and owner and agent APIs.
package monitor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/internal/config"
	"github.com/tinfoilsh/monitor/internal/frontdoor"
	"github.com/tinfoilsh/monitor/internal/policy"
	"github.com/tinfoilsh/monitor/internal/store"
	"github.com/tinfoilsh/monitor/internal/tinfoil/sandbox"
	"github.com/tinfoilsh/monitor/internal/worker"
	"github.com/tinfoilsh/monitor/presets"
	"gocloud.dev/blob"
	"golang.org/x/crypto/ssh"
)

// state is an immutable settings snapshot, published as a whole through live.
// Mutable connector availability and stream authority belong to monitor.
type state struct {
	*config.Config
	Engine    *policy.Engine
	Catalog   map[string]presets.Entry
	CatalogID string
	connector.Env
}

type connection struct {
	config.ConnectionSpec
	Server  connector.Server
	Secrets map[string]*credential.Value
	setup   *connector.Prepared
	env     connector.Env
	ctx     context.Context // Logical stream authority, not resource lifetime.
	cancel  context.CancelFunc
	active  sync.WaitGroup // Final retirement only; ordinary Update does not join uses.
	ready   bool
	err     error
	details json.RawMessage
}

type status struct {
	State   string          `json:"state"`
	Error   string          `json:"error,omitempty"`
	Details json.RawMessage `json:"details,omitempty"`
}

// Status runs under monitor.mu. Process availability is independent
// of successful setup delivery; it is queried directly without a watcher.
func (c *connection) Status() status {
	if c.err != nil {
		return status{State: "error", Error: c.err.Error()}
	}
	if !c.ready {
		return status{State: "connecting"}
	}
	if runtime, ok := c.Server.(interface{ Ready() error }); ok {
		if err := runtime.Ready(); err != nil {
			return status{State: "error", Error: err.Error()}
		}
	}
	return status{State: "ready", Details: c.details}
}

// acquire runs under mu and pins a ready connector until the caller finishes.
// Retirement cancels its authority before waiting for these uses to return.
func (m *monitor) acquire(c *connection, setup *connector.Prepared) error {
	if c == nil || m.connections[c.Name] != c || c.setup != setup || c.Status().State != "ready" {
		return errChanged
	}
	c.active.Add(1)
	return nil
}
func (c *connection) close() {
	// Drain work before teardown.
	c.active.Wait()
	if closer, ok := c.Server.(io.Closer); ok {
		_ = closer.Close()
	}
}

type connectionPlan struct {
	config.ConnectionSpec
	setup   *connector.Prepared
	secrets map[string]*credential.Value
}

// settingsPlan contains parsed settings, never candidate runtime instances.
type settingsPlan struct {
	next    *state
	source  string
	secrets store.Secrets
	updates []connectionPlan
	remove  []string
}

type Options struct {
	Bucket         *blob.Bucket
	BucketURL      string
	OwnerPublicKey ed25519.PublicKey
	HostKey        ssh.Signer
	Connectors     map[string]connector.Definition
	Workers        worker.Launcher
	EmbeddedFiles  http.Handler
}
type streamAuthority struct {
	key        string
	connection *connection
	setup      *connector.Prepared
	route      bool
}

// monitor owns the mutable document, connections, streams and approvals under mu.
// writes serializes settings preparation, commit, delivery and final teardown.
// When both are needed, take writes before mu. Connection-map membership changes
// require both locks, so a reader may hold either; gate only needs mu.
type monitor struct {
	workers                 worker.Launcher
	kinds                   map[string]connector.Definition
	live                    atomic.Pointer[state]
	mu                      sync.Mutex
	writes                  sync.Mutex
	store                   store.Store
	connections             map[string]*connection
	audit                   store.AuditLog[*record]
	ownerPublicKey          ed25519.PublicKey
	sshHostKey              ssh.Signer
	embeddedFiles, ownerAPI http.Handler
	bucket                  string
	forwards                *frontdoor.Forwarder
	sandboxes               *sandbox.Service
	streams                 map[*connector.Stream]streamAuthority
	records                 []*record
	signIns                 sync.Map
}

func New(o Options) *monitor {
	if o.EmbeddedFiles == nil {
		o.EmbeddedFiles = http.NotFoundHandler()
	}
	m := &monitor{
		store:          store.Store{Bucket: o.Bucket},
		audit:          store.AuditLog[*record]{Bucket: o.Bucket},
		ownerPublicKey: o.OwnerPublicKey,
		sshHostKey:     o.HostKey,
		bucket:         o.BucketURL,
		kinds:          o.Connectors,
		workers:        o.Workers,
		embeddedFiles:  o.EmbeddedFiles,
		forwards:       new(frontdoor.Forwarder),
		connections:    map[string]*connection{},
		streams:        map[*connector.Stream]streamAuthority{},
	}
	m.sandboxes = sandbox.New(m, m.forwards, sandbox.Verify)
	m.ownerAPI = m.newOwnerAPI()
	return m
}
func (m *monitor) generation() (uint64, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.store.Doc.Generation, m.live.Load() != nil
}

func (m *monitor) unlock(ctx context.Context, key []byte, minimum uint64, initialize bool) error {
	m.writes.Lock()
	defer m.writes.Unlock()
	m.mu.Lock()
	if m.ownerPublicKey != nil && len(key) != store.OwnerKeyBytes {
		m.mu.Unlock()
		return store.ErrOwner
	}
	if m.live.Load() != nil {
		defer m.mu.Unlock()
		if !m.store.IsOwner(key) {
			return store.ErrOwner
		}
		if m.store.Doc.Generation < minimum {
			return fmt.Errorf("live generation %d is older than %d", m.store.Doc.Generation, minimum)
		}
		return nil
	}
	base := m.store
	m.mu.Unlock()
	next, err := base.Load(ctx, key, minimum, initialize)
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
	plan, err := m.prepareSettings(ctx, next.Doc, next.Doc, env)
	if err != nil {
		return err
	}
	m.mu.Lock()
	m.store = next
	install, retired, err := m.commitSettings(ctx, next.Doc, plan, nil)
	if err != nil {
		m.store = base
	} else {
		m.audit.SealWith(next.Sealer)
	}
	m.mu.Unlock()
	if err != nil {
		return err
	}
	m.installConnections(install, retired)
	return nil
}

// prepareSettings validates settings and parses connector setups under writes, without
// mu. It creates no runtime instances. Stored maps and settings snapshots are
// immutable; credential refreshes can still commit while validation runs.
func (m *monitor) prepareSettings(ctx context.Context, base, proposed store.Document, env connector.Env) (*settingsPlan, error) {
	current := m.live.Load()
	next := current
	if current == nil || proposed.Policy != base.Policy {
		cfg, err := config.Load(proposed.Policy)
		if err != nil {
			return nil, err
		}
		// Preserve state across formatting.
		if current == nil || !reflect.DeepEqual(cfg, current.Config) {
			for _, id := range cfg.Identities {
				if err := sandbox.ValidateMetadata(id.Sandbox); err != nil {
					return nil, err
				}
			}
			var engine *policy.Engine
			if current != nil && cfg.SameProgram(current.Config) {
				engine = current.Engine
			} else if engine, err = policy.Prepare(ctx, cfg.Data, cfg.Policies, cfg.Lattices.Confidentiality, cfg.Lattices.Integrity); err != nil {
				return nil, err
			}
			next = &state{Config: cfg, Engine: engine, Env: env}
			next.Dialer = connector.NewDialer(cfg.AllowNetworks)
			if next.Catalog, next.CatalogID, err = cfg.Catalog(); err != nil {
				return nil, err
			}
		}
	}
	plan := &settingsPlan{next: next, source: proposed.Policy, secrets: store.Secrets{}}
	sameNetworks := current != nil && slices.Equal(current.AllowNetworks, next.AllowNetworks)
	present := map[string]bool{}
	for _, account := range slices.Sorted(maps.Keys(next.Accounts)) {
		specs, err := next.Connections(account)
		if err != nil {
			return nil, err
		}
		for _, spec := range specs {
			present[spec.Name] = true
			def := m.kinds[spec.Protocol]
			if def.Parse == nil || def.New == nil {
				return nil, fmt.Errorf("connection %s has unknown kind %s", spec.Name, spec.Protocol)
			}
			c, values := m.connections[spec.Name], proposed.Secrets.Connection(spec.Account, spec.Key)
			if c != nil && c.Protocol != spec.Protocol {
				plan.remove = append(plan.remove, spec.Name)
			}
			sameConnection := c != nil && c.Protocol == spec.Protocol && c.Account == spec.Account && c.Key == spec.Key
			reusable := sameConnection && sameNetworks
			unchanged := reusable &&
				bytes.Equal(c.Config, spec.Config) &&
				bytes.Equal(c.Definition, spec.Definition) &&
				bytes.Equal(c.Options, spec.Options) &&
				slices.Equal(c.Credentials, spec.Credentials)
			var parsed connector.Prepared
			if unchanged {
				parsed = *c.setup
			} else if parsed, err = def.Parse(connector.Setup{Config: spec.Config, Definition: spec.Definition, Options: spec.Options}); err != nil {
				return nil, fmt.Errorf("connection %s: %w", spec.Name, err)
			}
			if parsed.Secrets != nil {
				for name, raw := range values {
					plan.secrets.Set(store.SecretID{Account: spec.Account, Connection: spec.Key, Name: name}, raw)
				}
			}
			if unchanged && maps.EqualFunc(base.Secrets.Connection(spec.Account, spec.Key), values, slices.Equal[json.RawMessage]) {
				// Retry unavailable, unchanged connections.
				if !c.ready || c.Status().State != "ready" {
					plan.updates = append(plan.updates, connectionPlan{spec, c.setup, c.Secrets})
				}
				continue
			}
			var handles map[string]*credential.Value
			if parsed.Secrets != nil {
				handles = map[string]*credential.Value{}
				for _, name := range parsed.Secrets {
					handles[name] = nil
				}
				for _, name := range spec.Credentials {
					handles[name] = nil
				}
				for name := range values {
					handles[name] = nil
				}
				for name := range handles {
					id := store.SecretID{Account: spec.Account, Connection: spec.Key, Name: name}
					if reusable && c.Secrets[name] != nil && bytes.Equal(base.Secrets.Get(id), values[name]) {
						handles[name] = c.Secrets[name]
					}
				}
			}
			parsed.Discovery.Placeholders = maps.Clone(parsed.Discovery.Placeholders)
			if parsed.Discovery.Placeholders != nil {
				for name := range handles {
					parsed.Discovery.Placeholders[name] = placeholder(proposed.Keys, store.SecretID{Account: spec.Account, Connection: spec.Key, Name: name})
				}
			}
			plan.updates = append(plan.updates, connectionPlan{spec, &parsed, handles})
		}
	}

	for name := range m.connections {
		if !present[name] {
			plan.remove = append(plan.remove, name)
		}
	}
	return plan, nil
}

// commitSettings runs under writes and mu: rebase the planned changes, persist them,
// publish the settings and revoke lost authority. Changed connectors remain
// unavailable until installation. A saved approval is answered after persistence
// and before general settings invalidation.
func (m *monitor) commitSettings(ctx context.Context, base store.Document, plan *settingsPlan, saved *savedApproval) (install, retired []*connection, err error) {
	next := m.store.Doc
	next.Policy, next.Secrets = plan.source, store.Secrets{}
	for account, connections := range plan.secrets {
		for connection, fields := range connections {
			for name, raw := range fields {
				id := store.SecretID{Account: account, Connection: connection, Name: name}
				// Preserve concurrent credential refreshes.
				if bytes.Equal(raw, base.Secrets.Get(id)) {
					raw = m.store.Doc.Secrets.Get(id)
				}
				next.Secrets.Set(id, raw)
			}
		}
	}
	// Bind new handles to the latest durable record exactly once, before commit.
	// This is pure credential validation; it takes no Value lock or network call.
	client := plan.next.Client()
	for _, update := range plan.updates {
		for name, value := range update.secrets {
			if value != nil {
				continue
			}
			id := store.SecretID{Account: update.Account, Connection: update.Key, Name: name}
			v := new(credential.Value)
			if raw := next.Secrets.Get(id); raw != nil {
				if err := v.UnmarshalJSON(raw); err != nil {
					return nil, nil, fmt.Errorf("credential %s/%s: %w", update.Name, name, err)
				}
			}
			v.Placeholder, v.Client = placeholder(next.Keys, id), client
			v.Save = func(ctx context.Context, before, after json.RawMessage) error {
				return m.replaceValue(ctx, id, v, before, after)
			}
			update.secrets[name] = v
		}
	}
	next.Enrolled, next.Labels = maps.Clone(next.Enrolled), maps.Clone(next.Labels)
	if next.Enrolled == nil {
		next.Enrolled = map[string]bool{}
	}
	// Remember previously enrolled keys.
	for key := range plan.next.Principals {
		next.Enrolled[key] = true
	}
	maps.DeleteFunc(next.Labels, func(key string, _ facts.Label) bool { _, ok := plan.next.Principals[key]; return !ok })
	// Persist before publishing authority.
	if !reflect.DeepEqual(next, m.store.Doc) || m.live.Load() == nil {
		if err := m.store.Commit(ctx, next); err != nil {
			return nil, nil, err
		}
	}
	if saved != nil {
		saved.record.ruleSaved(saved.answer)
	}
	old, changed := m.live.Load(), false
	for _, name := range plan.remove {
		c := m.connections[name]
		c.cancel()
		retired = append(retired, c)
		delete(m.connections, name)
		changed = true
	}
	for _, update := range plan.updates {
		c := m.connections[update.Name]
		if c == nil {
			def := m.kinds[update.Protocol]
			c = &connection{}
			if m.workers != nil {
				c.Server = &worker.Proxy{Definition: def, Kind: update.Protocol, Launcher: m.workers}
			} else {
				c.Server = def.New()
			}
			m.connections[update.Name] = c
		}
		if c.setup != update.setup {
			if c.cancel != nil {
				c.cancel()
			}
			c.ctx, c.cancel = context.WithCancel(context.Background())
			changed = true
		}
		c.ConnectionSpec, c.setup, c.Secrets = update.ConnectionSpec, update.setup, update.secrets
		// Admission requires successful delivery.
		c.env, c.ready, c.err = plan.next.Env, false, nil
		if !m.kinds[c.Protocol].HostKey {
			c.env.HostKey = nil
		}
		install = append(install, c)
	}
	m.live.Store(plan.next)
	// Close streams losing authority.
	for stream, authority := range m.streams {
		if !m.sameStreamAuthority(old, authority) {
			stream.Close()
		}
	}
	if old != plan.next || changed {
		m.refusePending(errChanged)
	}
	return install, retired, nil
}

// installConnections installs committed setups under writes, without mu during connector
// I/O. Each successful Update makes that connector ready for admission. Delivery
// finishes before the settings write returns, even if its caller disconnects.
func (m *monitor) installConnections(install, retired []*connection) {
	for _, c := range retired {
		c.close()
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	for _, c := range install {
		env := c.env
		err := c.Server.Update(ctx, *c.setup, c.Secrets, &env)
		m.mu.Lock()
		c.err, c.ready = err, err == nil
		if d, ok := c.Server.(connector.Detailer); ok && err == nil {
			c.details = d.Details()
		}
		m.mu.Unlock()
	}
}

func (m *monitor) Close() {
	m.writes.Lock()
	defer m.writes.Unlock()
	m.mu.Lock()
	retired := slices.Collect(maps.Values(m.connections))
	for _, c := range retired {
		c.cancel()
	}
	clear(m.connections)
	m.mu.Unlock()
	for _, c := range retired {
		c.close()
	}
}

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
