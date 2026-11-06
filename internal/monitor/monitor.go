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

	"github.com/flynn/noise"
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

// settings is an immutable snapshot of the saved settings, published as a whole.
// Mutable connector availability and stream authority belong to monitor.
type settings struct {
	*config.Config
	Engine    *policy.Engine
	Catalog   map[string]presets.Entry
	CatalogID string
	connector.Env
}

type connection struct {
	config.ConnectionSpec
	Server      connector.Server
	Credentials map[string]*credential.Value
	prepared    *connector.Prepared
	env         connector.Env
	setupCtx    context.Context // Logical stream authority, not resource lifetime.
	cancelSetup context.CancelFunc
	active      sync.WaitGroup // Final retirement only; ordinary Update does not join uses.
	ready       bool
	err         error
	details     json.RawMessage
}

type status struct {
	State   string          `json:"state"`
	Error   string          `json:"error,omitempty"`
	Details json.RawMessage `json:"details,omitempty"`
}

const (
	statusError      = "error"
	statusConnecting = "connecting"
	statusReady      = "ready"
)

// Status runs under monitor.mu. Process availability is independent
// of successful setup delivery; it is queried directly without a watcher.
func (c *connection) Status() status {
	if c.err != nil {
		return status{State: statusError, Error: c.err.Error()}
	}
	if !c.ready {
		return status{State: statusConnecting}
	}
	if runtime, ok := c.Server.(interface{ Ready() error }); ok {
		if err := runtime.Ready(); err != nil {
			return status{State: statusError, Error: err.Error()}
		}
	}
	return status{State: statusReady, Details: c.details}
}

// usable runs under mu: c is still installed with this setup and ready.
func (m *monitor) usable(c *connection, prepared *connector.Prepared) bool {
	return c != nil && m.connections[c.Name] == c && c.prepared == prepared && c.Status().State == statusReady
}

// acquire runs under mu and pins a ready connector until release.
// Retirement cancels its authority before waiting for these uses to return.
func (m *monitor) acquire(c *connection, prepared *connector.Prepared) (release func(), err error) {
	if !m.usable(c, prepared) {
		return nil, errChanged
	}
	c.active.Add(1)
	return c.active.Done, nil
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
	prepared    *connector.Prepared
	credentials map[string]*credential.Value
}

// settingsPlan contains parsed settings, never candidate runtime instances.
type settingsPlan struct {
	next        *settings
	source      string
	credentials store.Secrets
	updates     []connectionPlan
	remove      []string
}

type Options struct {
	Bucket         *blob.Bucket
	OwnerPublicKey ed25519.PublicKey
	SessionKey     noise.DHKey
	HostKey        ssh.Signer
	Connectors     map[string]connector.Kind
	Workers        worker.Launcher
	EmbeddedFiles  http.Handler
}
type admission struct {
	fingerprint string
	connection  *connection
	prepared    *connector.Prepared
	route       bool
}

// monitor owns the mutable document, connections, streams and approvals under mu.
// writes serializes settings preparation, commit, delivery and final teardown.
// When both are needed, take writes before mu. Connection-map membership changes
// require both locks, so a reader may hold either; gate only needs mu.
type monitor struct {
	workers                 worker.Launcher
	kinds                   map[string]connector.Kind
	settings                atomic.Pointer[settings]
	mu                      sync.Mutex
	writes                  sync.Mutex
	store                   store.Store
	connections             map[string]*connection
	audit                   store.AuditLog[*record]
	ownerPublicKey          ed25519.PublicKey
	sessionKey              noise.DHKey
	sshHostKey              ssh.Signer
	embeddedFiles, ownerAPI http.Handler
	forwards                *frontdoor.Forwarder
	relays                  http.RoundTripper
	streams                 map[*connector.Stream]admission
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
		sessionKey:     o.SessionKey,
		sshHostKey:     o.HostKey,
		kinds:          o.Connectors,
		workers:        o.Workers,
		embeddedFiles:  o.EmbeddedFiles,
		forwards:       new(frontdoor.Forwarder),
		connections:    map[string]*connection{},
		streams:        map[*connector.Stream]admission{},
	}
	m.relays = sandbox.Relays(m.forwards)
	m.ownerAPI = m.newOwnerAPI()
	return m
}
func (m *monitor) generation() (uint64, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.store.Doc.Generation, m.settings.Load() != nil
}

// snapshot returns the committed document and the settings published from it.
func (m *monitor) snapshot() (store.Document, *settings) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.store.Doc, m.settings.Load()
}

// unlock reports whether it created the Monitor's state.
func (m *monitor) unlock(ctx context.Context, key []byte, minimum uint64) (bool, error) {
	m.writes.Lock()
	defer m.writes.Unlock()
	m.mu.Lock()
	if m.ownerPublicKey != nil && len(key) != store.OwnerKeyBytes {
		m.mu.Unlock()
		return false, store.ErrOwner
	}
	if m.settings.Load() != nil {
		defer m.mu.Unlock()
		if !m.store.IsOwner(key) {
			return false, store.ErrOwner
		}
		if m.store.Doc.Generation < minimum {
			return false, fmt.Errorf("live generation %d is older than %d", m.store.Doc.Generation, minimum)
		}
		return false, nil
	}
	base := m.store
	m.mu.Unlock()
	next, created, err := base.Load(ctx, key, minimum)
	if err != nil {
		return false, err
	}
	var env connector.Env
	if env.TLS, err = connectionTLS(&next.Doc.Keys); err != nil {
		return false, err
	}
	env.HostKey = m.sshHostKey
	if env.HostKey == nil {
		if env.HostKey, err = next.Doc.Keys.HostSigner(); err != nil {
			return false, err
		}
	}
	plan, err := m.prepareSettings(ctx, next.Doc, next.Doc, nil, env)
	if err != nil {
		return false, err
	}
	m.mu.Lock()
	m.store = next
	install, retired, err := m.commitSettings(ctx, plan, nil)
	if err != nil {
		m.store = base
	} else {
		m.audit.SealWith(next.Sealer)
	}
	m.mu.Unlock()
	if err != nil {
		return false, err
	}
	m.installConnections(install, retired)
	return created, nil
}

// prepareSettings validates settings and parses connector setups under writes, without
// mu. It creates no runtime instances. Stored maps and settings snapshots are
// immutable; credential refreshes can still commit while validation runs.
func (m *monitor) prepareSettings(ctx context.Context, base, proposed store.Document, credentials store.Secrets, env connector.Env) (*settingsPlan, error) {
	current := m.settings.Load()
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
			next = &settings{Config: cfg, Engine: engine, Env: env}
			next.Dialer = connector.NewDialer(cfg.AllowNetworks)
			if next.Catalog, next.CatalogID, err = cfg.Catalog(); err != nil {
				return nil, err
			}
		}
	}
	plan := &settingsPlan{next: next, source: proposed.Policy, credentials: credentials}
	sameNetworks := current != nil && slices.Equal(current.AllowNetworks, next.AllowNetworks)
	present := map[string]bool{}
	for _, name := range slices.Sorted(maps.Keys(next.Connections)) {
		spec, err := next.Spec(name)
		if err != nil {
			return nil, err
		}
		present[spec.Name] = true
		kind := m.kinds[spec.Protocol]
		if kind.Parse == nil || kind.New == nil {
			return nil, fmt.Errorf("connection %s has unknown kind %s", spec.Name, spec.Protocol)
		}
		c := m.connections[spec.Name]
		if c != nil && c.Protocol != spec.Protocol {
			plan.remove = append(plan.remove, spec.Name)
		}
		sameConnection := c != nil && c.Protocol == spec.Protocol
		reusable := sameConnection && sameNetworks
		unchanged := reusable &&
			bytes.Equal(c.Config, spec.Config) &&
			bytes.Equal(c.Definition, spec.Definition) &&
			bytes.Equal(c.Options, spec.Options) &&
			len(credentials[spec.Name]) == 0
		if unchanged {
			// Retry unavailable, unchanged connections.
			if c.Status().State != statusReady {
				plan.updates = append(plan.updates, connectionPlan{spec, c.prepared, c.Credentials})
			}
			continue
		}
		parsed, err := kind.Parse(connector.Setup{Config: spec.Config, Definition: spec.Definition, Options: spec.Options})
		if err != nil {
			return nil, fmt.Errorf("connection %s: %w", spec.Name, err)
		}
		var handles map[string]*credential.Value
		if parsed.SecretNames != nil {
			handles = map[string]*credential.Value{}
			for _, name := range parsed.SecretNames {
				handles[name] = nil
			}
		}
		for name, raw := range credentials[spec.Name] {
			if _, uses := handles[name]; raw != nil && !uses {
				return nil, fmt.Errorf("connection %s does not use credential %s", spec.Name, name)
			}
		}
		parsed.Discovery.Placeholders = maps.Clone(parsed.Discovery.Placeholders)
		if parsed.Discovery.Placeholders != nil {
			for name := range handles {
				parsed.Discovery.Placeholders[name] = placeholder(proposed.Keys, store.SecretID{Connection: spec.Name, Name: name})
			}
		}
		plan.updates = append(plan.updates, connectionPlan{spec, &parsed, handles})
	}
	for name := range credentials {
		if !present[name] {
			return nil, fmt.Errorf("connection %s does not exist", name)
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
func (m *monitor) commitSettings(ctx context.Context, plan *settingsPlan, saved *savedAnswer) (install, retired []*connection, err error) {
	next := m.store.Doc
	next.Policy = plan.source
	next.Credentials = next.Credentials.Clone()
	for connection, values := range plan.credentials {
		for name, raw := range values {
			next.Credentials.Set(store.SecretID{Connection: connection, Name: name}, raw)
		}
	}
	maps.DeleteFunc(next.Credentials, func(connection string, _ map[string]json.RawMessage) bool {
		_, ok := plan.next.Connections[connection]
		return !ok
	})
	// Bind new handles to the latest durable record exactly once, before commit.
	// This is pure credential validation; it takes no Value lock or network call.
	client := plan.next.Client()
	for _, update := range plan.updates {
		for name, value := range update.credentials {
			if value != nil {
				continue
			}
			id, v := store.SecretID{Connection: update.Name, Name: name}, new(credential.Value)
			if raw := next.Credentials.Get(id); raw != nil {
				if err := v.UnmarshalJSON(raw); err != nil {
					return nil, nil, fmt.Errorf("credential %s/%s: %w", update.Name, name, err)
				}
			}
			v.Placeholder, v.Client = placeholder(next.Keys, id), client
			v.Save = func(ctx context.Context, before, after json.RawMessage) error {
				return m.replaceValue(ctx, id, v, before, after)
			}
			update.credentials[name] = v
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
	if !reflect.DeepEqual(next, m.store.Doc) || m.settings.Load() == nil {
		if err := m.store.Commit(ctx, next); err != nil {
			return nil, nil, err
		}
	}
	if saved != nil {
		saved.record.committed(saved.answer)
	}
	old, changed := m.settings.Load(), false
	for _, name := range plan.remove {
		c := m.connections[name]
		c.cancelSetup()
		retired = append(retired, c)
		delete(m.connections, name)
		changed = true
	}
	for _, update := range plan.updates {
		c := m.connections[update.Name]
		if c == nil {
			kind := m.kinds[update.Protocol]
			c = &connection{}
			if m.workers != nil {
				c.Server = &worker.Proxy{Kind: kind, Protocol: update.Protocol, Launcher: m.workers}
			} else {
				c.Server = kind.New()
			}
			m.connections[update.Name] = c
		}
		if c.prepared != update.prepared {
			if c.cancelSetup != nil {
				c.cancelSetup()
			}
			c.setupCtx, c.cancelSetup = context.WithCancel(context.Background())
			changed = true
		}
		c.ConnectionSpec, c.prepared, c.Credentials = update.ConnectionSpec, update.prepared, update.credentials
		// Admission requires successful delivery.
		c.env, c.ready, c.err = plan.next.Env, false, nil
		if !m.kinds[c.Protocol].UsesHostKey {
			c.env.HostKey = nil
		}
		install = append(install, c)
	}
	m.settings.Store(plan.next)
	// Close streams losing authority.
	for stream, a := range m.streams {
		if !m.stillAdmitted(old, a) {
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
		err := c.Server.Update(ctx, *c.prepared, c.Credentials, &env)
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
		c.cancelSetup()
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
