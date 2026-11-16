// Package monitor owns authorization transactions, connector lifetimes and owner and agent APIs.
package monitor

import (
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"net/http"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/core"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/identity"
	"github.com/tinfoilsh/confidential-agent-monitor/core/netx"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/credential"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/internal/authz"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/internal/config"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/internal/sealedlog"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/internal/store"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/policy"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/presets"
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
	publicScope map[string][]string
}

type connectionPlan struct {
	config.ConnectionSpec
	prepared    *connector.Prepared
	credentials map[string]connector.Secret
}

// settingsPlan contains parsed settings, never candidate runtime instances.
type settingsPlan struct {
	next        *settings
	source      string
	credentials store.Secrets
	renamed     map[string]string
	updates     []connectionPlan
	remove      []string
}

const approvalWait = 2 * time.Minute

type Options struct {
	Bucket         *blob.Bucket
	HostKey        ssh.Signer
	Connectors     map[string]connector.Kind
	ApprovalWait   time.Duration // Zero waits approvalWait.
	PassphraseKeys bool
	Policy         func() (string, error)
	Presets        presets.Set
	BasePolicy     string
	PolicyLibrary  policy.Library
	Vocabulary     facts.Vocabulary
	Secrets        *os.Root
	Events         *slog.Logger
	Attributes     map[string]func(json.RawMessage) error
	Admin          map[string]http.Handler // Owner-only admin routes by ServeMux pattern.
}

// Monitor owns the mutable document and approvals under mu; table owns connections and streams.
// writes serializes settings preparation, commit, delivery and final teardown.
// When both are needed, take writes before mu. The table's lock is taken inside either;
// gate only needs mu.
type Monitor struct {
	kinds          map[string]connector.Kind
	settings       atomic.Pointer[settings]
	mu             sync.Mutex
	writes         sync.Mutex
	store          store.Store
	table          *core.Table
	audit          sealedlog.Log[*record]
	passphraseKeys bool
	sshHostKey     ssh.Signer
	policy         func() (string, error)
	presets        presets.Set
	basePolicy     string
	policyLibrary  policy.Library
	vocabulary     facts.Vocabulary
	secrets        *os.Root
	events         *slog.Logger
	attributes     map[string]func(json.RawMessage) error
	admin          map[string]http.Handler
	identities     *identity.Registry
	gate           *authz.Gatekeeper
	records        []*record
	signIns        credential.SignIns
}

func New(o Options) (*Monitor, error) {
	for _, name := range []string{"decision", "admin", "capable"} {
		if o.PolicyLibrary.Queries[name] == "" {
			return nil, fmt.Errorf("policy library needs query %s", name)
		}
	}
	if o.BasePolicy != "" {
		if _, err := policy.Prepare(context.Background(), o.PolicyLibrary, o.BasePolicy, nil, nil); err != nil {
			return nil, err
		}
	}
	if !o.Vocabulary.ValidLabel(o.Vocabulary.Initial) {
		return nil, errors.New("policy vocabulary needs a valid initial label")
	}
	m := &Monitor{
		policyLibrary:  o.PolicyLibrary,
		vocabulary:     o.Vocabulary,
		store:          store.Store{Bucket: o.Bucket, Presets: o.Presets},
		audit:          sealedlog.Log[*record]{Bucket: o.Bucket, Prefix: auditPrefix},
		passphraseKeys: o.PassphraseKeys,
		sshHostKey:     o.HostKey,
		policy:         o.Policy,
		presets:        o.Presets,
		basePolicy:     o.BasePolicy,
		secrets:        o.Secrets,
		events:         cmp.Or(o.Events, slog.New(slog.DiscardHandler)),
		kinds:          o.Connectors,
		attributes:     o.Attributes,
		admin:          o.Admin,
	}
	m.table = core.New(o.Connectors, access{m})
	m.identities = new(identity.Registry)
	m.gate = authz.New(&m.mu, m.identities, m.currentPolicy, gateStore{m}, cmp.Or(o.ApprovalWait, approvalWait), o.Vocabulary.Initial)
	return m, nil
}
func (m *Monitor) Generation() (uint64, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.store.Doc.Generation, m.settings.Load() != nil
}

func (m *Monitor) snapshot() (store.Document, *settings) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.store.Doc, m.settings.Load()
}

func (m *Monitor) Unlock(ctx context.Context, key []byte) error {
	_, err := m.unlock(ctx, key, 0)
	return err
}

// unlock reports whether it created the Monitor's state.
func (m *Monitor) unlock(ctx context.Context, key []byte, minimum uint64) (bool, error) {
	m.writes.Lock()
	defer m.writes.Unlock()
	m.mu.Lock()
	if !m.passphraseKeys && len(key) != store.OwnerKeyBytes {
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
		if env.HostKey, err = hostSigner(&next.Doc.Keys); err != nil {
			return false, err
		}
	}
	source := next.Doc.Policy
	if m.policy != nil {
		if source, err = m.policy(); err != nil {
			return false, err
		}
	}
	plan, err := m.prepareSettings(ctx, source, everyConnector, nil, nil, env)
	if err != nil {
		return false, err
	}
	m.mu.Lock()
	m.store = next
	err = m.commitSettings(ctx, plan, nil)
	if err != nil {
		m.store = base
	} else {
		m.audit.SealWith(next.Sealer)
		m.recordAdmin(ctx, "Unlock", nil, nil)
	}
	m.mu.Unlock()
	if err != nil {
		return false, err
	}
	m.table.Start()
	return created, nil
}

func everyConnector(string) bool { return true }

// prepareSettings validates source and parses the connector setups to rebuild
// under writes, without mu. It creates no runtime instances. Stored maps and
// settings snapshots are immutable; credential refreshes can still commit while
// validation runs.
func (m *Monitor) prepareSettings(ctx context.Context, source string, rebuild func(connection string) bool, renamed map[string]string, credentials store.Secrets, env connector.Env) (*settingsPlan, error) {
	cfg, err := config.Load(source, m.presets, m.vocabulary)
	if err != nil {
		return nil, err
	}
	for name, id := range cfg.Identities {
		for key, value := range id.Attributes {
			validate := m.attributes[key]
			if validate == nil {
				return nil, fmt.Errorf("identity %s has no field %s", name, key)
			}
			if err := validate(value); err != nil {
				return nil, fmt.Errorf("identity %s %s: %w", name, key, err)
			}
		}
	}
	library := m.policyLibrary
	library.Data = maps.Clone(library.Data)
	if library.Data == nil {
		library.Data = map[string]any{}
	}
	library.Data["levels"] = map[string]any{"audiences": m.vocabulary.Audiences, "trusts": m.vocabulary.Trusts, "effects": m.vocabulary.Effects}
	library.Data["lattices"] = cfg.Lattices
	engine, err := policy.Prepare(ctx, library, m.basePolicy, cfg.Data, cfg.Policies)
	if err != nil {
		return nil, err
	}
	next := &settings{Config: cfg, Engine: engine, Env: env, publicScope: map[string][]string{}}
	next.Dialer = connector.NewDialer(cfg.AllowNetworks)
	operations := map[string]map[string]facts.OperationSummary{}
	plan := &settingsPlan{next: next, source: source, credentials: credentials, renamed: renamed}
	present := map[string]bool{}
	installed := m.table.Connections()
	for _, name := range slices.Sorted(maps.Keys(next.Connections)) {
		spec, err := next.Spec(name)
		if err != nil {
			return nil, err
		}
		present[spec.Name] = true
		next.publicScope[spec.Name] = spec.PublicScope
		kind := m.kinds[spec.Protocol]
		if kind.Parse == nil || kind.Open == nil {
			return nil, fmt.Errorf("service %s has unknown kind %s", spec.Name, spec.Protocol)
		}
		c, exists := installed[spec.Name]
		if exists && c.Protocol != spec.Protocol {
			plan.remove = append(plan.remove, spec.Name)
		}
		if exists && c.Protocol == spec.Protocol && !rebuild(spec.Name) && len(credentials[spec.Name]) == 0 {
			operations[next.Connections[spec.Name].Preset] = c.Prepared.Operations
			if c.State != core.Ready {
				plan.updates = append(plan.updates, connectionPlan{spec, c.Prepared, c.Secrets})
			}
			continue
		}
		setup := connector.Setup{Vocabulary: m.vocabulary, Config: spec.Config, Definition: spec.Definition, Options: spec.Options}
		parsed, err := kind.Parse(setup)
		if err != nil {
			return nil, fmt.Errorf("service %s: %w", spec.Name, err)
		}
		parsed.Source = setup
		operations[next.Connections[spec.Name].Preset] = parsed.Operations
		handles := map[string]connector.Secret{}
		for _, name := range parsed.SecretNames {
			handles[name] = nil
		}
		for name, raw := range credentials[spec.Name] {
			if _, uses := handles[name]; raw != nil && !uses {
				return nil, fmt.Errorf("service %s does not use credential %s", spec.Name, name)
			}
		}
		plan.updates = append(plan.updates, connectionPlan{spec, &parsed, handles})
	}
	if next.Catalog, next.CatalogID, err = cfg.Catalog(operations); err != nil {
		return nil, err
	}
	for name := range credentials {
		if !present[name] {
			return nil, fmt.Errorf("service %s does not exist", name)
		}
	}

	for name := range installed {
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
func (m *Monitor) commitSettings(ctx context.Context, plan *settingsPlan, saved *savedAnswer) (err error) {
	next := m.store.Doc
	next.Policy = plan.source
	next.Credentials = next.Credentials.Clone()
	for to, from := range plan.renamed {
		if values, ok := m.store.Doc.Credentials[from]; ok {
			next.Credentials[to] = maps.Clone(values)
		}
	}
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
				if v, err = credential.Parse(raw, m.secrets); err != nil {
					return fmt.Errorf("credential %s/%s: %w", update.Name, name, err)
				}
			}
			v.Client = client
			v.SetPlaceholder(placeholder(next.Keys, id))
			v.Save = func(ctx context.Context, before, after json.RawMessage) error {
				return m.replaceValue(ctx, id, v, before, after)
			}
			update.credentials[name] = v
		}
	}
	next.Enrolled = maps.Clone(next.Enrolled)
	if next.Enrolled == nil {
		next.Enrolled = map[string]bool{}
	}
	for key := range plan.next.Principals {
		next.Enrolled[key] = true
	}
	next.Revision++
	// Persist before publishing authority.
	if err := m.store.Commit(ctx, next); err != nil {
		return err
	}
	if saved != nil {
		m.gate.Saved(saved.record.Record, saved.answer)
	}
	for _, name := range plan.remove {
		m.table.Remove(name)
	}
	for _, update := range plan.updates {
		m.table.Stage(update.Name, update.Protocol, update.prepared, update.credentials, plan.next.Env)
	}
	previous := m.settings.Swap(plan.next)
	if previous != nil {
		for key := range previous.Principals {
			if _, kept := plan.next.Principals[key]; !kept {
				m.identities.Unregister(key)
			}
		}
	}
	for key := range plan.next.Principals {
		p, _ := plan.next.Config.Principal(key)
		m.identities.Register(key, p, true)
	}
	for _, r := range m.records {
		if r.State != authz.StatePending || r.Changes == nil {
			continue
		}
		f := summarize(r.Record).Facts
		if _, raw, err := m.proposal(plan.next, plan.source, f.Principal, f.Connection, r.Requirements[0].Message, r.Changes); err == nil {
			r.Facts = raw
		} else {
			m.outdateRecord(r)
		}
	}
	m.gate.Recheck()
	return nil
}

func (m *Monitor) Close() {
	m.writes.Lock()
	defer m.writes.Unlock()
	m.table.Close()
}

const (
	caName     = "perimeter dev CA"
	caLifetime = 10 * 365 * 24 * time.Hour
)

// connectionTLS mints connection leaves from the stored CA, creating it if keys have none.
func connectionTLS(keys *store.Keys) (*tls.Config, error) {
	if keys.CACert == "" {
		created, err := netx.NewAuthority(caName, caLifetime)
		if err != nil {
			return nil, err
		}
		keys.CACert, keys.CAKey = created.PEM()
	}
	authority, err := netx.LoadAuthority(keys.CACert, keys.CAKey)
	if err != nil {
		return nil, err
	}
	config := authority.TLS()
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

// hostSigner is the stored SSH host key, created if keys have none.
func hostSigner(keys *store.Keys) (ssh.Signer, error) {
	if keys.HostKey == "" {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		block, err := ssh.MarshalPrivateKey(private, "")
		if err != nil {
			return nil, err
		}
		keys.HostKey = string(pem.EncodeToMemory(block))
	}
	return ssh.ParsePrivateKey([]byte(keys.HostKey))
}

var errLocked = httpError{errors.New("the Perimeter is locked"), http.StatusLocked}
