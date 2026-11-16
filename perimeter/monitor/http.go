package monitor

import (
	"bytes"
	"cmp"
	"context"
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/tinfoilsh/confidential-agent-monitor/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/core"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/netx"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/credential"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/internal/authz"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/internal/config"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/internal/store"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/internal/tomledit"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/policy"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/presets"
	"golang.org/x/crypto/ssh"
)

const (
	maxDocumentBytes = 16 << 20
	// Base64 inflates the call by a third.
	MaxCallBytes  = 2 * maxDocumentBytes
	maxAgentBytes = 96 << 10
	adminPrefix   = "/admin"
)

type unlockInput struct {
	Generation uint64 `json:"generation"`
	StorageKey []byte `json:"storage_key,omitempty"`
	DeviceKey  string `json:"device_key,omitempty"`
}

type sourceInput struct {
	Revision *uint64 `json:"revision,omitempty"`
	Source   string  `json:"source"`
}

type editsInput struct {
	Revision    *uint64         `json:"revision,omitempty"`
	Changes     []config.Change `json:"changes"`
	Credentials store.Secrets   `json:"credentials,omitempty"`
}

// AdminAPI serves the admin routes.
func (m *Monitor) AdminAPI() http.Handler {
	mux := http.NewServeMux()
	m.registerOwnerRoutes(mux)
	return mux
}

func (m *Monitor) registerOwnerRoutes(mux *http.ServeMux) {
	mux.Handle("GET /healthz", JSON(0, func(r *http.Request, _ struct{}) (any, error) {
		var health struct {
			State string `json:"state,omitempty"`
		}
		// Only owners learn whether state exists; the probe reads storage.
		if caller, _ := CallerFrom(r.Context()); caller.Owner {
			m.mu.Lock()
			current := m.store
			m.mu.Unlock()
			present, err := current.Exists(r.Context())
			if err != nil {
				return nil, unavailable{err}
			}
			health.State = map[bool]string{false: "absent", true: "present"}[present]
		}
		return health, nil
	}))
	mux.Handle("POST /unlock", JSON(maxDocumentBytes, func(r *http.Request, req unlockInput) (any, error) {
		caller, err := m.caller(r)
		key := req.StorageKey
		if err == nil && len(key) == 0 {
			key = caller.Key
		}
		if err != nil {
			return nil, err
		}
		req.Generation = max(req.Generation, caller.Minimum)
		defer clear(key)
		ctx := WithCaller(r.Context(), caller)
		initialized, err := m.unlock(ctx, key, req.Generation)
		if err == nil && req.DeviceKey != "" {
			err = m.restoreDevice(ctx, req.DeviceKey)
		}
		view, err := m.viewAfter(r, err)
		view.Initialized = initialized
		return view, err
	}))
	mux.Handle("GET /{$}", ownerTx(m, func(r *http.Request, _ struct{}) (any, error) { return m.view(r) }))
	mux.Handle("POST /enroll", m.ownerOnly(JSON(maxDocumentBytes, func(r *http.Request, input map[string]identityEnrollment) (any, error) {
		return m.viewAfter(r, m.enroll(r.Context(), input))
	})))
	for pattern, handler := range m.admin {
		mux.Handle(pattern, m.ownerOnly(handler.ServeHTTP))
	}
	mux.Handle("POST /labels/{identity}", ownerTx(m, func(r *http.Request, l facts.Label) (any, error) {
		// A certified name can be held by several keys, and each key has its own label.
		fingerprints := m.identities.Keys(r.PathValue("identity"))
		if fingerprints == nil {
			return nil, fmt.Errorf("no identity %s", r.PathValue("identity"))
		}
		if !m.vocabulary.ValidLabel(l) {
			return nil, fmt.Errorf("a label needs trust in %v and audience in %v", m.vocabulary.Trusts, m.vocabulary.Audiences)
		}
		var err error
		for _, fingerprint := range fingerprints {
			old := m.gate.Label(fingerprint)
			l.Because = map[string]string{}
			if l.Trust != m.vocabulary.Initial.Trust {
				l.Because["trust"] = cmp.Or(old.Because["trust"], "the owner")
			}
			if l.Audience != m.vocabulary.Initial.Audience {
				l.Because["audience"] = cmp.Or(old.Because["audience"], "the owner")
			}
			if err = m.gate.Relabel(r.Context(), fingerprint, l, nil); err != nil {
				break
			}
		}
		m.recordAdmin(r.Context(), "Set the label of "+r.PathValue("identity"), l, err)
		if err != nil {
			return nil, err
		}
		return m.view(r)
	}))
	mux.Handle("POST /connections/{name}/sign-in", m.ownerOnly(JSON(maxDocumentBytes, m.startSignIn)))
	mux.Handle("POST /sign-in/{state}", m.ownerOnly(JSON(maxDocumentBytes, m.finishSignIn)))
	mux.Handle("/connections/{name}/{control...}", m.ownerOnly(m.connectionControl))
	mux.Handle("GET /requests", ownerTx(m, func(*http.Request, struct{}) (any, error) {
		newest := make([]recordSummary, 0, len(m.records))
		for _, r := range slices.Backward(m.records) {
			newest = append(newest, summarize(r.Record))
		}
		return newest, nil
	}))
	mux.Handle("GET /audit", m.ownerOnly(JSON(0, func(r *http.Request, _ struct{}) (any, error) {
		return m.readAuditPage(r.Context(), r.URL.Query().Get("before"))
	})))
	mux.Handle("GET /audit/{segment}/{id}", m.ownerOnly(JSON(0, func(r *http.Request, _ struct{}) (any, error) {
		return m.readAuditRecord(r.Context(), r.PathValue("segment"), r.PathValue("id"))
	})))
	mux.Handle("GET /requests/{id}", ownerTx(m, func(r *http.Request, _ struct{}) (any, error) {
		if record := m.findRecord(r.PathValue("id")); record != nil {
			return *record, nil
		}
		return nil, errRecordGone
	}))
	mux.Handle("POST /requests/{id}", m.ownerOnly(JSON(maxDocumentBytes, func(r *http.Request, req struct {
		authz.Answer
		Revision uint64 `json:"revision"`
	}) (any, error) {
		return m.viewAfter(r, m.answerRequest(r.Context(), r.PathValue("id"), req.Answer, req.Revision))
	})))
	mux.Handle("GET /policy", ownerTx(m, func(r *http.Request, _ struct{}) (any, error) {
		result := map[string]any{"source": m.store.Doc.Policy, "revision": m.store.Doc.Revision}
		var err error
		if r.URL.Query().Has("effective") {
			result["effective"], err = m.settings.Load().Config.Effective()
		}
		return result, err
	}))
	mux.Handle("POST /policy/preview", m.ownerOnly(JSON(maxDocumentBytes, func(r *http.Request, input sourceInput) (any, error) {
		m.writes.Lock()
		defer m.writes.Unlock()
		base, before := m.snapshot()
		return m.previewPolicy(r.Context(), base, before, input.Source)
	})))
	mux.Handle("POST /policy", m.ownerOnly(JSON(maxDocumentBytes, func(r *http.Request, input sourceInput) (any, error) {
		m.writes.Lock()
		defer m.writes.Unlock()
		return m.viewAfter(r, m.writeSettings(r.Context(), settingsWrite{source: &input.Source, check: m.reviewed(input.Revision)}))
	})))
	mux.Handle("POST /policy/edits", m.ownerOnly(JSON(maxDocumentBytes, func(r *http.Request, input editsInput) (any, error) {
		for _, values := range input.Credentials {
			for name, raw := range values {
				if bytes.Equal(raw, []byte("null")) {
					values[name] = nil
				}
			}
		}
		m.writes.Lock()
		defer m.writes.Unlock()
		err := m.writeSettings(r.Context(), settingsWrite{changes: input.Changes, credentials: input.Credentials, check: m.reviewed(input.Revision)})
		return m.viewAfter(r, err)
	})))
}

func (m *Monitor) connectionControl(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	handler, setupCtx, release, ok := m.table.Control(name)
	if !ok {
		if _, installed := m.table.Connections()[name]; !installed {
			http.NotFound(w, r)
			return
		}
		http.Error(w, authz.ErrChanged.Error(), http.StatusConflict)
		return
	}
	defer release()
	ctx, cancel := netx.Bind(r.Context(), setupCtx)
	defer cancel()
	r.Body = http.MaxBytesReader(w, r.Body, maxDocumentBytes)
	http.StripPrefix("/connections/"+name, handler).ServeHTTP(w, r.WithContext(ctx))
}

type agentCatalogView struct {
	CatalogID  string                       `json:"catalog_id"`
	Presets    map[string]presets.Entry     `json:"presets"`
	Vocabulary map[string]facts.Obligations `json:"vocabulary"`
}

func (m *Monitor) agentHandler(key string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /connections", agentTx(m, key, func(_ *http.Request, _ struct{}, p config.Principal) (any, error) {
		return m.listing(p), nil
	}))
	mux.HandleFunc("GET /policy", agentTx(m, key, func(_ *http.Request, _ struct{}, p config.Principal) (any, error) {
		return m.agentPolicy(p)
	}))
	mux.HandleFunc("GET /catalog", agentTx(m, key, func(*http.Request, struct{}, config.Principal) (any, error) {
		settings := m.settings.Load()
		return agentCatalogView{CatalogID: settings.CatalogID, Presets: settings.Catalog, Vocabulary: m.vocabulary.Effects}, nil
	}))
	mux.HandleFunc("GET /policy/proposals/{id}", agentTx(m, key, func(r *http.Request, _ struct{}, p config.Principal) (any, error) {
		record := m.findRecord(r.PathValue("id"))
		if record == nil || record.Changes == nil || !summarize(record.Record).Facts.Principal.Same(p) {
			return nil, errRecordGone
		}
		return receipt(record), nil
	}))
	mux.HandleFunc("POST /policy/proposals", JSON(maxAgentBytes, func(r *http.Request, input proposalInput) (any, error) {
		return m.proposePolicy(r.Context(), key, input)
	}))
	mux.Handle(adminPrefix+"/", http.StripPrefix(adminPrefix, m.adminHandler(key)))
	return mux
}

func (m *Monitor) adminHandler(key string) http.Handler {
	api := m.AdminAPI()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := m.identities.Lookup(key)
		switch {
		case !ok:
			Error(w, errNoAgent)
		case p.Name == Owner:
			Error(w, refused("an identity named owner cannot make admin calls"))
		// A browser pointed at a forwarded port sends its own Host; unlock reads the storage key.
		case r.Host != agentHost || r.URL.Path == "/unlock":
			http.NotFound(w, r)
		default:
			caller := Caller{Name: p.Name, ID: key, Claims: map[string]any{"key": key, "groups": append([]string{}, p.Groups...)}}
			api.ServeHTTP(w, r.WithContext(WithCaller(r.Context(), caller)))
		}
	})
}

// ownerTx runs each owner request as one transaction; reading the body and writing the response stay outside it.
func ownerTx[T any](m *Monitor, fn func(*http.Request, T) (any, error)) http.HandlerFunc {
	return m.ownerOnly(JSON(maxDocumentBytes, func(r *http.Request, input T) (any, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		return fn(r, input)
	}))
}

// ownerOnly serves the owner without the monitor's lock, for calls that wait on the network.
func (m *Monitor) ownerOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st := m.settings.Load()
		caller, err := m.caller(r)
		if err == nil && st == nil {
			err = errLocked
		}
		ctx := WithCaller(context.WithValue(r.Context(), routeKey{}, r.Pattern), caller)
		if err == nil {
			err = m.admit(ctx, st.Engine, adminCall{})
		}
		if err != nil {
			Error(w, err)
			return
		}
		next(w, r.WithContext(ctx))
	}
}

// refused is an admin call that policy, or a policy loaded from a file, does not allow.
type refused string

func (r refused) Error() string { return string(r) }
func (refused) HTTPStatus() int { return http.StatusForbidden }

// admit asks policy whether the caller in ctx may make its call; call carries the answer and record of an answer.
func (m *Monitor) admit(ctx context.Context, engine *policy.Engine, call adminCall) error {
	c, _ := CallerFrom(ctx)
	call.Caller = policyCaller{Name: c.Name, Owner: c.Owner, Claims: c.Claims}
	call.Route, _ = ctx.Value(routeKey{}).(string)
	deny, err := policy.Eval[[]string](ctx, engine, "admin", call)
	if err == nil && len(deny) != 0 {
		err = refused(strings.Join(deny, "; "))
	}
	return err
}

type routeKey struct{}

func (m *Monitor) caller(r *http.Request) (Caller, error) {
	if c, ok := CallerFrom(r.Context()); ok {
		return c, nil
	}
	return Caller{}, store.ErrOwner
}

// IsOwner reports whether key is a well-formed storage key and, once unlocked, the owner's.
// While locked any well-formed key passes; only unlock can check a key then.
func (m *Monitor) IsOwner(key []byte) bool {
	if len(key) < store.MinOwnerKeyBytes || len(key) > store.MaxOwnerKeyBytes {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.settings.Load() == nil || m.store.IsOwner(key)
}

func agentTx[T any](m *Monitor, key string, fn func(*http.Request, T, config.Principal) (any, error)) http.HandlerFunc {
	return JSON(maxAgentBytes, func(r *http.Request, input T) (any, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		p, ok := m.identities.Lookup(key)
		if !ok {
			return nil, errNoAgent
		}
		return fn(r, input, p)
	})
}

// unavailable is a dependency failure, never a client error.
type unavailable struct{ error }

func (unavailable) HTTPStatus() int { return http.StatusServiceUnavailable }

type httpError struct {
	error
	status int
}

func (e httpError) HTTPStatus() int { return e.status }

type fieldMetadata struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Placeholder string `json:"placeholder,omitempty"`
	Account     string `json:"account,omitempty"`
}

// ownerView exposes credential status without credential values.
type ownerView struct {
	Generation uint64                       `json:"generation"`
	Revision   uint64                       `json:"revision"`
	Config     map[string]any               `json:"config"`
	HostKey    string                       `json:"host_key"`
	HostID     string                       `json:"host_id"`
	CA         string                       `json:"ca"`
	Fields     map[string][]fieldMetadata   `json:"fields"`
	Status     map[string]core.Status       `json:"status"`
	Labels     map[string]facts.Label       `json:"labels"`
	CatalogID  string                       `json:"catalog_id"`
	Presets    map[string]presets.Entry     `json:"presets,omitempty"`
	Vocabulary map[string]facts.Obligations `json:"vocabulary"`
	// Initialized is true only on the unlock that created this Monitor's state.
	Initialized bool `json:"initialized"`
}

// view snapshots owner state while the caller holds mu. It never calls a connector.
// Presets are omitted when the request names the catalog the owner already has.
func (m *Monitor) view(r *http.Request) (ownerView, error) {
	s := m.settings.Load()
	// The persisted CA identifies the host across restarts and SSH key rotation.
	block, _ := pem.Decode([]byte(m.store.Doc.Keys.CACert))
	if block == nil {
		return ownerView{}, errors.New("Perimeter has no host certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ownerView{}, err
	}
	key, err := jwk.Import(certificate.PublicKey)
	if err != nil {
		return ownerView{}, err
	}
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return ownerView{}, err
	}
	v := ownerView{Generation: m.store.Doc.Generation, Revision: m.store.Doc.Revision, HostKey: string(ssh.MarshalAuthorizedKey(s.HostKey.PublicKey())), CA: m.store.Doc.Keys.CACert,
		HostID: "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" + base64.RawURLEncoding.EncodeToString(thumbprint),
		Fields: map[string][]fieldMetadata{}, Status: map[string]core.Status{}, Labels: map[string]facts.Label{},
		CatalogID: s.CatalogID, Presets: s.Catalog, Vocabulary: m.vocabulary.Effects}
	if r.URL.Query().Get("catalog") == s.CatalogID {
		v.Presets = nil
	}
	if v.Config, err = s.Config.View(); err != nil {
		return ownerView{}, err
	}
	for _, c := range m.table.Connections() {
		v.Status[c.Name] = c.Status
		for name, value := range c.Secrets {
			kind, account := credential.Describe(m.store.Doc.Credentials.Get(store.SecretID{Connection: c.Name, Name: name}))
			v.Fields[c.Name] = append(v.Fields[c.Name], fieldMetadata{Name: name, Kind: kind, Placeholder: value.Placeholder(), Account: account})
		}
	}
	for _, fields := range v.Fields {
		slices.SortFunc(fields, func(a, b fieldMetadata) int { return strings.Compare(a.Name, b.Name) })
	}
	for key, name := range s.Principals {
		v.Labels[name] = m.gate.Label(key)
	}
	return v, nil
}

// Discovery describes reachable connections, not the owner's configuration or credentials.
// HTTP connections add public routing and placeholder data, never credentials.
type connectionListing struct {
	Name         string            `json:"name"`
	Protocol     string            `json:"kind"`
	Host         string            `json:"host"`
	State        string            `json:"state"`
	Access       config.Access     `json:"access"`
	Hosts        []string          `json:"hosts"`
	Slots        any               `json:"slots"`
	Placeholders map[string]string `json:"placeholders"`
	Credentials  map[string]string `json:"credentials,omitempty"`
}

// listing snapshots the connections p reaches while the caller holds mu.
func (m *Monitor) listing(p config.Principal) any {
	result := struct {
		Identity    string              `json:"identity"`
		CA          string              `json:"ca"`
		Connections []connectionListing `json:"connections"`
	}{p.Name, m.store.Doc.Keys.CACert, []connectionListing{}}
	connections := m.table.Connections()
	for _, name := range slices.Sorted(maps.Keys(connections)) {
		c := connections[name]
		if !m.settings.Load().Reaches(p.Name, c.Name) {
			continue
		}
		l := connectionListing{Name: name, Protocol: c.Protocol, Host: name + connector.Domain,
			State: c.State, Access: m.settings.Load().Access(p.Name, c.Name)}
		l.Hosts, l.Slots = c.Prepared.Discovery.Hosts, c.Prepared.Discovery.Slots
		if m.kinds[c.Protocol].Placeholders {
			l.Placeholders = map[string]string{}
			for name, value := range c.Secrets {
				l.Placeholders[name] = value.Placeholder()
			}
		}
		if len(c.Secrets) != 0 {
			l.Credentials = map[string]string{}
			for name := range c.Secrets {
				id := store.SecretID{Connection: c.Name, Name: name}
				l.Credentials[name], _ = credential.Describe(m.store.Doc.Credentials.Get(id))
			}
		}
		result.Connections = append(result.Connections, l)
	}
	return result
}

func (m *Monitor) agentPolicy(p config.Principal) (any, error) {
	st := m.settings.Load()
	var visible map[string]any
	var err error
	if st.Capable(p, capabilityConfig) {
		// Credential values live outside Config.
		visible, err = st.Config.View()
	} else {
		visible, err = st.Config.AgentView(p)
	}
	if err != nil {
		return nil, err
	}
	source, err := tomledit.Render(visible)
	return map[string]any{"identity": p.Name, "source": source}, err
}
