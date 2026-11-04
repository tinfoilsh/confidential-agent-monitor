package monitor

import (
	"cmp"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/coder/websocket"
	"github.com/klauspost/compress/gzhttp"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/internal/config"
	"github.com/tinfoilsh/monitor/internal/store"
	"github.com/tinfoilsh/monitor/internal/tinfoil/ownerauth"
	"github.com/tinfoilsh/monitor/internal/tinfoil/sandbox"
	"github.com/tinfoilsh/monitor/presets"
	"golang.org/x/crypto/ssh"
)

const (
	maxDocumentBytes = 16 << 20
	maxAgentBytes    = 96 << 10
	sandboxRelayPath = "/sandboxes/relay"
)

type unlockInput struct {
	Generation uint64 `json:"generation"`
	StorageKey []byte `json:"storage_key,omitempty"`
	DeviceKey  string `json:"device_key,omitempty"`
}

type sourceInput struct {
	Source string `json:"source"`
}

type editsInput struct {
	Generation *uint64         `json:"generation,omitempty"`
	Changes    []config.Change `json:"changes"`
}

// HTTPHandler serves the owner API on the local listener; nil devFiles uses embedded assets.
func (m *monitor) HTTPHandler(devFiles http.Handler) http.Handler {
	mux := http.NewServeMux()
	if m.ownerPublicKey != nil {
		mux.Handle("GET /healthz", m.ownerAPI)
		// Base64 inflates the call by a third.
		mux.Handle("GET /owner/ws", &ownerauth.Handler{Key: m.ownerPublicKey, SessionKey: m.sessionKey, MaxBytes: 2 * maxDocumentBytes, API: m.ownerAPI, Generation: m.generation,
			Relay: func(ctx context.Context, instance string) (*websocket.Conn, error) {
				return sandbox.DialOwner(ctx, m.relays, instance)
			}})
		return mux
	}
	m.registerOwnerRoutes(mux)
	m.registerOwnerApp(mux, "bearer", devFiles)
	return mux
}

// newOwnerAPI is shared by authenticated SSH and Noise session transports.
func (m *monitor) newOwnerAPI() http.Handler {
	mux := http.NewServeMux()
	m.registerOwnerRoutes(mux)
	m.registerOwnerApp(mux, "ssh", nil)
	return mux
}

func (m *monitor) registerOwnerRoutes(mux *http.ServeMux) {
	mux.Handle("GET /healthz", JSONHandler(0, func(r *http.Request, _ struct{}) (any, error) {
		health := struct {
			Locked bool   `json:"locked"`
			State  string `json:"state,omitempty"`
		}{Locked: m.settings.Load() == nil}
		// Only owners learn whether state exists; the probe reads storage.
		if _, owner := ownerauth.FromContext(r.Context()); owner {
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
	mux.Handle("POST /unlock", JSONHandler(maxDocumentBytes, func(r *http.Request, req unlockInput) (any, error) {
		key := req.StorageKey
		if m.ownerPublicKey != nil {
			session, ok := ownerauth.FromContext(r.Context())
			if !ok {
				return nil, store.ErrOwner
			}
			req.Generation = max(req.Generation, session.Minimum)
		} else {
			var err error
			key, err = bearerKey(r)
			if err != nil {
				return nil, err
			}
		}
		defer clear(key)
		initialized, err := m.unlock(r.Context(), key, req.Generation)
		if err == nil && req.DeviceKey != "" {
			err = m.restoreDevice(r.Context(), req.DeviceKey)
		}
		view, err := m.viewAfter(err)
		if v, ok := view.(ownerView); ok {
			v.Initialized = initialized
			view = v
		}
		return view, err
	}))
	mux.Handle("GET /{$}", ownerTx(m, func(_ *http.Request, _ struct{}) (any, error) { return m.view() }))
	mux.Handle("POST /enroll", m.ownerOnly(JSONHandler(maxDocumentBytes, func(r *http.Request, input map[string]identityEnrollment) (any, error) {
		return m.viewAfter(m.enroll(r.Context(), input))
	})))
	mux.Handle("POST "+sandboxRelayPath, m.ownerOnly(JSONHandler(sandbox.MaxRelayBytes, func(r *http.Request, in sandbox.RelayInput) (any, error) {
		return sandbox.Relay(r.Context(), m.relays, in)
	})))
	m.registerDevelopmentOwnerRoutes(mux)
	mux.Handle("POST /labels/{identity}", ownerTx(m, func(r *http.Request, l facts.Label) (any, error) {
		var fingerprint string
		for key, name := range m.settings.Load().Principals {
			if name == r.PathValue("identity") {
				fingerprint = key
			}
		}
		if fingerprint == "" {
			return nil, fmt.Errorf("no identity %s", r.PathValue("identity"))
		}
		if !l.Valid() {
			return nil, fmt.Errorf("a label needs trust in %v and audience in %v", facts.Trusts, facts.Audiences)
		}
		old := m.currentLabel(fingerprint)
		l.Because = map[string]string{}
		if l.Trust != cleanLabel.Trust {
			l.Because["trust"] = cmp.Or(old.Because["trust"], "the owner")
		}
		if l.Audience != cleanLabel.Audience {
			l.Because["audience"] = cmp.Or(old.Because["audience"], "the owner")
		}
		if err := m.relabel(r.Context(), fingerprint, l, nil); err != nil {
			return nil, err
		}
		return m.view()
	}))
	mux.Handle("POST /accounts/{account}/sign-in", m.ownerOnly(JSONHandler(maxDocumentBytes, m.startSignIn)))
	mux.Handle("POST /sign-in/{state}", m.ownerOnly(JSONHandler(maxDocumentBytes, m.finishSignIn)))
	mux.Handle("/connections/{name}/{control...}", m.ownerOnly(m.connectionControl))
	mux.Handle("GET /requests", ownerTx(m, func(*http.Request, struct{}) (any, error) {
		newest := make([]recordSummary, 0, len(m.records))
		for _, r := range slices.Backward(m.records) {
			newest = append(newest, r.summary())
		}
		return newest, nil
	}))
	mux.Handle("GET /audit", m.ownerOnly(JSONHandler(0, func(r *http.Request, _ struct{}) (any, error) {
		return m.readAuditPage(r.Context(), r.URL.Query().Get("before"))
	})))
	mux.Handle("GET /audit/{segment}/{id}", m.ownerOnly(JSONHandler(0, func(r *http.Request, _ struct{}) (any, error) {
		return m.readAuditRecord(r.Context(), r.PathValue("segment"), r.PathValue("id"))
	})))
	mux.Handle("GET /requests/{id}", ownerTx(m, func(r *http.Request, _ struct{}) (any, error) {
		if record := m.findRecord(r.PathValue("id")); record != nil {
			return *record, nil
		}
		return nil, errRecordGone
	}))
	mux.Handle("POST /requests/{id}", m.ownerOnly(JSONHandler(maxDocumentBytes, func(r *http.Request, req answerInput) (any, error) {
		return nil, m.answerRequest(r.Context(), r.PathValue("id"), req)
	})))
	mux.Handle("GET /policy/proposals", m.ownerOnly(JSONHandler(0, func(*http.Request, struct{}) (any, error) {
		return m.policyProposals(), nil
	})))
	mux.Handle("GET /policy/proposals/{id}", m.ownerOnly(JSONHandler(0, func(r *http.Request, _ struct{}) (any, error) {
		return m.policyProposalView(r.PathValue("id"))
	})))
	mux.Handle("POST /policy/proposals", m.ownerOnly(JSONHandler(maxProposalBytes, func(r *http.Request, input proposalInput) (any, error) {
		proposals, err := m.submitPolicyProposals(r.Context(), facts.Principal{Name: "owner"}, input)
		if err != nil {
			return nil, err
		}
		views := make([]proposalView, 0, len(proposals))
		for _, proposal := range proposals {
			views = append(views, proposalViewOf(proposal, false))
		}
		return views, nil
	})))
	mux.Handle("POST /policy/proposals/{id}/approve", m.ownerOnly(JSONHandler(maxProposalBytes, func(r *http.Request, decision proposalDecision) (any, error) {
		return m.viewAfter(m.approvePolicyProposal(r.Context(), r.PathValue("id"), decision))
	})))
	mux.Handle("POST /policy/proposals/{id}/reject", m.ownerOnly(JSONHandler(maxProposalBytes, func(r *http.Request, decision proposalDecision) (any, error) {
		return nil, m.rejectPolicyProposal(r.Context(), r.PathValue("id"), decision)
	})))
	mux.Handle("GET /policy", ownerTx(m, func(r *http.Request, _ struct{}) (any, error) {
		result := map[string]any{"source": m.store.Doc.Policy}
		var err error
		if r.URL.Query().Has("effective") {
			result["effective"], err = m.settings.Load().Config.Effective()
		}
		return result, err
	}))
	mux.Handle("POST /policy/preview", m.ownerOnly(JSONHandler(maxDocumentBytes, func(r *http.Request, input sourceInput) (any, error) {
		m.writes.Lock()
		defer m.writes.Unlock()
		base, before := m.snapshot()
		return m.previewPolicy(r.Context(), base, before, input.Source)
	})))
	mux.Handle("POST /policy", m.ownerOnly(JSONHandler(maxDocumentBytes, func(r *http.Request, input sourceInput) (any, error) {
		m.writes.Lock()
		defer m.writes.Unlock()
		return m.viewAfter(m.writeSettings(r.Context(), &input.Source, nil, nil, nil, ""))
	})))
	mux.Handle("POST /policy/edits", m.ownerOnly(JSONHandler(maxDocumentBytes, func(r *http.Request, input editsInput) (any, error) {
		m.writes.Lock()
		defer m.writes.Unlock()
		err := m.writeSettings(r.Context(), nil, input.Changes, func() error {
			if input.Generation != nil && *input.Generation != m.store.Doc.Generation {
				return errPolicyConflict
			}
			return nil
		}, nil, "")
		return m.viewAfter(err)
	})))
}

func (m *monitor) registerOwnerApp(mux *http.ServeMux, mode string, devFiles http.Handler) {
	mux.Handle("GET /app/auth.json", JSONHandler(0, func(_ *http.Request, _ struct{}) (any, error) {
		return map[string]string{"mode": mode}, nil
	}))
	files := cmp.Or(devFiles, m.embeddedFiles)
	mux.HandleFunc("GET /app/", func(w http.ResponseWriter, r *http.Request) {
		// Authenticated owner transports use embedded assets; local development can reload files.
		w.Header().Set("Cache-Control", "no-store")
		if devFiles != nil {
			r.Header.Del("If-Modified-Since")
			r.Header.Del("If-None-Match")
		}
		files.ServeHTTP(w, r)
	})
}

func (m *monitor) connectionControl(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	c := m.connections[r.PathValue("name")]
	if c == nil {
		m.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	release, err := m.acquire(c, c.prepared)
	if err != nil {
		m.mu.Unlock()
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	setupCtx, name, server := c.setupCtx, c.Name, c.Server
	m.mu.Unlock()
	defer release()
	ctx, cancel := connector.Bind(r.Context(), setupCtx)
	defer cancel()
	r.Body = http.MaxBytesReader(w, r.Body, maxDocumentBytes)
	http.StripPrefix("/connections/"+name, connector.Control(server)).ServeHTTP(w, r.WithContext(ctx))
}

func (m *monitor) agentHandler(key string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /connections", agentTx(m, key, func(_ *http.Request, _ struct{}, p config.Principal) (any, error) {
		return m.listing(p), nil
	}))
	mux.HandleFunc("GET /policy", agentTx(m, key, func(*http.Request, struct{}, config.Principal) (any, error) {
		return m.agentPolicy(key)
	}))
	mux.HandleFunc("GET /catalog", agentTx(m, key, func(*http.Request, struct{}, config.Principal) (any, error) {
		settings := m.settings.Load()
		return struct {
			CatalogID string                   `json:"catalog_id"`
			Presets   map[string]presets.Entry `json:"presets"`
		}{CatalogID: settings.CatalogID, Presets: settings.Catalog}, nil
	}))
	mux.HandleFunc("POST /policy/proposals", JSONHandler(maxAgentBytes, func(r *http.Request, input proposalInput) (any, error) {
		m.mu.Lock()
		principal, known := m.settings.Load().Principal(key)
		m.mu.Unlock()
		if !known {
			return nil, errNoAgent
		}
		proposals, err := m.submitPolicyProposals(r.Context(), facts.Principal{Key: principal.Fingerprint, Name: principal.Name}, input)
		if err != nil {
			return nil, err
		}
		receipts := make([]proposalReceipt, 0, len(proposals))
		for _, proposal := range proposals {
			receipts = append(receipts, proposalReceiptOf(proposal))
		}
		return receipts, nil
	}))
	return mux
}

// ownerTx runs each owner request as one transaction; reading the body and writing the response stay outside it.
func ownerTx[T any](m *monitor, fn func(*http.Request, T) (any, error)) http.HandlerFunc {
	return m.ownerOnly(JSONHandler(maxDocumentBytes, func(r *http.Request, input T) (any, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		return fn(r, input)
	}))
}

// ownerOnly serves the owner without the monitor's lock, for calls that wait on the network.
func (m *monitor) ownerOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		unlocked := m.settings.Load() != nil
		var err error
		if m.ownerPublicKey != nil {
			if _, ok := ownerauth.FromContext(r.Context()); !ok {
				err = store.ErrOwner
			}
		} else {
			var key []byte
			key, err = bearerKey(r)
			if err == nil && unlocked && !m.store.IsOwner(key) {
				err = store.ErrOwner
			}
		}
		if err == nil && !unlocked {
			err = errLocked
		}
		if err != nil {
			responseError(w, err)
			return
		}
		next(w, r)
	}
}

// bearerKey reads the owner secret of a request without an owner public key.
func bearerKey(r *http.Request) ([]byte, error) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || len(token) > base64.StdEncoding.EncodedLen(store.MaxOwnerKeyBytes) {
		return nil, store.ErrOwner
	}
	key, err := base64.StdEncoding.Strict().DecodeString(token)
	if err != nil || len(key) < store.MinOwnerKeyBytes || len(key) > store.MaxOwnerKeyBytes {
		return nil, store.ErrOwner
	}
	return key, nil
}

func agentTx[T any](m *monitor, key string, fn func(*http.Request, T, config.Principal) (any, error)) http.HandlerFunc {
	return JSONHandler(maxAgentBytes, func(r *http.Request, input T) (any, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		p, ok := m.settings.Load().Principal(key)
		if !ok {
			return nil, errNoAgent
		}
		return fn(r, input, p)
	})
}

func JSONHandler[T any](limit int64, fn func(*http.Request, T) (any, error)) http.HandlerFunc {
	return gzhttp.GzipHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		var err error
		var req T
		r.Body = http.MaxBytesReader(w, r.Body, limit)
		if r.Method == http.MethodPost {
			var raw []byte
			raw, err = io.ReadAll(r.Body)
			if err == nil {
				err = facts.DecodeNumbers(raw, &req)
			}
		}
		if err != nil {
			responseError(w, err)
			return
		}
		value, err := fn(r, req)
		if err != nil {
			responseError(w, err)
			return
		}
		if view, ok := value.(ownerView); ok && r.URL.Query().Get("catalog") == view.CatalogID {
			view.Presets = nil
			value = view
		}
		response, err := json.Marshal(value)
		if err != nil {
			responseError(w, err)
			return
		}
		// Confirm checkpoint before responding.
		if session, ok := ownerauth.FromContext(r.Context()); ok {
			if err := session.Acknowledge(); err != nil {
				responseError(w, err)
				return
			}
		}
		// Validate only after authentication and the SSH generation acknowledgement.
		// A weak validator covers both identity and compressed representations of this JSON.
		if r.Method == http.MethodGet {
			tag := fmt.Sprintf(`W/"%x"`, sha256.Sum256(response))
			w.Header().Set("ETag", tag)
			for _, known := range strings.Split(r.Header.Get("If-None-Match"), ",") {
				known = strings.TrimSpace(known)
				if known == "*" || strings.TrimPrefix(known, "W/") == strings.TrimPrefix(tag, "W/") {
					w.WriteHeader(http.StatusNotModified)
					return
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(response)
	}))
}

func responseError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	var specific interface{ HTTPStatus() int }
	if errors.As(err, &specific) {
		status = specific.HTTPStatus()
	}
	switch {
	case errors.Is(err, errNoAgent):
		status = http.StatusForbidden
	case errors.Is(err, store.ErrOwner):
		status = http.StatusUnauthorized
	case errors.Is(err, errLocked):
		status = http.StatusLocked
	case errors.Is(err, errPolicyConflict):
		status = http.StatusConflict
	case errors.Is(err, errRecordGone):
		status = http.StatusNotFound
	}
	http.Error(w, err.Error(), status)
}

// unavailable is a dependency failure, never a client error.
type unavailable struct{ error }

func (unavailable) HTTPStatus() int { return http.StatusServiceUnavailable }

type fieldMetadata struct {
	Path        []string `json:"path"`
	Kind        string   `json:"kind"`
	Placeholder string   `json:"placeholder,omitempty"`
	Account     string   `json:"account,omitempty"`
}

// ownerView exposes credential status without credential values.
type ownerView struct {
	Generation uint64                       `json:"generation"`
	Config     map[string]any               `json:"config"`
	HostKey    string                       `json:"host_key"`
	HostID     string                       `json:"host_id"`
	CA         string                       `json:"ca"`
	Fields     map[string][]fieldMetadata   `json:"fields"`
	Status     map[string]status            `json:"status"`
	Labels     map[string]facts.Label       `json:"labels"`
	CatalogID  string                       `json:"catalog_id"`
	Presets    map[string]presets.Entry     `json:"presets,omitempty"`
	Vocabulary map[string]facts.Obligations `json:"vocabulary"`
	// Initialized is true only on the unlock that created this Monitor's state.
	Initialized bool `json:"initialized"`
}

// view snapshots owner state while the caller holds mu. It never calls a connector.
func (m *monitor) view() (any, error) {
	s := m.settings.Load()
	// The persisted CA identifies the host across restarts and SSH key rotation.
	block, _ := pem.Decode([]byte(m.store.Doc.Keys.CACert))
	if block == nil {
		return nil, errors.New("Monitor has no host certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := jwk.Import(certificate.PublicKey)
	if err != nil {
		return nil, err
	}
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	v := ownerView{Generation: m.store.Doc.Generation, HostKey: string(ssh.MarshalAuthorizedKey(s.HostKey.PublicKey())), CA: m.store.Doc.Keys.CACert,
		HostID: "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" + base64.RawURLEncoding.EncodeToString(thumbprint),
		Fields: map[string][]fieldMetadata{}, Status: map[string]status{}, Labels: map[string]facts.Label{},
		CatalogID: s.CatalogID, Presets: s.Catalog, Vocabulary: facts.Effects}
	if v.Config, err = s.Config.View(); err != nil {
		return nil, err
	}
	for _, c := range m.connections {
		v.Status[c.Name] = c.Status()
		for name, value := range c.Credentials {
			path := presets.CredentialPath{Connection: c.Key, Protocol: c.Protocol, Secret: name}.Path()
			kind, account := credential.Describe(m.store.Doc.Secrets.Get(store.SecretID{Account: c.Account, Connection: c.Key, Name: name}))
			v.Fields[c.Account] = append(v.Fields[c.Account], fieldMetadata{Path: path, Kind: kind, Placeholder: value.Placeholder, Account: account})
		}
	}
	for _, fields := range v.Fields {
		slices.SortFunc(fields, func(a, b fieldMetadata) int { return slices.Compare(a.Path, b.Path) })
	}
	for key, name := range s.Principals {
		v.Labels[name] = m.currentLabel(key)
	}
	return v, nil
}

// Discovery describes reachable connections, not the owner's configuration or credentials.
// HTTP connections add public routing and placeholder data, never credentials.
type connectionListing struct {
	Name         string            `json:"name"`
	Account      string            `json:"account"`
	Protocol     string            `json:"kind"`
	Host         string            `json:"host"`
	State        string            `json:"state"`
	Access       config.Access     `json:"access"`
	Hosts        []string          `json:"hosts"`
	Slots        any               `json:"slots"`
	Placeholders map[string]string `json:"placeholders"`
}

// listing snapshots the connections p reaches while the caller holds mu.
func (m *monitor) listing(p config.Principal) any {
	result := struct {
		Identity    string              `json:"identity"`
		CA          string              `json:"ca"`
		Connections []connectionListing `json:"connections"`
	}{p.Name, m.store.Doc.Keys.CACert, []connectionListing{}}
	for _, name := range slices.Sorted(maps.Keys(m.connections)) {
		c := m.connections[name]
		if !m.settings.Load().Reaches(p.Name, c.Account) {
			continue
		}
		l := connectionListing{Name: name, Account: c.Account, Protocol: c.Protocol, Host: name + ".monitor",
			State: c.Status().State, Access: m.settings.Load().Access(p.Name, c.Account)}
		l.Hosts, l.Slots, l.Placeholders = c.prepared.Discovery.Hosts, c.prepared.Discovery.Slots, c.prepared.Discovery.Placeholders
		result.Connections = append(result.Connections, l)
	}
	return result
}

func (m *monitor) agentPolicy(key string) (any, error) {
	st := m.settings.Load()
	p, known := st.Principal(key)
	if !known {
		return nil, errNoAgent
	}
	var visible map[string]any
	var err error
	if st.Identities[p.Name].Routes {
		// Trusted devices can inspect the expanded, credential-free configuration
		// used to prepare owner-reviewed proposals. Credential values live outside
		// Config.
		visible, err = st.Config.View()
	} else {
		// A sandbox sees only its own identity and reachable account semantics.
		visible, err = st.Config.AgentView(p)
	}
	if err != nil {
		return nil, err
	}
	source, err := config.RenderTOML(visible)
	return map[string]any{"identity": p.Name, "source": source}, err
}
