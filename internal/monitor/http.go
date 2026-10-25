package monitor

import (
	"cmp"
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

	"github.com/klauspost/compress/gzhttp"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/connector/web"
	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/internal/policy"
	"github.com/tinfoilsh/monitor/internal/store"
	"github.com/tinfoilsh/monitor/internal/supervisor"
	"github.com/tinfoilsh/monitor/internal/tinfoil/ownerauth"
	"github.com/tinfoilsh/monitor/internal/tinfoil/sandbox"
	"github.com/tinfoilsh/monitor/presets"
	"golang.org/x/crypto/ssh"
)

const (
	maxDocumentBytes = 16 << 20
	maxAgentBytes    = 96 << 10
)

type unlockInput struct {
	Initialize bool   `json:"initialize,omitempty"`
	Generation uint64 `json:"generation"`
	StorageKey []byte `json:"storage_key,omitempty"`
	DeviceKey  string `json:"device_key,omitempty"`
}

type sourceInput struct {
	Source string `json:"source"`
}

type editsInput struct {
	Generation *uint64         `json:"generation,omitempty"`
	Changes    []policy.Change `json:"changes"`
}

// Handler serves the owner API on the local listener; a nil file handler uses embedded assets.
func (m *monitor) Handler(files http.Handler) http.Handler { return m.ownerHandler(false, files) }

// A nil file handler uses embedded assets. Owner SSH always uses embedded assets.
func (m *monitor) ownerHandler(overSSH bool, files http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", jsonHandler(0, func(_ *http.Request, _ struct{}) (any, error) {
		return struct {
			Locked bool `json:"locked"`
		}{Locked: m.live.Load() == nil}, nil
	}))
	if m.ownerPublicKey != nil && !overSSH {
		// Base64 inflates the signed request by a third.
		mux.Handle("POST /owner/rpc", &ownerauth.Handler{Key: m.ownerPublicKey, Monitor: m.bucket, MaxBytes: 2 * maxDocumentBytes, API: m.ownerAPI, Generation: m.generation})
		return mux
	}
	mux.Handle("POST /unlock", jsonHandler(maxDocumentBytes, func(r *http.Request, req unlockInput) (any, error) {
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
		err := m.unlock(r.Context(), key, req.Generation, req.Initialize || m.ownerPublicKey == nil)
		m.mu.Lock()
		defer m.mu.Unlock()
		if err == nil && req.DeviceKey != "" {
			err = m.restoreDevice(r.Context(), req.DeviceKey)
		}
		return m.view(err)
	}))
	mux.Handle("GET /{$}", ownerLocked(m, func(_ *http.Request, _ struct{}) (any, error) { return m.view(nil) }))
	mux.Handle("POST /enroll", ownerLocked(m, func(r *http.Request, input map[string]identityEnrollment) (any, error) {
		changes, err := m.enrollmentChanges(input)
		if err != nil {
			return nil, err
		}
		return m.view(m.editPolicy(r.Context(), changes))
	}))
	mux.Handle("POST /sandboxes/{name}/enroll", m.sandboxHandler(jsonHandler(sandbox.MaxRequestBytes, m.enrollSandbox)))
	mux.Handle("POST /sandboxes/{name}/shell", m.sandboxHandler(jsonHandler(sandbox.MaxRequestBytes, m.shellSandbox)))
	mux.Handle("GET /presets/{name}", ownerLocked(m, func(r *http.Request, _ struct{}) (any, error) {
		preset := m.live.Load().Config.Resolved[r.PathValue("name")]
		if preset == nil {
			return nil, errors.New("unknown preset")
		}
		return preset, nil
	}))
	mux.Handle("POST /labels/{identity}", ownerLocked(m, func(r *http.Request, l facts.Label) (any, error) {
		var fingerprint string
		for key, p := range m.live.Load().Principals {
			if p.Name == r.PathValue("identity") {
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
		return m.view(m.observe(r.Context(), fingerprint, l, nil))
	}))
	mux.Handle("POST /accounts/{account}/sign-in", m.ownerOnly(jsonHandler(maxDocumentBytes, m.startSignIn)))
	mux.Handle("POST /sign-in/{state}", m.ownerOnly(jsonHandler(maxDocumentBytes, m.finishSignIn)))
	mux.Handle("/connections/{name}/{control...}", m.ownerOnly(m.connectionControl))
	mux.Handle("GET /requests", ownerLocked(m, func(*http.Request, struct{}) (any, error) {
		newest := make([]recordSummary, 0, len(m.records))
		for _, r := range slices.Backward(m.records) {
			newest = append(newest, r.summary())
		}
		return newest, nil
	}))
	mux.Handle("GET /audit", m.ownerOnly(jsonHandler(0, func(r *http.Request, _ struct{}) (any, error) {
		return m.readAuditPage(r.Context(), r.URL.Query().Get("before"))
	})))
	mux.Handle("GET /audit/{segment}/{id}", m.ownerOnly(jsonHandler(0, func(r *http.Request, _ struct{}) (any, error) {
		return m.readAuditRecord(r.Context(), r.PathValue("segment"), r.PathValue("id"))
	})))
	mux.Handle("GET /requests/{id}", ownerLocked(m, func(r *http.Request, _ struct{}) (any, error) {
		if record := m.findRecord(r.PathValue("id")); record != nil {
			return *record, nil
		}
		return nil, errRecordGone
	}))
	mux.Handle("POST /requests/{id}", ownerLocked(m, func(r *http.Request, req approvalInput) (any, error) {
		return nil, m.answerRequest(r.Context(), "owner", r.PathValue("id"), req)
	}))
	mux.Handle("GET /policy", ownerLocked(m, func(r *http.Request, _ struct{}) (any, error) {
		result := map[string]any{"source": m.store.Doc.Policy}
		var err error
		if r.URL.Query().Has("effective") {
			result["effective"], err = m.live.Load().Config.Effective()
		}
		return result, err
	}))
	mux.Handle("POST /policy/preview", ownerLocked(m, func(r *http.Request, input sourceInput) (any, error) {
		next, st, err := m.candidate(r.Context(), input.Source, nil)
		if err != nil {
			return nil, err
		}
		return m.policyPreview(next, st)
	}))
	mux.Handle("POST /policy", ownerLocked(m, func(r *http.Request, input sourceInput) (any, error) {
		next, st, err := m.candidate(r.Context(), input.Source, nil)
		if err == nil {
			err = m.activate(r.Context(), next, st)
		}
		return m.view(err)
	}))
	mux.Handle("POST /policy/edits", ownerLocked(m, func(r *http.Request, input editsInput) (any, error) {
		if input.Generation != nil && *input.Generation != m.store.Doc.Generation {
			return nil, errPolicyConflict
		}
		return m.view(m.editPolicy(r.Context(), input.Changes))
	}))
	mux.Handle("GET /app/auth.json", jsonHandler(0, func(_ *http.Request, _ struct{}) (any, error) {
		mode := "bearer"
		if overSSH {
			mode = "ssh"
		}
		return map[string]string{"mode": mode}, nil
	}))
	localFiles := files != nil && !overSSH
	if !localFiles {
		files = m.embeddedFiles
	}
	mux.HandleFunc("GET /app/", func(w http.ResponseWriter, r *http.Request) {
		// Owner SSH always serves the embedded assets. Local development can reload files.
		w.Header().Set("Cache-Control", "no-store")
		if localFiles {
			r.Header.Del("If-Modified-Since")
			r.Header.Del("If-None-Match")
		}
		files.ServeHTTP(w, r)
	})
	return mux
}

func (m *monitor) connectionControl(w http.ResponseWriter, r *http.Request) {
	c := m.live.Load().connections[r.PathValue("name")]
	if c == nil {
		http.NotFound(w, r)
		return
	}
	if status := c.Status(); status.State != "ready" {
		http.Error(w, "the connector is "+status.State, http.StatusConflict)
		return
	}
	ctx, cancel := connector.Bind(r.Context(), c.Context())
	defer cancel()
	r.Body = http.MaxBytesReader(w, r.Body, maxDocumentBytes)
	if err := c.Dispatch(ctx, func(service connector.Server, _ *connector.Env) {
		http.StripPrefix("/connections/"+c.Name, connector.Control(service)).ServeHTTP(w, r.WithContext(ctx))
	}); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
}

var errSandboxSSHDisabled = errors.New("browser terminals and sandbox setup are disabled; enable them in Monitor Settings")

// sandboxHandler gates the entire SSH path, including request decoding and setup.
func (m *monitor) sandboxHandler(next http.HandlerFunc) http.HandlerFunc {
	return m.ownerOnly(func(w http.ResponseWriter, r *http.Request) {
		if !m.live.Load().Config.AllowSandboxSSH {
			responseError(w, errSandboxSSHDisabled)
			return
		}
		next(w, r)
	})
}

func (m *monitor) enrollSandbox(r *http.Request, in sandbox.EnrollInput) (any, error) {
	if err := m.sandboxes.Enroll(r.Context(), r.PathValue("name"), in); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.view(nil)
}

func (m *monitor) shellSandbox(r *http.Request, in sandbox.ShellInput) (any, error) {
	session, _ := ownerauth.FromContext(r.Context())
	return m.sandboxes.Shell(r.Context(), session.ID, r.PathValue("name"), in)
}

func (m *monitor) agentHandler(key string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /connections", agentLocked(m, key, func(_ *http.Request, _ struct{}, p policy.Principal) (any, error) {
		return m.listing(p), nil
	}))
	mux.HandleFunc("GET /policy", agentLocked(m, key, func(*http.Request, struct{}, policy.Principal) (any, error) {
		return m.agentPolicy(key, nil)
	}))
	mux.HandleFunc("POST /policy/proposals", agentLocked(m, key, func(r *http.Request, input proposalInput, p policy.Principal) (any, error) {
		return m.agentPolicy(key, m.proposePolicy(r.Context(), p, input))
	}))
	return mux
}

// ownerLocked runs each owner request as one transaction; reading the body and writing the response stay outside it.
func ownerLocked[T any](m *monitor, fn func(*http.Request, T) (any, error)) http.HandlerFunc {
	return m.ownerOnly(jsonHandler(maxDocumentBytes, func(r *http.Request, input T) (any, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		return fn(r, input)
	}))
}

// ownerOnly serves the owner without the monitor's lock, for calls that wait on the network.
func (m *monitor) ownerOnly(next http.HandlerFunc) http.HandlerFunc {
	if m.ownerPublicKey != nil {
		return func(w http.ResponseWriter, r *http.Request) {
			if _, ok := ownerauth.FromContext(r.Context()); !ok {
				responseError(w, store.ErrOwner)
				return
			}
			if m.live.Load() == nil {
				responseError(w, errLocked)
				return
			}
			next(w, r)
		}
	}

	return func(w http.ResponseWriter, r *http.Request) {
		key, err := bearerKey(r)
		// owner is set before live is published and never changes after.
		if err == nil && m.live.Load() == nil {
			err = errLocked
		}
		if err == nil && !m.store.IsOwner(key) {
			err = store.ErrOwner
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

func agentLocked[T any](m *monitor, key string, fn func(*http.Request, T, policy.Principal) (any, error)) http.HandlerFunc {
	return jsonHandler(maxAgentBytes, func(r *http.Request, input T) (any, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		p, ok := m.live.Load().Principals[key]
		if !ok {
			return nil, errNoAgent
		}
		return fn(r, input, p)
	})
}

func jsonHandler[T any](limit int64, fn func(*http.Request, T) (any, error)) http.HandlerFunc {
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
	switch {
	case errors.Is(err, errNoAgent), errors.Is(err, errSandboxSSHDisabled):
		status = http.StatusForbidden
	case errors.Is(err, store.ErrOwner):
		status = http.StatusUnauthorized
	case errors.Is(err, errLocked):
		status = http.StatusLocked
	case errors.Is(err, store.ErrMissingState):
		status = http.StatusPreconditionRequired
	case errors.Is(err, errPolicyConflict):
		status = http.StatusConflict
	case errors.Is(err, sandbox.ErrRouteUnavailable):
		status = http.StatusServiceUnavailable
	case errors.Is(err, errRecordGone), errors.Is(err, sandbox.ErrShellGone):
		status = http.StatusNotFound
	}
	http.Error(w, err.Error(), status)
}

type fieldMetadata struct {
	Path        []string `json:"path"`
	Kind        string   `json:"kind"`
	Placeholder string   `json:"placeholder,omitempty"`
	Account     string   `json:"account,omitempty"`
}

// ownerView exposes credential status without credential values.
type ownerView struct {
	Generation uint64                         `json:"generation"`
	Config     json.RawMessage                `json:"config"`
	HostKey    string                         `json:"host_key"`
	HostID     string                         `json:"host_id"`
	CA         string                         `json:"ca"`
	Fields     map[string][]fieldMetadata     `json:"fields"`
	Status     map[string]supervisor.Status   `json:"status"`
	Labels     map[string]facts.Label         `json:"labels"`
	CatalogID  string                         `json:"catalog_id"`
	Presets    map[string]policy.CatalogEntry `json:"presets,omitempty"`
	Vocabulary map[string]facts.Obligations   `json:"vocabulary"`
}

// view snapshots owner state while the caller holds mu. It never calls a connector.
func (m *monitor) view(err error) (any, error) {
	if err != nil {
		return nil, err
	}
	s := m.live.Load()
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
		Fields: map[string][]fieldMetadata{}, Status: map[string]supervisor.Status{}, Labels: map[string]facts.Label{},
		CatalogID: s.CatalogID, Presets: s.Catalog, Vocabulary: facts.Effects}
	if v.Config, err = json.Marshal(s.Config); err != nil {
		return nil, err
	}
	for _, c := range s.connections {
		v.Status[c.Name] = c.Status()
		for name, value := range c.Secrets {
			path := presets.CredentialPath{Connection: c.Key, Protocol: c.Protocol, Secret: name}.Path()
			kind, account := credential.Describe(m.store.Doc.Secrets[store.SecretID{Account: c.Account, Connection: c.Key, Name: name}])
			v.Fields[c.Account] = append(v.Fields[c.Account], fieldMetadata{Path: path, Kind: kind, Placeholder: value.Placeholder, Account: account})
		}
	}
	for _, fields := range v.Fields {
		slices.SortFunc(fields, func(a, b fieldMetadata) int { return slices.Compare(a.Path, b.Path) })
	}
	for _, p := range s.Principals {
		v.Labels[p.Name] = m.currentLabel(p.Key)
	}
	return v, nil
}

// Discovery describes reachable connections, not the owner's configuration or credentials.
// HTTP connections add public routing and placeholder data, never credentials.
type connectionListing struct {
	Name         string            `json:"name"`
	Account      string            `json:"account"`
	Kind         string            `json:"kind"`
	Host         string            `json:"host"`
	State        string            `json:"state"`
	Access       policy.Access     `json:"access"`
	Hosts        []string          `json:"hosts"`
	Slots        []web.Slot        `json:"slots"`
	Placeholders map[string]string `json:"placeholders"`
}

// listing snapshots the connections p reaches while the caller holds mu.
func (m *monitor) listing(p policy.Principal) any {
	st := m.live.Load()
	result := struct {
		Identity    string              `json:"identity"`
		CA          string              `json:"ca"`
		Connections []connectionListing `json:"connections"`
	}{p.Name, m.store.Doc.Keys.CACert, []connectionListing{}}
	for _, name := range slices.Sorted(maps.Keys(st.connections)) {
		c := st.connections[name]
		if !p.Reaches(c.Account) {
			continue
		}
		l := connectionListing{Name: name, Account: c.Account, Kind: c.Protocol, Host: name + ".monitor",
			State: c.Status().State, Access: p.Accounts[c.Account]}
		if provider, ok := c.Server.(web.HTTPProvider); ok {
			h := provider.HTTPConfig()
			l.Hosts, l.Slots, l.Placeholders = h.Hosts, h.Slots, map[string]string{}
			for secret := range h.Names() {
				l.Placeholders[secret] = h.Placeholder(secret)
			}
		}
		result.Connections = append(result.Connections, l)
	}
	return result
}

func (m *monitor) agentPolicy(key string, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	st := m.live.Load()
	p := st.Principals[key]
	visible, _, err := st.Config.AgentView(p)
	if err != nil {
		return nil, err
	}
	source, err := policy.RenderTOML(visible)
	return map[string]any{"identity": p.Name, "source": source}, err
}
