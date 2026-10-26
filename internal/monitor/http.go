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
	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/internal/config"
	"github.com/tinfoilsh/monitor/internal/store"
	"github.com/tinfoilsh/monitor/internal/tinfoil/ownerauth"
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
	Changes    []config.Change `json:"changes"`
}

// Handler serves the owner API on the local listener; a nil file handler uses embedded assets.
func (m *monitor) Handler(files http.Handler) http.Handler { return m.ownerHandler(false, files) }

// A nil file handler uses embedded assets. Owner SSH always uses embedded assets.
func (m *monitor) ownerHandler(overSSH bool, files http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", JSONHandler(0, func(_ *http.Request, _ struct{}) (any, error) {
		return struct {
			Locked bool `json:"locked"`
		}{Locked: m.live.Load() == nil}, nil
	}))
	if m.ownerPublicKey != nil && !overSSH {
		// Base64 inflates the signed request by a third.
		mux.Handle("POST /owner/rpc", &ownerauth.Handler{Key: m.ownerPublicKey, Monitor: m.bucket, MaxBytes: 2 * maxDocumentBytes, API: m.ownerAPI, Generation: m.generation})
		return mux
	}
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
		err := m.unlock(r.Context(), key, req.Generation, req.Initialize || m.ownerPublicKey == nil)
		if err == nil && req.DeviceKey != "" {
			err = m.restoreDevice(r.Context(), req.DeviceKey)
		}
		return m.ownerResult(err)
	}))
	mux.Handle("GET /{$}", ownerLocked(m, func(_ *http.Request, _ struct{}) (any, error) { return m.view(nil) }))
	mux.Handle("POST /enroll", m.ownerOnly(JSONHandler(maxDocumentBytes, func(r *http.Request, input map[string]identityEnrollment) (any, error) {
		return m.ownerResult(m.enroll(r.Context(), input))
	})))
	if m.ownerRoutes != nil {
		integrations := http.NewServeMux()
		m.ownerRoutes(integrations)
		mux.Handle("/", m.ownerOnly(integrations.ServeHTTP))
	}
	mux.Handle("GET /presets/{name}", ownerLocked(m, func(r *http.Request, _ struct{}) (any, error) {
		return m.live.Load().Config.Preset(r.PathValue("name"))
	}))
	mux.Handle("POST /labels/{identity}", ownerLocked(m, func(r *http.Request, l facts.Label) (any, error) {
		var fingerprint string
		for key, name := range m.live.Load().Principals {
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
		return m.view(m.observe(r.Context(), fingerprint, l, nil))
	}))
	mux.Handle("POST /accounts/{account}/sign-in", m.ownerOnly(JSONHandler(maxDocumentBytes, m.startSignIn)))
	mux.Handle("POST /sign-in/{state}", m.ownerOnly(JSONHandler(maxDocumentBytes, m.finishSignIn)))
	mux.Handle("/connections/{name}/{control...}", m.ownerOnly(m.connectionControl))
	mux.Handle("GET /requests", ownerLocked(m, func(*http.Request, struct{}) (any, error) {
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
	mux.Handle("GET /requests/{id}", ownerLocked(m, func(r *http.Request, _ struct{}) (any, error) {
		if record := m.findRecord(r.PathValue("id")); record != nil {
			return *record, nil
		}
		return nil, errRecordGone
	}))
	mux.Handle("POST /requests/{id}", m.ownerOnly(JSONHandler(maxDocumentBytes, func(r *http.Request, req approvalInput) (any, error) {
		return nil, m.answerRequest(r.Context(), "owner", r.PathValue("id"), req)
	})))
	mux.Handle("GET /policy", ownerLocked(m, func(r *http.Request, _ struct{}) (any, error) {
		result := map[string]any{"source": m.store.Doc.Policy}
		var err error
		if r.URL.Query().Has("effective") {
			result["effective"], err = m.live.Load().Config.Effective()
		}
		return result, err
	}))
	mux.Handle("POST /policy/preview", m.ownerOnly(JSONHandler(maxDocumentBytes, func(r *http.Request, input sourceInput) (any, error) {
		return m.previewPolicy(r.Context(), input.Source)
	})))
	mux.Handle("POST /policy", m.ownerOnly(JSONHandler(maxDocumentBytes, func(r *http.Request, input sourceInput) (any, error) {
		return m.ownerResult(m.setPolicy(r.Context(), input.Source))
	})))
	mux.Handle("POST /policy/edits", m.ownerOnly(JSONHandler(maxDocumentBytes, func(r *http.Request, input editsInput) (any, error) {
		m.writes.Lock()
		defer m.writes.Unlock()
		err := m.writePolicy(r.Context(), nil, input.Changes, func() error {
			if input.Generation != nil && *input.Generation != m.store.Doc.Generation {
				return errPolicyConflict
			}
			return nil
		}, nil)
		return m.ownerResult(err)
	})))
	mux.Handle("GET /app/auth.json", JSONHandler(0, func(_ *http.Request, _ struct{}) (any, error) {
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
	m.mu.Lock()
	c := m.connections[r.PathValue("name")]
	if c == nil {
		m.mu.Unlock()
		http.NotFound(w, r)
		return
	}
	if err := m.acquire(c, c.setup); err != nil {
		m.mu.Unlock()
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	authority, name, server := c.ctx, c.Name, c.Server
	m.mu.Unlock()
	defer c.active.Done()
	ctx, cancel := connector.Bind(r.Context(), authority)
	defer cancel()
	r.Body = http.MaxBytesReader(w, r.Body, maxDocumentBytes)
	http.StripPrefix("/connections/"+name, connector.Control(server)).ServeHTTP(w, r.WithContext(ctx))
}

func (m *monitor) agentHandler(key string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /connections", agentLocked(m, key, func(_ *http.Request, _ struct{}, p config.Principal) (any, error) {
		return m.listing(p), nil
	}))
	mux.HandleFunc("GET /policy", agentLocked(m, key, func(*http.Request, struct{}, config.Principal) (any, error) {
		return m.agentPolicy(key, nil)
	}))
	mux.HandleFunc("POST /policy/proposals", JSONHandler(maxAgentBytes, func(r *http.Request, input proposalInput) (any, error) {
		m.mu.Lock()
		p, known := m.live.Load().Principal(key)
		m.mu.Unlock()
		if !known {
			return nil, errNoAgent
		}
		err := m.proposePolicy(r.Context(), p, input)
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.agentPolicy(key, err)
	}))
	return mux
}

// ownerLocked runs each owner request as one transaction; reading the body and writing the response stay outside it.
func ownerLocked[T any](m *monitor, fn func(*http.Request, T) (any, error)) http.HandlerFunc {
	return m.ownerOnly(JSONHandler(maxDocumentBytes, func(r *http.Request, input T) (any, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		return fn(r, input)
	}))
}

// ownerOnly serves the owner without the monitor's lock, for calls that wait on the network.
func (m *monitor) ownerOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		unlocked := m.live.Load() != nil
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

func agentLocked[T any](m *monitor, key string, fn func(*http.Request, T, config.Principal) (any, error)) http.HandlerFunc {
	return JSONHandler(maxAgentBytes, func(r *http.Request, input T) (any, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		p, ok := m.live.Load().Principal(key)
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
	case errors.Is(err, store.ErrMissingState):
		status = http.StatusPreconditionRequired
	case errors.Is(err, errPolicyConflict):
		status = http.StatusConflict
	case errors.Is(err, errRecordGone):
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
		Fields: map[string][]fieldMetadata{}, Status: map[string]status{}, Labels: map[string]facts.Label{},
		CatalogID: s.CatalogID, Presets: s.Catalog, Vocabulary: facts.Effects}
	if v.Config, err = s.Config.View(); err != nil {
		return nil, err
	}
	for _, c := range m.connections {
		v.Status[c.Name] = c.Status()
		for name, value := range c.Secrets {
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
	Kind         string            `json:"kind"`
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
		if !m.live.Load().Reaches(p.Name, c.Account) {
			continue
		}
		l := connectionListing{Name: name, Account: c.Account, Kind: c.Protocol, Host: name + ".monitor",
			State: c.Status().State, Access: m.live.Load().Access(p.Name, c.Account)}
		l.Hosts, l.Slots, l.Placeholders = c.setup.Discovery.Hosts, c.setup.Discovery.Slots, c.setup.Discovery.Placeholders
		result.Connections = append(result.Connections, l)
	}
	return result
}

func (m *monitor) agentPolicy(key string, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	st := m.live.Load()
	p, known := st.Principal(key)
	if !known {
		return nil, errNoAgent
	}
	visible, err := st.Config.AgentView(p)
	if err != nil {
		return nil, err
	}
	source, err := config.RenderTOML(visible)
	return map[string]any{"identity": p.Name, "source": source}, err
}
