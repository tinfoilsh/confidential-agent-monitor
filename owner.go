package main

import (
	"cmp"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/pmezard/go-difflib/difflib"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/facts"
	"golang.org/x/crypto/ssh"
)

const (
	maxDocumentBytes = 16 << 20
	preflightMaxAge  = "600"
)

//go:embed app
var app embed.FS

var errPolicyConflict = errors.New("policy changed; reload it and review a new diff before applying")
var errRequestGone = errors.New("this request is no longer in the activity log")

// Activity never needs request bodies, policy parameters or saved-rule grants.
// Keep those in the existing audit record and load one through /requests/{id}.
type requestSummary struct {
	ID      string    `json:"id"`
	State   string    `json:"state"`
	Invalid bool      `json:"invalid,omitempty"`
	Time    time.Time `json:"time"`
	Expires time.Time `json:"expires,omitzero"`
	Summary bool      `json:"summary"`
	Facts   struct {
		Principal facts.Principal  `json:"principal"`
		Account   string           `json:"account"`
		Operation *facts.Operation `json:"operation"`
		Title     string           `json:"title"`
	} `json:"facts"`
}

type fieldMetadata struct {
	Path []string `json:"path"`
	Kind string   `json:"kind"`
}

// ownerView exposes credential status without credential values.
type ownerView struct {
	Generation uint64                       `json:"generation"`
	Config     json.RawMessage              `json:"config"`
	HostKey    string                       `json:"host_key"`
	CA         string                       `json:"ca"`
	Fields     map[string][]fieldMetadata   `json:"fields"`
	Status     map[string]connectionStatus  `json:"status"`
	Labels     map[string]facts.Label       `json:"labels"`
	CatalogID  string                       `json:"catalog_id"`
	Presets    map[string]catalogEntry      `json:"presets,omitempty"`
	Vocabulary map[string]facts.Obligations `json:"vocabulary"`
}

// A catalogEntry exposes a preset's setup metadata and operations.
type catalogEntry struct {
	*presetCatalog
	Title      string                       `json:"title"`
	Operations *map[string]catalogOperation `json:"operations,omitempty"`
}

type catalogOperation struct {
	Action  string   `json:"action"`
	Effects []string `json:"effects,omitempty"`
}

type ownerCatalog struct {
	state   *state
	id      string
	entries map[string]catalogEntry
}

// The catalog changes with policy, not with every poll. Only configured accounts
// need action metadata; operation definitions remain at /presets/{name}.
func (m *monitor) catalogView(s *state) (*ownerCatalog, error) {
	if m.catalog != nil && m.catalog.state == s {
		return m.catalog, nil
	}
	used := map[string]bool{}
	for _, a := range s.cfg.Accounts {
		used[a.Preset] = true
	}
	entries := map[string]catalogEntry{}
	for name, p := range s.cfg.resolved {
		metadata := *p.Catalog
		entry := catalogEntry{presetCatalog: &metadata, Title: p.Title}
		if !used[name] {
			metadata.Actions = nil
		} else if p.HTTP != nil {
			operations := map[string]catalogOperation{}
			for id, op := range p.HTTP.Operations {
				operations[id] = catalogOperation{Action: op.Action, Effects: op.Effects}
			}
			entry.Operations = &operations
		}
		entries[name] = entry
	}
	raw, err := json.Marshal(entries)
	if err != nil {
		return nil, err
	}
	m.catalog = &ownerCatalog{state: s, id: fmt.Sprintf("%x", sha256.Sum256(raw)), entries: entries}
	return m.catalog, nil
}

// view snapshots owner state while the caller holds mu. It never calls a connector.
func (m *monitor) view(err error) (any, error) {
	if err != nil {
		return nil, err
	}
	s := m.live.Load()
	catalog, err := m.catalogView(s)
	if err != nil {
		return nil, err
	}
	v := ownerView{Generation: m.doc.Generation, HostKey: string(ssh.MarshalAuthorizedKey(s.HostKey.PublicKey())), CA: m.doc.Keys.CACert,
		Fields: map[string][]fieldMetadata{}, Status: map[string]connectionStatus{}, Labels: map[string]facts.Label{},
		CatalogID: catalog.id, Presets: catalog.entries, Vocabulary: facts.Effects}
	if v.Config, err = json.Marshal(s.cfg); err != nil {
		return nil, err
	}
	for _, c := range s.connections {
		v.Status[c.name] = c.status()
		for name := range c.Secrets {
			path := []string{"connections", c.key, c.protocol, "secrets", name}
			v.Fields[c.account] = append(v.Fields[c.account], fieldMetadata{path, credential.Describe(m.doc.Secrets.get(secretID{c.account, c.key, name}))})
		}
	}
	for _, fields := range v.Fields {
		slices.SortFunc(fields, func(a, b fieldMetadata) int { return slices.Compare(a.Path, b.Path) })
	}
	for _, p := range s.principals {
		v.Labels[p.Name] = m.currentLabel(p.Key)
	}
	return v, nil
}

type unlockInput struct {
	Initialize bool   `json:"initialize,omitempty"`
	Generation uint64 `json:"generation"`
	StorageKey []byte `json:"storage_key,omitempty"`
}
type signInInput struct {
	Redirect   string          `json:"redirect"`
	Path       []string        `json:"path"`
	Credential json.RawMessage `json:"credential"`
}
type finishSignInInput struct {
	Code string `json:"code"`
}
type decisionInput struct {
	Decision string `json:"decision"`
}
type sourceInput struct {
	Source string `json:"source"`
}
type editsInput struct {
	Generation *uint64        `json:"generation,omitempty"`
	Changes    []sourceChange `json:"changes"`
}

func (m *monitor) handler() http.Handler { return m.ownerHandler(false) }

func (m *monitor) ownerHandler(overSSH bool) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", jsonHandler(0, func(_ *http.Request, _ struct{}) (any, error) {
		return struct {
			Locked bool `json:"locked"`
		}{Locked: m.live.Load() == nil}, nil
	}))
	if m.ownerPublicKey != nil && !overSSH {
		return mux
	}
	mux.Handle("POST /unlock", jsonHandler(maxDocumentBytes, func(r *http.Request, req unlockInput) (any, error) {
		key := req.StorageKey
		if m.ownerPublicKey != nil {
			owner, ok := r.Context().Value(ownerSSHContextKey{}).(ownerSSHContext)
			if !ok {
				return nil, errOwner
			}
			req.Generation = max(req.Generation, owner.minimum)
		} else {
			var err error
			key, err = ownerKey(r)
			if err != nil {
				return nil, err
			}
		}
		defer clear(key)
		err := m.unlockState(r.Context(), key, req.Generation, req.Initialize || m.ownerPublicKey == nil)
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.view(err)
	}))
	mux.Handle("GET /{$}", owned(m, func(_ *http.Request, _ struct{}) (any, error) { return m.view(nil) }))
	mux.Handle("POST /enroll", owned(m, func(r *http.Request, input map[string]struct {
		Key    string `json:"key"`
		Routes bool   `json:"routes"`
	}) (any, error) {
		var changes []sourceChange
		for name, id := range input {
			key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(id.Key))
			if err != nil {
				return nil, err
			}
			fingerprint := ssh.FingerprintSHA256(key)
			if existing, ok := m.live.Load().principals[fingerprint]; ok {
				if id.Routes && !existing.Routes {
					return nil, errors.New("device route access was revoked")
				}
				continue
			}
			if m.doc.Enrolled[fingerprint] {
				return nil, errors.New("identity was revoked; restore access explicitly in Monitor")
			}
			if _, exists := m.live.Load().cfg.Identities[name]; exists {
				return nil, errors.New("identity name belongs to another key")
			}
			changes = append(changes, sourceChange{Path: []string{"identities", name}, Value: map[string]any{"key": id.Key, "routes": id.Routes}})
		}
		return m.view(m.editPolicy(r.Context(), changes))
	}))
	mux.Handle("GET /presets/{name}", owned(m, func(r *http.Request, _ struct{}) (any, error) {
		preset := m.live.Load().cfg.resolved[r.PathValue("name")]
		if preset == nil {
			return nil, errors.New("unknown preset")
		}
		return preset, nil
	}))
	mux.Handle("POST /labels/{identity}", owned(m, func(r *http.Request, l facts.Label) (any, error) {
		var fingerprint string
		for key, p := range m.live.Load().principals {
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
	mux.Handle("POST /accounts/{account}/sign-in", m.authenticated(jsonHandler(maxDocumentBytes, m.startSignIn)))
	mux.Handle("POST /sign-in/{state}", m.authenticated(jsonHandler(maxDocumentBytes, m.finishSignIn)))
	mux.Handle("/connections/{name}/{control...}", m.authenticated(m.connectionControl))
	mux.Handle("GET /requests", owned(m, func(r *http.Request, _ struct{}) (any, error) {
		if r.URL.Query().Has("summary") {
			newest := make([]requestSummary, 0, len(m.records))
			for _, r := range slices.Backward(m.records) {
				v := requestSummary{ID: r.ID, State: r.State, Invalid: r.Invalid, Time: r.Time, Expires: r.Expires, Summary: true}
				v.Facts.Principal, v.Facts.Account, v.Facts.Operation = r.Facts.Principal, r.Facts.Account, r.Facts.Operation
				v.Facts.Title = r.Facts.Title
				// SQL and other protocol titles can contain the entire request.
				if len(v.Facts.Title) > 512 {
					v.Facts.Title = strings.ToValidUTF8(v.Facts.Title[:512], "") + "…"
				}
				newest = append(newest, v)
			}
			return newest, nil
		}
		newest := make([]record, 0, len(m.records))
		for _, r := range slices.Backward(m.records) {
			newest = append(newest, *r)
		}
		return newest, nil
	}))
	mux.Handle("GET /requests/{id}", owned(m, func(r *http.Request, _ struct{}) (any, error) {
		for _, record := range m.records {
			if record.ID == r.PathValue("id") {
				return *record, nil
			}
		}
		return nil, errRequestGone
	}))
	mux.Handle("POST /requests/{id}", owned(m, func(r *http.Request, req decisionInput) (any, error) {
		return nil, m.answer(r.Context(), r.PathValue("id"), req.Decision)
	}))
	mux.Handle("GET /policy", owned(m, func(r *http.Request, _ struct{}) (any, error) {
		result := map[string]any{"source": m.doc.Policy}
		var err error
		if r.URL.Query().Has("effective") {
			result["effective"], err = effectiveSource(m.live.Load())
		}
		return result, err
	}))
	mux.Handle("POST /policy/preview", owned(m, func(r *http.Request, input sourceInput) (any, error) {
		next, st, err := m.prepareCandidate(r.Context(), input.Source, nil)
		if err != nil {
			return nil, err
		}
		return m.policyPreview(next, st)
	}))
	mux.Handle("POST /policy", owned(m, func(r *http.Request, input sourceInput) (any, error) {
		next, st, err := m.prepareCandidate(r.Context(), input.Source, nil)
		if err == nil {
			err = m.activate(r.Context(), next, st)
		}
		return m.view(err)
	}))
	mux.Handle("POST /policy/edits", owned(m, func(r *http.Request, input editsInput) (any, error) {
		if input.Generation != nil && *input.Generation != m.doc.Generation {
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
	files := http.FileServerFS(app)
	localFiles := false
	if m.dev && !overSSH {
		if dir, err := os.Stat("app"); err == nil && dir.IsDir() {
			files = http.StripPrefix("/app/", http.FileServer(http.Dir("app")))
			localFiles = true
		}
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

func (m *monitor) startSignIn(r *http.Request, req signInInput) (any, error) {
	if len(req.Path) < 4 || req.Path[0] != "connections" {
		return nil, errors.New("invalid credential path")
	}
	c := m.live.Load().connections[connectionName(r.PathValue("account"), req.Path[1])]
	if c == nil || c.protocol != req.Path[2] {
		return nil, errors.New("connection does not exist")
	}
	path := append([]string{"accounts", c.account}, req.Path...)
	if !isCredentialPath(path) || c.Secrets[path[6]] == nil {
		return nil, errors.New("invalid credential path")
	}
	m.mu.Lock()
	previous := m.doc.Secrets.get(credentialID(path))
	m.mu.Unlock()
	record := previous
	if req.Credential != nil {
		record = req.Credential
	}
	sign, err := credential.NewSignIn(r.Context(), m.live.Load().Client(), record, req.Redirect)
	if err != nil {
		return nil, err
	}
	value := c.Secrets[path[6]]
	m.signIns.Store(sign.State, func(ctx context.Context, code string) error {
		secret, err := sign.Exchange(ctx, code)
		if err != nil {
			return err
		}
		return value.Replace(ctx, previous, secret)
	})
	return map[string]string{"url": sign.URL}, nil
}

func (m *monitor) finishSignIn(r *http.Request, req finishSignInInput) (any, error) {
	finish, ok := m.signIns.LoadAndDelete(r.PathValue("state"))
	if !ok {
		return nil, errors.New("no sign-in is waiting for this state")
	}
	err := finish.(func(context.Context, string) error)(r.Context(), req.Code)
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.view(err)
}

func (m *monitor) connectionControl(w http.ResponseWriter, r *http.Request) {
	c := m.live.Load().connections[r.PathValue("name")]
	if c == nil {
		http.NotFound(w, r)
		return
	}
	if status := c.status(); status.State != "ready" {
		http.Error(w, "the connector is "+status.State, http.StatusConflict)
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	stop := context.AfterFunc(c.ctx, cancel)
	defer stop()
	r.Body = http.MaxBytesReader(w, r.Body, maxDocumentBytes)
	if err := c.dispatch(ctx, func(service connector.Server, _ *connector.Env) {
		http.StripPrefix("/connections/"+c.name, connector.Control(service)).ServeHTTP(w, r.WithContext(ctx))
	}); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
}

// ownerOrigins parses a comma-separated list of exact browser origins, such as https://dash.tinfoil.sh.
func ownerOrigins(list string) ([]string, error) {
	var origins []string
	for _, origin := range strings.Split(list, ",") {
		if origin = strings.TrimSpace(origin); origin == "" {
			continue
		}
		u, err := url.Parse(origin)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Scheme+"://"+u.Host != origin {
			return nil, fmt.Errorf("owner origin %q must be scheme://host[:port]", origin)
		}
		origins = append(origins, origin)
	}
	return origins, nil
}

// allowOrigins lets the listed origins call the owner API from a browser, such as a dashboard
// holding the owner key in memory. Only the bearer key authenticates; credentials are never allowed.
func allowOrigins(origins []string, next http.Handler) http.Handler {
	if len(origins) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Origin")
		origin := r.Header.Get("Origin")
		if !slices.Contains(origins, origin) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Expose-Headers", "ETag")
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, If-None-Match")
			w.Header().Set("Access-Control-Max-Age", preflightMaxAge)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

var errLocked = errors.New("the monitor is locked")

func ownerKey(r *http.Request) ([]byte, error) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || len(token) > base64.StdEncoding.EncodedLen(maxOwnerKeyBytes) {
		return nil, errOwner
	}
	key, err := base64.StdEncoding.Strict().DecodeString(token)
	if err != nil || len(key) < minOwnerKeyBytes || len(key) > maxOwnerKeyBytes {
		return nil, errOwner
	}
	return key, nil
}

func responseError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	switch {
	case errors.Is(err, errNoAgent):
		status = http.StatusForbidden
	case errors.Is(err, errOwner):
		status = http.StatusUnauthorized
	case errors.Is(err, errLocked):
		status = http.StatusLocked
	case errors.Is(err, errPolicyConflict):
		status = http.StatusConflict
	case errors.Is(err, errRequestGone):
		status = http.StatusNotFound
	}
	http.Error(w, err.Error(), status)
}

// owned runs each owner request as one transaction; reading the body and writing the response stay outside it.
func owned[T any](m *monitor, fn func(*http.Request, T) (any, error)) http.HandlerFunc {
	return m.authenticated(jsonHandler(maxDocumentBytes, func(r *http.Request, input T) (any, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		return fn(r, input)
	}))
}

// authenticated serves the owner without the monitor's lock, for calls that wait on the network.
func (m *monitor) authenticated(next http.HandlerFunc) http.HandlerFunc {
	if m.ownerPublicKey != nil {
		return func(w http.ResponseWriter, r *http.Request) {
			if r.Context().Value(ownerSSHContextKey{}) == nil {
				responseError(w, errOwner)
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
		key, err := ownerKey(r)
		// owner is set before live is published and never changes after.
		if err == nil && m.live.Load() == nil {
			err = errLocked
		}
		if err == nil && subtle.ConstantTimeCompare(key, m.owner) != 1 {
			err = errOwner
		}
		if err != nil {
			responseError(w, err)
			return
		}
		next(w, r)
	}
}

func jsonHandler[T any](limit int64, fn func(*http.Request, T) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
		if owner, ok := r.Context().Value(ownerSSHContextKey{}).(ownerSSHContext); ok {
			if err := owner.acknowledge(); err != nil {
				responseError(w, err)
				return
			}
		}
		// Validate only after authentication and the SSH generation acknowledgement.
		// A weak validator covers both identity and gzip representations of this JSON.
		w.Header().Add("Vary", "Accept-Encoding")
		// The legacy full-history export can be hundreds of MB; the UI validates
		// its compact summaries instead of hashing all request bodies every poll.
		if r.Method == http.MethodGet && !(r.URL.Path == "/requests" && !r.URL.Query().Has("summary")) {
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
		if len(response) >= 1024 && acceptsGzip(r.Header.Get("Accept-Encoding")) {
			w.Header().Set("Content-Encoding", "gzip")
			compressed := gzip.NewWriter(w)
			defer compressed.Close()
			compressed.Write(response)
			return
		}
		w.Write(response)
	}
}

func acceptsGzip(accept string) bool {
	for _, coding := range strings.Split(accept, ",") {
		parts := strings.Split(coding, ";")
		if !strings.EqualFold(strings.TrimSpace(parts[0]), "gzip") {
			continue
		}
		quality := 1.0
		for _, parameter := range parts[1:] {
			if key, value, ok := strings.Cut(strings.TrimSpace(parameter), "="); ok && strings.EqualFold(key, "q") {
				var err error
				quality, err = strconv.ParseFloat(value, 64)
				if err != nil {
					return false
				}
			}
		}
		return quality > 0 && quality <= 1
	}
	return false
}

// effectiveSource renders an already compiled state; reading it cannot compile
// or change policy. Configuration contains no credential values.
func effectiveSource(st *state) (string, error) {
	v, err := facts.JSON[map[string]any](st.cfg)
	if err != nil {
		return "", err
	}
	ps := map[string]any{}
	for _, acc := range st.cfg.Accounts {
		if ps[acc.Preset], err = facts.JSON[map[string]any](st.cfg.resolved[acc.Preset]); err != nil {
			return "", err
		}
	}
	v["presets"] = ps
	return renderTOML(v)
}

func (m *monitor) policyPreview(next sealed, st *state) (*facts.Policy, error) {
	before, err := effectiveSource(m.live.Load())
	if err != nil {
		return nil, err
	}
	after, err := effectiveSource(st)
	if err != nil {
		return nil, err
	}
	diff := func(a, b string) string {
		text, _ := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
			A: difflib.SplitLines(a), B: difflib.SplitLines(b),
			FromFile: "active/policy.toml", ToFile: "proposed/policy.toml", Context: 3,
		})
		return text
	}
	return &facts.Policy{SourceDiff: diff(m.doc.Policy, next.Policy), EffectiveDiff: diff(before, after)}, nil
}
