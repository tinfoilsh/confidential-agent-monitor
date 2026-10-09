package main

import (
	"cmp"
	"context"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"

	"github.com/pmezard/go-difflib/difflib"
	"github.com/tinfoilsh/monitor/connector/browser"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/connector/web"
	"github.com/tinfoilsh/monitor/facts"
	"golang.org/x/crypto/ssh"
)

const maxDocumentBytes = 16 << 20

//go:embed app
var app embed.FS

var errPolicyConflict = errors.New("policy changed; reload it and review a new diff before applying")

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
	Presets    map[string]catalogEntry      `json:"presets"`
	Vocabulary map[string]facts.Obligations `json:"vocabulary"`
}

// A catalogEntry exposes a preset's setup metadata and operations.
type catalogEntry struct {
	*presetCatalog
	Title      string                    `json:"title"`
	Operations *map[string]web.Operation `json:"operations,omitempty"`
}

func (m *monitor) view(err error) (any, error) {
	if err != nil {
		return nil, err
	}
	s := m.live.Load()
	v := ownerView{Generation: m.doc.Generation, HostKey: string(ssh.MarshalAuthorizedKey(s.HostKey.PublicKey())), CA: m.doc.Keys.CACert,
		Fields: map[string][]fieldMetadata{}, Status: map[string]connectionStatus{}, Labels: map[string]facts.Label{}, Presets: map[string]catalogEntry{}, Vocabulary: facts.Effects}
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
	for _, p := range s.principals {
		v.Labels[p.Name] = m.currentLabel(p.Key)
	}
	for name, p := range s.cfg.resolved {
		entry := catalogEntry{presetCatalog: p.Catalog, Title: p.Title}
		if p.HTTP != nil {
			entry.Operations = &p.HTTP.Operations
		}
		v.Presets[name] = entry
	}
	return v, nil
}

type unlockInput struct {
	Generation uint64 `json:"generation"`
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
	Changes []sourceChange `json:"changes"`
}

func (m *monitor) handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /unlock", jsonHandler(maxDocumentBytes, func(r *http.Request, req unlockInput) (any, error) {
		key, err := ownerKey(r)
		if err != nil {
			return nil, err
		}
		err = m.unlock(r.Context(), key, req.Generation)
		m.mu.Lock()
		defer m.mu.Unlock()
		return m.view(err)
	}))
	mux.Handle("GET /{$}", owned(m, func(_ *http.Request, _ struct{}) (any, error) { return m.view(nil) }))
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
	mux.Handle("GET /connections/{name}/browser", m.authenticated(m.browserControl))
	mux.Handle("POST /connections/{name}/browser", m.authenticated(m.browserControl))
	mux.Handle("GET /requests", owned(m, func(_ *http.Request, _ struct{}) (any, error) {
		newest := append([]*record{}, m.records...)
		slices.Reverse(newest)
		return newest, nil
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
		return m.view(m.editPolicy(r.Context(), input.Changes))
	}))
	mux.Handle("GET /app/", http.FileServerFS(app))
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

// browserControl runs outside the monitor's lock, since a browser call can be slow.
func (m *monitor) browserControl(w http.ResponseWriter, r *http.Request) {
	s := m.live.Load()
	c := s.connections[r.PathValue("name")]
	b, ok := (*browser.Browser)(nil), false
	if c != nil {
		b, ok = c.connector.(*browser.Browser)
	}
	if !ok {
		http.Error(w, "no browser connection "+r.PathValue("name"), http.StatusNotFound)
		return
	}
	if status := c.status(); status.State != "ready" {
		http.Error(w, "the browser is "+status.State, http.StatusConflict)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxDocumentBytes)
	b.ServeOwner(w, r)
}

var errLocked = errors.New("the monitor is locked")

func ownerKey(r *http.Request) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if err != nil || len(key) != ownerKeyBytes {
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
		response, err := json.Marshal(value)
		if err != nil {
			responseError(w, err)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(response)
	}
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
