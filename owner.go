package main

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/tinfoilsh/monitor/connector/browser"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/facts"
	"golang.org/x/crypto/ssh"
)

const maxDocumentBytes = 16 << 20

//go:embed app
var app embed.FS

// Dev runs use the working tree so UI edits only need a browser refresh.
// A standalone binary still has the embedded app when no local copy exists.
func appHandler(dev bool) http.Handler {
	if dev {
		local := os.DirFS("app")
		if info, err := fs.Stat(local, "index.html"); err == nil && !info.IsDir() {
			files := http.StripPrefix("/app/", http.FileServerFS(local))
			return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Cache-Control", "no-store")
				// HTTP dates only have second precision; rapid edits can share a timestamp.
				r.Header.Del("If-Modified-Since")
				files.ServeHTTP(w, r)
			})
		}
	}
	return http.FileServerFS(app)
}

type fieldMetadata struct {
	Path []string `json:"path"`
	Kind string   `json:"kind"`
}

// ownerView exposes credential status without credential values.
type ownerView struct {
	Generation uint64                      `json:"generation"`
	Config     json.RawMessage             `json:"config"`
	HostKey    string                      `json:"host_key"`
	CA         string                      `json:"ca"`
	Fields     map[string][]fieldMetadata  `json:"fields"`
	Status     map[string]connectionStatus `json:"status"`
	Labels     map[string]facts.Label      `json:"labels"`
	Presets    map[string]catalogEntry     `json:"presets"`
}

func (m *monitor) view(err error) (any, error) {
	if err != nil {
		return nil, err
	}
	s := m.live.Load()
	v := ownerView{Generation: m.doc.Generation, HostKey: string(ssh.MarshalAuthorizedKey(s.HostKey.PublicKey())), CA: m.doc.Keys.CACert,
		Fields: map[string][]fieldMetadata{}, Status: map[string]connectionStatus{}, Labels: map[string]facts.Label{}, Presets: catalog(s.cfg.resolved)}
	v.Config, v.Fields, err = configView(m.doc, s)
	if err != nil {
		return nil, err
	}
	for _, c := range s.connections {
		v.Status[c.name] = c.status()
	}
	for _, p := range s.principals {
		v.Labels[p.Name] = m.currentLabel(p.Key)
	}
	return v, nil
}

func configView(doc sealed, st *state) (json.RawMessage, map[string][]fieldMetadata, error) {
	fields := map[string][]fieldMetadata{}
	for _, c := range st.connections {
		for name := range c.Secrets {
			path := append(c.path(), "secrets", name)
			fields[c.account] = append(fields[c.account], fieldMetadata{path[2:], credential.Describe(doc.Secrets.get(secretID{c.account, c.key, name}))})
		}
	}
	raw, err := json.Marshal(st.cfg)
	return raw, fields, err
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

func (m *monitor) handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /unlock", jsonHandler(maxDocumentBytes, func(r *http.Request, req unlockInput) (any, error) {
		key, err := m.authenticate(r, false)
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
		if r.URL.Query().Has("effective") {
			preset := m.live.Load().cfg.resolved[r.PathValue("name")]
			if preset == nil {
				return nil, errors.New("unknown preset")
			}
			source, err := facts.JSON[map[string]any](preset)
			if err != nil {
				return nil, err
			}
			return source, nil
		}
		src, err := presetFiles.ReadFile("presets/" + r.PathValue("name") + ".json")
		if err != nil && draftFiles != nil {
			src, err = fs.ReadFile(draftFiles, r.PathValue("name")+".json")
		}
		return json.RawMessage(src), err
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
		newest := slices.Clone(m.records)
		slices.Reverse(newest)
		return newest, nil
	}))
	mux.Handle("POST /requests/{id}", owned(m, func(r *http.Request, req decisionInput) (any, error) {
		return nil, m.answer(r.Context(), r.PathValue("id"), req.Decision)
	}))
	m.policyRoutes(mux)
	mux.Handle("GET /app/", appHandler(m.dev))
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

func (m *monitor) authenticate(r *http.Request, unlocked bool) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if err != nil || len(key) != ownerKeyBytes {
		return nil, errOwner
	}
	// owner is set before live is published and never changes after.
	if unlocked && m.live.Load() == nil {
		return nil, errLocked
	}
	if unlocked && subtle.ConstantTimeCompare(key, m.owner) != 1 {
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
		if _, err := m.authenticate(r, true); err != nil {
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

const (
	approvalWait = 2 * time.Minute
	maxRecords   = 1000

	statePending  = "pending"
	stateExpired  = "expired"
	stateAllowed  = "allowed"
	stateRefused  = "refused"
	stateApproved = "approved"
	stateDenied   = "denied"

	answerOnce = "once"
	answerSave = "save"
	answerDeny = "deny"
)

// A record is one decision; requests are the pending and expired ones.
type record struct {
	ID      string    `json:"id"`
	State   string    `json:"state"`
	Time    time.Time `json:"time"`
	Expires time.Time `json:"expires,omitzero"`
	*decision
	answered chan struct{}
}

func (m *monitor) addRecord(d *decision) *record {
	r := &record{ID: rand.Text(), Time: time.Now(), State: stateAllowed, decision: d}
	m.records = append(m.records, r)
	if len(m.records) > maxRecords {
		m.records = m.records[1:]
	}
	return r
}

// await holds a record for the owner's answer, releasing the lock while it waits.
func (m *monitor) await(ctx context.Context, r *record) error {
	r.State, r.Expires, r.answered = statePending, r.Time.Add(approvalWait), make(chan struct{})
	m.mu.Unlock()
	wait, cancel := context.WithDeadline(ctx, r.Expires)
	select {
	case <-r.answered:
	case <-wait.Done():
	}
	cancel()
	m.mu.Lock()
	switch r.State {
	case statePending:
		r.State = stateExpired
		return errors.New("waiting for the owner's approval in the monitor timed out")
	case stateDenied:
		return errors.New("the owner denied this request")
	}
	return nil
}

// settle marks a record refused when its request fails for a reason other than the owner's answer.
func (r *record) settle(err error) {
	if err != nil && r.State != stateDenied && r.State != stateExpired {
		r.State = stateRefused
		if len(r.Deny) == 0 {
			r.Deny = []string{err.Error()}
		}
	}
}

// Expired requests can still save a rule, but cannot resume the original call.
func (m *monitor) answer(ctx context.Context, id, choice string) error {
	if !slices.Contains([]string{answerOnce, answerSave, answerDeny}, choice) {
		return fmt.Errorf("decision must be %s, %s or %s", answerOnce, answerSave, answerDeny)
	}
	i := slices.IndexFunc(m.records, func(r *record) bool { return r.ID == id })
	if i < 0 {
		return fmt.Errorf("no request %s", id)
	}
	r := m.records[i]
	if r.State != statePending && !(r.State == stateExpired && choice == answerSave) {
		return fmt.Errorf("request %s is %s", id, r.State)
	}
	if choice == answerSave {
		if err := m.saveRule(ctx, r); err != nil {
			return err
		}
	}
	if r.State == statePending {
		r.State = stateApproved
		if choice == answerDeny {
			r.State = stateDenied
		}
		close(r.answered)
	}
	return nil
}

func (m *monitor) saveRule(ctx context.Context, r *record) error {
	f := r.Facts
	if f.Operation == nil || f.Operation.ID == "" {
		return errors.New("a request without a known operation cannot be saved")
	}
	p, exists := m.live.Load().principals[f.Principal.Key]
	if !exists || p.Name != f.Principal.Name {
		return errors.New("the requesting identity was revoked or replaced")
	}
	value, err := json.Marshal(rule{Account: f.Account, Action: f.Operation.Action, Operation: f.Operation.ID,
		Definition: r.Definition, Scope: r.Grant, Requirements: slices.Clone(r.Requirements)})
	if err != nil {
		return err
	}
	return m.editPolicy(ctx, []sourceChange{{Path: []string{"identities", p.Name, "rules", r.ID}, Value: value}})
}
