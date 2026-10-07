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
	"io/fs"
	"iter"
	"maps"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/browser"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/connector/mcp"
	"github.com/tinfoilsh/monitor/connector/web"
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

// ownerView omits values marked redact in connector field metadata.
type ownerView struct {
	Generation uint64                     `json:"generation"`
	Config     json.RawMessage            `json:"config"`
	HostKey    string                     `json:"host_key"`
	CA         string                     `json:"ca"`
	Fields     map[string][]fieldMetadata `json:"fields"`
	Status     map[string]any             `json:"status"`
	Labels     map[string]label           `json:"labels"`
	Setup      map[string]string          `json:"setup"`
	Presets    any                        `json:"presets"`
}

func (m *monitor) view(s *state, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	presets, err := catalog(s.cfg.resolved)
	if err != nil {
		return nil, err
	}
	v := ownerView{m.doc.Generation, m.doc.Config, string(ssh.MarshalAuthorizedKey(s.HostKey.PublicKey())), m.doc.Keys.CACert,
		map[string][]fieldMetadata{}, map[string]any{}, map[string]label{}, map[string]string{}, presets}
	v.Config, v.Fields = configView(m.doc.Config, s.connections)
	for _, c := range s.connections {
		v.Status[c.name] = c.status()
	}
	for _, p := range s.principals {
		v.Labels[p.Name] = m.labelLocked(p.Key)
		v.Setup[p.Name] = setup(p, s.connections)
	}
	return v, nil
}

// setup exports each secret's placeholder; a name in several connections stays a comment, since one variable cannot hold both.
func setup(p principal, connections map[string]*connection) string {
	holders := map[string][]string{}
	gateway := false
	for _, name := range slices.Sorted(maps.Keys(connections)) {
		if _, ok := connections[name].connector.(*mcp.Server); ok && p.reaches(connections[name].account) {
			gateway = true
		}
		if h, ok := connections[name].connector.(interface{ Names() iter.Seq[string] }); ok && p.reaches(connections[name].account) {
			for secret := range h.Names() {
				holders[secret] = append(holders[secret], name)
			}
		}
	}
	lines := []string{"# Discover available connections: monitor connections (uses the agent's SSH identity)"}
	for _, secret := range slices.Sorted(maps.Keys(holders)) {
		for _, name := range holders[secret] {
			if len(holders[secret]) == 1 {
				lines = append(lines, fmt.Sprintf("export %s=%s", secret, web.Placeholder(name, secret)))
			} else {
				lines = append(lines, fmt.Sprintf("# %s for %s.monitor: %s", secret, name, web.Placeholder(name, secret)))
			}
		}
	}
	if gateway {
		lines = append(lines, fmt.Sprintf("# MCP tools of every reachable server: forward %s:%d, for example ssh -N -L 127.0.0.1:8400:%s:%d monitor", gatewayHost, gatewayPort, gatewayHost, gatewayPort))
	}
	return strings.Join(lines, "\n")
}

func configView(raw json.RawMessage, connections map[string]*connection) (json.RawMessage, map[string][]fieldMetadata) {
	fields := map[string][]fieldMetadata{}
	visible := raw
	for _, c := range connections {
		for _, field := range c.connector.Fields() {
			if !field.Redact {
				continue
			}
			path := append(c.path(), field.Path...)
			value := configValue(raw, path)
			fields[c.account] = append(fields[c.account], fieldMetadata{path[2:], credential.Describe(value)})
			visible, _ = jsonpatch.MergePatch(visible, valuePatch(path, json.RawMessage("null")))
		}
	}
	return visible, fields
}

type ownerInput struct {
	Generation uint64          `json:"generation"`
	Redirect   string          `json:"redirect"`
	Path       []string        `json:"path"`
	Credential json.RawMessage `json:"credential"`
	Code       string          `json:"code"`
	Decision   string          `json:"decision"`
	key        []byte
	raw        json.RawMessage
}

func (m *monitor) handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /unlock", m.owned(false, func(r *http.Request, req ownerInput) (any, error) {
		return m.view(m.unlock(r.Context(), req.key, req.Generation))
	}))
	mux.Handle("GET /{$}", m.owned(true, func(*http.Request, ownerInput) (any, error) { return m.view(m.live.Load(), nil) }))
	mux.Handle("PATCH /{$}", m.owned(true, func(r *http.Request, req ownerInput) (any, error) {
		return m.view(m.patch(r.Context(), req.raw))
	}))
	// A shipped preset as its file has it, so an owner's copy keeps its order and environment references.
	mux.Handle("GET /presets/{name}", m.owned(true, func(r *http.Request, _ ownerInput) (any, error) {
		src, err := presetFiles.ReadFile("presets/" + r.PathValue("name") + ".json")
		if err != nil && draftFiles != nil {
			src, err = fs.ReadFile(draftFiles, r.PathValue("name")+".json")
		}
		return json.RawMessage(src), err
	}))
	// The owner may move a label to any point; an axis left tainted keeps the account it came from.
	mux.Handle("POST /labels/{identity}", m.owned(true, func(r *http.Request, req ownerInput) (any, error) {
		id, ok := m.live.Load().cfg.Identities[r.PathValue("identity")]
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(id.Key))
		if !ok || err != nil {
			return nil, fmt.Errorf("no identity %s", r.PathValue("identity"))
		}
		var l label
		if json.Unmarshal(req.raw, &l) != nil || !slices.Contains(trusts, l.Trust) || !slices.Contains(audiences, l.Audience) {
			return nil, fmt.Errorf("a label needs trust in %v and audience in %v", trusts, audiences)
		}
		fingerprint := ssh.FingerprintSHA256(key)
		old := m.labelLocked(fingerprint)
		l.Because = map[string]string{}
		if l.Trust != cleanLabel.Trust {
			l.Because["trust"] = cmp.Or(old.Because["trust"], "the owner")
		}
		if l.Audience != cleanLabel.Audience {
			l.Because["audience"] = cmp.Or(old.Because["audience"], "the owner")
		}
		m.setLabelLocked(fingerprint, l, nil)
		return m.view(m.live.Load(), m.commitLocked(r.Context(), m.doc))
	}))
	mux.Handle("POST /accounts/{account}/sign-in", m.owned(true, func(r *http.Request, req ownerInput) (any, error) {
		s := m.live.Load()
		if len(req.Path) < 4 || req.Path[0] != "connections" {
			return nil, errors.New("invalid credential path")
		}
		c := s.connections[connectionName(r.PathValue("account"), req.Path[1])]
		if c == nil || c.protocol != req.Path[2] {
			return nil, errors.New("connection does not exist")
		}
		path := append([]string{"accounts", c.account}, req.Path...)
		previous := configValue(m.doc.Config, path)
		record := previous
		if req.Credential != nil {
			record = req.Credential
		}
		sign, err := credential.NewSignIn(r.Context(), s.Client(), record, req.Redirect)
		if err != nil {
			return nil, err
		}
		if m.signIns == nil {
			m.signIns = map[string]func(context.Context, string) (*state, error){}
		}
		m.signIns[sign.State] = func(ctx context.Context, code string) (*state, error) {
			if !m.currentValue(c, path, previous) {
				return nil, errors.New("credential changed during sign-in; start again")
			}
			secret, err := sign.Exchange(ctx, code)
			if err != nil {
				return nil, err
			}
			return m.patch(ctx, valuePatch(path, secret))
		}
		return map[string]string{"url": sign.URL}, nil
	}))
	mux.Handle("POST /sign-in/{state}", m.owned(true, func(r *http.Request, req ownerInput) (any, error) {
		finish, ok := m.signIns[r.PathValue("state")]
		delete(m.signIns, r.PathValue("state"))
		if !ok {
			return nil, errors.New("no sign-in is waiting for this state")
		}
		return m.view(finish(r.Context(), req.Code))
	}))
	mux.HandleFunc("GET /connections/{name}/browser", m.browserControl)
	mux.HandleFunc("POST /connections/{name}/browser", m.browserControl)
	m.requests(mux)
	mux.Handle("GET /app/", appHandler(m.dev))
	return mux
}

// browserControl checks the owner's secret as owned does, then releases the monitor's locks, since a browser call can be slow.
func (m *monitor) browserControl(w http.ResponseWriter, r *http.Request) {
	m.mu.Lock()
	s, owner := m.live.Load(), m.owner
	m.mu.Unlock()
	if s == nil {
		http.Error(w, "the monitor is locked", http.StatusLocked)
		return
	}
	key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
	if err != nil || len(key) != ownerKeyBytes || subtle.ConstantTimeCompare(key, owner) != 1 {
		http.Error(w, errOwner.Error(), http.StatusUnauthorized)
		return
	}
	c := s.connections[r.PathValue("name")]
	b, ok := (*browser.Browser)(nil), false
	if c != nil {
		b, ok = c.connector.(*browser.Browser)
	}
	if !ok {
		http.Error(w, "no browser connection "+r.PathValue("name"), http.StatusNotFound)
		return
	}
	if status, _ := c.status().(map[string]string); status["state"] != "ready" {
		http.Error(w, "the browser is "+status["state"], http.StatusConflict)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxDocumentBytes)
	b.ServeOwner(w, r)
}

// owned uses the same lock order as agent requests. Before unlock, decrypting
// the state is what proves the secret.
func (m *monitor) owned(unlocked bool, fn func(*http.Request, ownerInput) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.flow.Lock()
		defer m.flow.Unlock()
		m.mu.Lock()
		defer m.mu.Unlock()
		if unlocked && m.live.Load() == nil {
			http.Error(w, "the monitor is locked", http.StatusLocked)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, maxDocumentBytes)
		var v any
		key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if err == nil && len(key) == ownerKeyBytes && (!unlocked || subtle.ConstantTimeCompare(key, m.owner) == 1) {
			req := ownerInput{key: key}
			if r.Method == http.MethodPost || r.Method == http.MethodPatch {
				if req.raw, err = io.ReadAll(r.Body); err == nil {
					err = json.Unmarshal(req.raw, &req)
				}
			}
			if err == nil {
				v, err = fn(r, req)
			}
		} else {
			err = errOwner
		}
		switch {
		case errors.Is(err, errOwner):
			http.Error(w, err.Error(), http.StatusUnauthorized)
		case err != nil:
			http.Error(w, err.Error(), http.StatusBadRequest)
		default:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(v)
		}
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

// Audit events include connector observations and monitor-owned messages.
type auditEvent struct {
	*connector.Event
	Message *messageEvent `json:"message,omitempty"`
}

type messageEvent struct {
	From string `json:"from"`
	To   string `json:"to"`
	ID   string `json:"id,omitempty"`
}

// A record is one decision; requests are the pending and expired ones.
type record struct {
	ID       string      `json:"id"`
	State    string      `json:"state"`
	Time     time.Time   `json:"time"`
	Expires  time.Time   `json:"expires,omitzero"`
	Identity string      `json:"identity"`
	Account  string      `json:"account"`
	Label    label       `json:"label"`
	Event    *auditEvent `json:"event,omitempty"`
	*decision
	answered chan struct{}
}

// After add, only State changes. mu protects State and the list.
type records struct {
	mu   sync.Mutex
	list []*record
}

func (rs *records) add(r *record) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.list = append(rs.list, r)
	if len(rs.list) > maxRecords {
		rs.list = rs.list[1:]
	}
}

func (rs *records) wait(ctx context.Context, r *record) string {
	ctx, cancel := context.WithDeadline(ctx, r.Expires)
	defer cancel()
	select {
	case <-r.answered:
	case <-ctx.Done():
	}
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if r.State == statePending {
		r.State = stateExpired
	}
	return r.State
}

func (rs *records) marshal() (json.RawMessage, error) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	newest := append([]*record{}, rs.list...)
	slices.Reverse(newest)
	return json.Marshal(newest)
}

// answer requires m.mu, held by the owner HTTP handler.
// Expired requests can still save a rule, but cannot resume the original call.
func (m *monitor) answer(ctx context.Context, id, choice string) error {
	m.records.mu.Lock()
	i := slices.IndexFunc(m.records.list, func(r *record) bool { return r.ID == id })
	var r *record
	state := ""
	if i >= 0 {
		r = m.records.list[i]
		state = r.State
	}
	m.records.mu.Unlock()
	switch {
	case r == nil:
		return fmt.Errorf("no request %s", id)
	case !slices.Contains([]string{answerOnce, answerSave, answerDeny}, choice):
		return fmt.Errorf("decision must be %s, %s or %s", answerOnce, answerSave, answerDeny)
	}
	switch state {
	case statePending:
	case stateExpired:
		if choice != answerSave {
			return fmt.Errorf("request %s is %s", id, state)
		}
	default:
		return fmt.Errorf("request %s is %s", id, state)
	}
	if choice == answerSave {
		if r.Action == nil || r.Operation == "" || r.Definition == "" {
			return errors.New("an unrecognized request cannot be saved")
		}
		if err := m.saveApproval(ctx, r); err != nil {
			return err
		}
	}
	m.records.mu.Lock()
	defer m.records.mu.Unlock()
	if r.State == statePending {
		r.State = stateApproved
		if choice == answerDeny {
			r.State = stateDenied
		}
		close(r.answered)
	}
	return nil
}

func (m *monitor) requests(mux *http.ServeMux) {
	mux.Handle("GET /requests", m.owned(true, func(*http.Request, ownerInput) (any, error) { return m.records.marshal() }))
	mux.Handle("POST /requests/{id}", m.owned(true, func(r *http.Request, req ownerInput) (any, error) {
		return nil, m.answer(r.Context(), r.PathValue("id"), req.Decision)
	}))
}

func (m *monitor) saveApproval(ctx context.Context, r *record) error {
	rules := slices.Clone(m.live.Load().cfg.Identities[r.Identity].Rules)
	rules = append(rules, rule{
		Account:    r.Account,
		Action:     *r.Action,
		Operation:  r.Operation,
		Definition: r.Definition,
		Scope:      r.Grant,
		Waives:     r.Gaps,
	})
	patch, err := json.Marshal(map[string]any{"identities": map[string]any{r.Identity: map[string]any{"rules": rules}}})
	if err != nil {
		return err
	}
	_, err = m.patch(ctx, patch)
	return err
}

func (rs *records) refuseApproved(r *record) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if r.State == stateApproved {
		r.State = stateRefused
	}
}
