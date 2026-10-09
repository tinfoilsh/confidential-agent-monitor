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
	"time"

	"github.com/tinfoilsh/monitor/connector/browser"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/connector/mcp"
	"github.com/tinfoilsh/monitor/connector/web"
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
	Generation      uint64                      `json:"generation"`
	Config          json.RawMessage             `json:"config"`
	HostKey         string                      `json:"host_key"`
	CA              string                      `json:"ca"`
	Fields          map[string][]fieldMetadata  `json:"fields"`
	Status          map[string]connectionStatus `json:"status"`
	Labels          map[string]facts.Label      `json:"labels"`
	Setup           map[string]string           `json:"setup"`
	Presets         map[string]catalogEntry     `json:"presets"`
	PolicyProposals []proposalSummary           `json:"policy_proposals"`
}

func (m *transaction) view() (any, error) {
	s := m.live.Load()
	var err error
	v := ownerView{Generation: m.doc.Generation, HostKey: string(ssh.MarshalAuthorizedKey(s.HostKey.PublicKey())), CA: m.doc.Keys.CACert,
		Fields: map[string][]fieldMetadata{}, Status: map[string]connectionStatus{}, Labels: map[string]facts.Label{}, Setup: map[string]string{}, Presets: catalog(s.cfg.resolved), PolicyProposals: []proposalSummary{}}
	for _, proposal := range m.doc.Policy.Proposals {
		v.PolicyProposals = append(v.PolicyProposals, proposal.summary(m.doc.Policy.Source))
	}
	v.Config, v.Fields, err = configView(m.doc, s)
	if err != nil {
		return nil, err
	}
	for _, c := range s.connections {
		v.Status[c.name] = c.status()
	}
	for _, p := range s.principals {
		v.Labels[p.Name] = m.currentLabel(p.Key)
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

func (m *monitor) view(err error) (result any, outErr error) {
	if err != nil {
		return nil, err
	}
	outErr = m.transact(func(tx *transaction) error { result, outErr = tx.view(); return outErr })
	return
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
		err := m.transact(func(tx *transaction) error {
			var fingerprint string
			for key, p := range tx.live.Load().principals {
				if p.Name == r.PathValue("identity") {
					fingerprint = key
					break
				}
			}
			if fingerprint == "" {
				return fmt.Errorf("no identity %s", r.PathValue("identity"))
			}
			if !l.Valid() {
				return fmt.Errorf("a label needs trust in %v and audience in %v", facts.Trusts, facts.Audiences)
			}
			old := tx.currentLabel(fingerprint)
			l.Because = map[string]string{}
			if l.Trust != cleanLabel.Trust {
				l.Because["trust"] = cmp.Or(old.Because["trust"], "the owner")
			}
			if l.Audience != cleanLabel.Audience {
				l.Because["audience"] = cmp.Or(old.Because["audience"], "the owner")
			}
			tx.setLabel(fingerprint, l, nil)
			return tx.commit(r.Context(), tx.doc)
		})
		return m.view(err)
	}))
	mux.Handle("POST /accounts/{account}/sign-in", owned(m, m.startSignIn))
	mux.Handle("POST /sign-in/{state}", owned(m, m.finishSignIn))
	mux.HandleFunc("GET /connections/{name}/browser", m.browserControl)
	mux.HandleFunc("POST /connections/{name}/browser", m.browserControl)
	m.requests(mux)
	m.policyRoutes(mux)
	mux.Handle("GET /app/", appHandler(m.dev))
	return mux
}

type pendingSignIn struct {
	sign       *credential.SignIn
	connection *connection
	path       []string
	before     json.RawMessage
}

func (m *monitor) startSignIn(r *http.Request, req signInInput) (any, error) {
	var c *connection
	var path []string
	var previous json.RawMessage
	err := m.transact(func(tx *transaction) error {
		if len(req.Path) < 4 || req.Path[0] != "connections" {
			return errors.New("invalid credential path")
		}
		c = tx.live.Load().connections[connectionName(r.PathValue("account"), req.Path[1])]
		if c == nil || c.protocol != req.Path[2] {
			return errors.New("connection does not exist")
		}
		path = append([]string{"accounts", c.account}, req.Path...)
		if !isCredentialPath(path) || c.Secrets[path[6]] == nil {
			return errors.New("invalid credential path")
		}
		previous = tx.doc.Secrets.get(credentialID(path))
		return nil
	})
	if err != nil {
		return nil, err
	}
	record := previous
	if req.Credential != nil {
		record = req.Credential
	}
	sign, err := credential.NewSignIn(r.Context(), m.live.Load().Client(), record, req.Redirect)
	if err != nil {
		return nil, err
	}
	err = m.transact(func(tx *transaction) error {
		tx.signIns[sign.State] = pendingSignIn{sign, c, path, previous}
		return nil
	})
	return map[string]string{"url": sign.URL}, err
}

func (m *monitor) finishSignIn(r *http.Request, req finishSignInInput) (any, error) {
	var pending pendingSignIn
	err := m.transact(func(tx *transaction) error {
		var ok bool
		pending, ok = tx.signIns[r.PathValue("state")]
		delete(tx.signIns, r.PathValue("state"))
		if !ok {
			return errors.New("no sign-in is waiting for this state")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	secret, err := pending.sign.Exchange(r.Context(), req.Code)
	if err != nil {
		return nil, err
	}
	value := pending.connection.Secrets[pending.path[6]]
	return m.view(value.Replace(r.Context(), pending.before, secret))
}

// browserControl checks the owner's secret as owned does, then releases the monitor's locks, since a browser call can be slow.
func (m *monitor) browserControl(w http.ResponseWriter, r *http.Request) {
	_, err := m.authenticate(r, true)
	if err != nil {
		responseError(w, err)
		return
	}
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
	if unlocked {
		err = m.transact(func(tx *transaction) error {
			if tx.live.Load() == nil {
				return errLocked
			}
			if subtle.ConstantTimeCompare(key, tx.owner) != 1 {
				return errOwner
			}
			return nil
		})
	}
	return key, err
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

// Authentication owns no operation lock. Each mutation explicitly captures,
// prepares and commits its state; response writes never extend a transaction.
func owned[T any](m *monitor, fn func(*http.Request, T) (any, error)) http.HandlerFunc {
	handler := jsonHandler(maxDocumentBytes, fn)
	return func(w http.ResponseWriter, r *http.Request) {
		if _, err := m.authenticate(r, true); err != nil {
			responseError(w, err)
			return
		}
		handler(w, r)
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

// waitApproval reads only immutable wait metadata. State is checked when the
// request resumes its authorization transaction.
func waitApproval(ctx context.Context, r *record) {
	ctx, cancel := context.WithDeadline(ctx, r.Expires)
	defer cancel()
	select {
	case <-r.answered:
	case <-ctx.Done():
	}
}

func marshalRecords(records []*record) (json.RawMessage, error) {
	newest := append([]*record{}, records...)
	slices.Reverse(newest)
	return json.Marshal(newest)
}

// Expired requests can still save a rule, but cannot resume the original call.
func (m *monitor) answer(ctx context.Context, id, choice string) error {
	var candidate *policyCandidate
	if choice == answerSave {
		var snapshot record
		err := m.transact(func(tx *transaction) error {
			r, err := tx.pendingAnswer(id, choice)
			if err != nil {
				return err
			}
			snapshot = *r
			return nil
		})
		if err != nil {
			return err
		}
		candidate, err = m.prepareApproval(ctx, &snapshot)
		if err != nil {
			return err
		}
	}
	return m.transact(func(tx *transaction) error {
		r, err := tx.pendingAnswer(id, choice)
		if err != nil {
			return err
		}
		if candidate != nil {
			if err := tx.activate(ctx, candidate); err != nil {
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
	})
}

func (m *transaction) pendingAnswer(id, choice string) (*record, error) {
	i := slices.IndexFunc(m.records, func(r *record) bool { return r.ID == id })
	if i < 0 {
		return nil, fmt.Errorf("no request %s", id)
	}
	if !slices.Contains([]string{answerOnce, answerSave, answerDeny}, choice) {
		return nil, fmt.Errorf("decision must be %s, %s or %s", answerOnce, answerSave, answerDeny)
	}
	r := m.records[i]
	if r.State != statePending && !(r.State == stateExpired && choice == answerSave) {
		return nil, fmt.Errorf("request %s is %s", id, r.State)
	}
	return r, nil
}

func (m *monitor) requests(mux *http.ServeMux) {
	mux.Handle("GET /requests", owned(m, func(_ *http.Request, _ struct{}) (any, error) {
		var raw json.RawMessage
		err := m.transact(func(tx *transaction) error { var err error; raw, err = marshalRecords(tx.records); return err })
		return raw, err
	}))
	mux.Handle("POST /requests/{id}", owned(m, func(r *http.Request, req decisionInput) (any, error) {
		return nil, m.answer(r.Context(), r.PathValue("id"), req.Decision)
	}))
}

func (m *monitor) prepareApproval(ctx context.Context, r *record) (*policyCandidate, error) {
	f := r.Facts
	if f.Operation == nil || f.Operation.ID == "" || r.Definition == "" {
		return nil, errors.New("a request without a known operation cannot be saved")
	}
	base, err := m.policySnapshot()
	if err != nil {
		return nil, err
	}
	p, exists := base.state.principals[f.Principal.Key]
	if !exists || p.Name != f.Principal.Name {
		return nil, errors.New("the requesting identity was revoked or replaced")
	}
	value, err := json.Marshal(rule{Account: f.Account, Action: f.Operation.Action, Operation: f.Operation.ID,
		Definition: r.Definition, Scope: r.Grant, Requirements: slices.Clone(r.Requirements)})
	if err != nil {
		return nil, err
	}
	return m.prepareEdits(ctx, base, []sourceChange{{Path: []string{"identities", p.Name, "rules", r.ID}, Value: value}})
}
