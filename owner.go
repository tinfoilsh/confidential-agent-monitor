package main

import (
	"context"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/connector/web"
	"golang.org/x/crypto/ssh"
)

const maxDocumentBytes = 16 << 20

//go:embed app
var app embed.FS

// ownerView never includes private keys or secret values.
type ownerView struct {
	Generation uint64                       `json:"generation"`
	Config     json.RawMessage              `json:"config"`
	HostKey    string                       `json:"host_key"`
	CA         string                       `json:"ca"`
	Secrets    map[string][]string          `json:"secrets"`
	Status     map[string]any               `json:"status"`
	Labels     map[string]label             `json:"labels"`
	Setup      map[string]map[string]string `json:"setup"`
	Templates  any                          `json:"templates"`
}

func (m *monitor) view(s *state, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	templates, err := catalog()
	if err != nil {
		return nil, err
	}
	v := ownerView{s.Generation, s.Config, string(ssh.MarshalAuthorizedKey(s.HostKey.PublicKey())), s.Keys.CACert,
		map[string][]string{}, map[string]any{}, map[string]label{}, map[string]map[string]string{}, templates}
	for acct, secrets := range s.Secrets {
		v.Secrets[acct] = slices.Sorted(maps.Keys(secrets))
	}
	for _, c := range s.connections {
		v.Status[c.name] = c.status()
	}
	for _, p := range s.principals {
		v.Labels[p.Name] = m.label(p.Key)
		v.Setup[p.Name] = map[string]string{}
		for _, c := range s.connections {
			if r, ok := c.connector.(*web.HTTP); ok && p.reaches(c.account) {
				for secret := range r.Secrets {
					v.Setup[p.Name][secret] = web.Placeholder(c.name, secret)
				}
			}
		}
	}
	return v, nil
}

func (m *monitor) handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /unlock", m.owned(false, func(r *http.Request, key []byte) (any, error) {
		var req struct {
			Generation uint64 `json:"generation"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, err
		}
		return m.view(m.unlock(r.Context(), key, req.Generation))
	}))
	mux.Handle("GET /{$}", m.owned(true, func(*http.Request, []byte) (any, error) { return m.view(m.live.Load(), nil) }))
	mux.Handle("PATCH /{$}", m.owned(true, func(r *http.Request, _ []byte) (any, error) {
		patch, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		return m.view(m.patch(r.Context(), patch))
	}))
	mux.Handle("POST /secrets/{account}/{key}/sign-in", m.owned(true, func(r *http.Request, _ []byte) (any, error) {
		var req struct {
			Redirect string `json:"redirect"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, err
		}
		s, acct, key := m.live.Load(), r.PathValue("account"), r.PathValue("key")
		sign, err := credential.NewSignIn(r.Context(), &http.Client{Transport: &http.Transport{DialContext: s.Dialer.DialContext}}, s.Secrets[acct][key], req.Redirect)
		if err != nil {
			return nil, err
		}
		m.signIns.Store(sign.State, func(ctx context.Context, code string) (*state, error) {
			secret, err := sign.Exchange(ctx, code)
			if err != nil {
				return nil, err
			}
			patch, err := json.Marshal(map[string]any{"secrets": map[string]any{acct: map[string]any{key: secret}}})
			if err != nil {
				return nil, err
			}
			return m.patch(ctx, patch)
		})
		return map[string]string{"url": sign.URL}, nil
	}))
	mux.Handle("POST /sign-in/{state}", m.owned(true, func(r *http.Request, _ []byte) (any, error) {
		var req struct {
			Code string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, err
		}
		finish, ok := m.signIns.LoadAndDelete(r.PathValue("state"))
		if !ok {
			return nil, errors.New("no sign-in is waiting for this state")
		}
		return m.view(finish.(func(context.Context, string) (*state, error))(r.Context(), req.Code))
	}))
	m.requests(mux)
	mux.Handle("GET /app/", http.FileServerFS(app))
	return mux
}

// owned serializes owner requests; before unlock, decrypting the state is what proves the secret.
func (m *monitor) owned(unlocked bool, fn func(*http.Request, []byte) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
			v, err = fn(r, key)
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

// A record is one decision; requests are the pending and expired ones.
type record struct {
	ID       string           `json:"id"`
	State    string           `json:"state"`
	Time     time.Time        `json:"time"`
	Expires  time.Time        `json:"expires,omitzero"`
	Identity string           `json:"identity"`
	Account  string           `json:"account"`
	Label    label            `json:"label"`
	Event    *connector.Event `json:"event,omitempty"`
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
		if r.Action == nil {
			return errors.New("an unknown request cannot be saved")
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
	mux.Handle("GET /requests", m.owned(true, func(*http.Request, []byte) (any, error) { return m.records.marshal() }))
	mux.Handle("POST /requests/{id}", m.owned(true, func(r *http.Request, _ []byte) (any, error) {
		var req struct {
			Decision string `json:"decision"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, err
		}
		return nil, m.answer(r.Context(), r.PathValue("id"), req.Decision)
	}))
}

func (m *monitor) saveApproval(ctx context.Context, r *record) error {
	rules := slices.Clone(m.live.Load().cfg.Identities[r.Identity].Rules)
	rules = append(rules, rule{
		Account: r.Account,
		Action:  *r.Action,
		Scope:   r.Scope,
		Waives:  r.Gaps,
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
