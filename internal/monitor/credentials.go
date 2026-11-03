package monitor

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/internal/config"
	"github.com/tinfoilsh/monitor/internal/store"
	"github.com/tinfoilsh/monitor/internal/tinfoil/ownerauth"
	"github.com/tinfoilsh/monitor/presets"
)

// Derive references from the existing persisted private key so restarts and
// credential refreshes keep them stable, without storing another set of tokens.
func placeholder(k store.Keys, id store.SecretID) string {
	mac := hmac.New(sha256.New, []byte(k.CAKey))
	mac.Write([]byte("monitor credential placeholder v1\x00"))
	raw, _ := json.Marshal([]string{id.Account, id.Connection, id.Name})
	mac.Write(raw)
	suffix := strings.ToLower(base32.StdEncoding.EncodeToString(mac.Sum(nil))[:9])
	return "tfm_" + config.ConnectionName(id.Account, id.Connection) + "_" + suffix
}

// Provider writes preserve the connector and publish only after persistence.
func (m *monitor) replaceValue(ctx context.Context, id store.SecretID, value *credential.Value, before, after json.RawMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.connections[config.ConnectionName(id.Account, id.Connection)]
	// Reject stale credential refreshes.
	if c == nil || c.Credentials[id.Name] != value || !bytes.Equal(m.store.Doc.Secrets.Get(id), before) {
		return errors.New("credential changed; start again")
	}
	next := m.store.Doc
	next.Secrets = next.Secrets.Clone()
	next.Secrets.Set(id, bytes.Clone(after))
	return m.store.Commit(ctx, next)
}

// credentialID interprets an owner edit path; credential storage only sees its ID.
func credentialID(path []string) (store.SecretID, bool) {
	if len(path) < 2 || path[0] != "accounts" {
		return store.SecretID{}, false
	}
	p, ok := presets.ParseCredentialPath(path[2:])
	return store.SecretID{Account: path[1], Connection: p.Connection, Name: p.Secret}, ok
}

// One catalog field can feed several connections. Capture all destinations so
// a completed sign-in updates them together, without overwriting a newer edit.
func (m *monitor) signInCredential(account string, path []string) (json.RawMessage, func(context.Context, json.RawMessage) error, error) {
	requested, ok := presets.ParseCredentialPath(path)
	if !ok {
		return nil, nil, errors.New("invalid credential path")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.settings.Load()
	c := m.connections[config.ConnectionName(account, requested.Connection)]
	if c == nil || c.Account != account || c.Protocol != requested.Protocol || c.Credentials[requested.Secret] == nil {
		return nil, nil, errors.New("connection does not exist")
	}
	paths := []presets.CredentialPath{requested}
	preset, err := s.Config.Preset(s.Config.Accounts[account].Preset)
	if err != nil {
		return nil, nil, err
	}
	fields, err := preset.Catalog.CredentialFields()
	if err != nil {
		return nil, nil, err
	}
	for _, field := range fields {
		if slices.Contains(field, requested) {
			paths = field
			break
		}
	}
	type destination struct {
		connection *connection
		value      *credential.Value
		path       []string
		id         store.SecretID
		before     json.RawMessage
	}
	var destinations []destination
	for _, p := range paths {
		target := m.connections[config.ConnectionName(account, p.Connection)]
		// An account may disable one of the preset's connections.
		if target == nil {
			continue
		}
		if target.Account != account || target.Protocol != p.Protocol || target.Credentials[p.Secret] == nil {
			return nil, nil, errors.New("credential connection does not exist")
		}
		destinationID := store.SecretID{Account: account, Connection: p.Connection, Name: p.Secret}
		path := append([]string{"accounts", account}, p.Path()...)
		destinations = append(destinations, destination{target, target.Credentials[p.Secret], path, destinationID, bytes.Clone(m.store.Doc.Secrets.Get(destinationID))})
	}
	return bytes.Clone(m.store.Doc.Secrets.Get(store.SecretID{Account: account, Connection: requested.Connection, Name: requested.Secret})), func(ctx context.Context, raw json.RawMessage) error {
		m.writes.Lock()
		defer m.writes.Unlock()
		var changes []config.Change
		for _, d := range destinations {
			changes = append(changes, config.Change{Path: d.path, Value: raw})
		}
		return m.writeSettings(ctx, nil, changes, func() error {
			for _, d := range destinations {
				if m.connections[d.connection.Name] != d.connection || d.connection.Credentials[d.id.Name] != d.value || !bytes.Equal(m.store.Doc.Secrets.Get(d.id), d.before) {
					return errors.New("credential changed; start again")
				}
			}
			return nil
		}, nil, "")
	}, nil
}

type signInInput struct {
	Redirect   string          `json:"redirect"`
	Path       []string        `json:"path"`
	Credential json.RawMessage `json:"credential"`
}

type finishSignInInput struct {
	Code     string  `json:"code"`
	ClientID string  `json:"client_id,omitempty"`
	Error    *string `json:"error,omitempty"`
	Cancel   bool    `json:"cancel,omitempty"`
}

type pendingSignIn struct {
	finish  func(context.Context, finishSignInInput) error
	session string
	expires time.Time
	done    <-chan struct{}
	cancel  context.CancelFunc
}

func (m *monitor) startSignIn(r *http.Request, req signInInput) (any, error) {
	previous, save, err := m.signInCredential(r.PathValue("account"), req.Path)
	if err != nil {
		return nil, err
	}
	record := previous
	if req.Credential != nil {
		record = req.Credential
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	session, _ := ownerauth.FromContext(r.Context())
	pending := &pendingSignIn{session: session.ID, expires: time.Now().Add(10 * time.Minute)}
	sign, err := credential.NewSignIn(ctx, m.settings.Load().Client(), record, req.Redirect)
	if err != nil {
		return nil, err
	}
	var response any = map[string]string{"url": sign.URL}
	exchange := sign.Exchange
	if sign.UserCode != "" {
		poll, stop := context.WithDeadline(context.Background(), sign.Expires)
		done := make(chan struct{})
		var secret json.RawMessage
		var failure error
		go func() { defer close(done); defer stop(); secret, failure = sign.WaitDevice(poll) }()
		pending.expires, pending.done, pending.cancel = sign.Expires, done, stop
		exchange = func(context.Context, string, string) (json.RawMessage, error) { return secret, failure }
		response = map[string]any{"url": sign.URL, "state": sign.State, "user_code": sign.UserCode, "expires": sign.Expires}
	}
	pending.finish = func(ctx context.Context, result finishSignInInput) error {
		if result.Error != nil {
			return errors.New("sign-in was not completed; try again")
		}
		secret, err := exchange(ctx, result.Code, result.ClientID)
		if err != nil {
			return err
		}
		return save(ctx, secret)
	}

	m.signIns.Store(sign.State, pending)
	time.AfterFunc(time.Until(pending.expires), func() { m.signIns.CompareAndDelete(sign.State, pending) })
	return response, nil
}

func (m *monitor) finishSignIn(r *http.Request, req finishSignInInput) (any, error) {
	state := r.PathValue("state")
	value, ok := m.signIns.Load(state)
	if !ok {
		return nil, errors.New("sign-in expired or already completed; start again")
	}
	pending := value.(*pendingSignIn)
	session, _ := ownerauth.FromContext(r.Context())
	if pending.session != session.ID {
		return nil, errors.New("sign-in belongs to a different Monitor session")
	}
	if !req.Cancel && req.Error == nil && pending.done != nil && time.Now().Before(pending.expires) {
		select {
		case <-pending.done:
		default:
			return map[string]bool{"pending": true}, nil
		}
	}
	if !m.signIns.CompareAndDelete(state, pending) {
		return nil, errors.New("sign-in expired or already completed; start again")
	}
	if pending.cancel != nil {
		defer pending.cancel()
	}
	if !time.Now().Before(pending.expires) {
		return nil, errors.New("sign-in expired or already completed; start again")
	}
	if req.Cancel {
		return nil, nil
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	return m.viewAfter(pending.finish(ctx, req))
}
