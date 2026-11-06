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
	"strings"
	"time"

	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/internal/store"
	"github.com/tinfoilsh/monitor/internal/tinfoil/ownerauth"
)

// Derive references from the existing persisted private key so restarts and
// credential refreshes keep them stable, without storing another set of tokens.
// The empty element keeps the references derived from version 1 state.
func placeholder(k store.Keys, id store.SecretID) string {
	mac := hmac.New(sha256.New, []byte(k.CAKey))
	mac.Write([]byte("monitor credential placeholder v1\x00"))
	raw, _ := json.Marshal([]string{id.Connection, "", id.Name})
	mac.Write(raw)
	suffix := strings.ToLower(base32.StdEncoding.EncodeToString(mac.Sum(nil))[:9])
	return "tfm_" + id.Connection + "_" + suffix
}

// Provider writes preserve the connector and publish only after persistence.
func (m *monitor) replaceValue(ctx context.Context, id store.SecretID, value *credential.Value, before, after json.RawMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.connections[id.Connection]
	// Reject stale credential refreshes.
	if c == nil || c.Credentials[id.Name] != value || !bytes.Equal(m.store.Doc.Credentials.Get(id), before) {
		return errors.New("credential changed; start again")
	}
	next := m.store.Doc
	next.Credentials = next.Credentials.Clone()
	next.Credentials.Set(id, bytes.Clone(after))
	return m.store.Commit(ctx, next)
}

// signInCredential captures the record a sign-in replaces, so completing it cannot
// overwrite a newer edit.
func (m *monitor) signInCredential(connection, name string) (json.RawMessage, func(context.Context, json.RawMessage) error, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c := m.connections[connection]
	if c == nil || c.Credentials[name] == nil {
		return nil, nil, errors.New("credential does not exist")
	}
	id := store.SecretID{Connection: connection, Name: name}
	value, before := c.Credentials[name], bytes.Clone(m.store.Doc.Credentials.Get(id))
	return before, func(ctx context.Context, raw json.RawMessage) error {
		m.writes.Lock()
		defer m.writes.Unlock()
		return m.writeSettings(ctx, nil, nil, store.Secrets{connection: {name: raw}}, func() error {
			if m.connections[connection] != c || c.Credentials[name] != value || !bytes.Equal(m.store.Doc.Credentials.Get(id), before) {
				return errors.New("credential changed; start again")
			}
			return nil
		}, nil)
	}, nil
}

type signInInput struct {
	Redirect   string          `json:"redirect"`
	Name       string          `json:"name"`
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
	previous, save, err := m.signInCredential(r.PathValue("name"), req.Name)
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
