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

	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/credential"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/internal/store"
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
func (m *Monitor) replaceValue(ctx context.Context, id store.SecretID, value *credential.Value, before, after json.RawMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.table.Connections()[id.Connection].Secrets[id.Name] != value || !bytes.Equal(m.store.Doc.Credentials.Get(id), before) {
		return errors.New("credential changed; start again")
	}
	next := m.store.Doc
	next.Credentials = next.Credentials.Clone()
	next.Credentials.Set(id, bytes.Clone(after))
	return m.store.Commit(ctx, next)
}

// signInCredential captures the record a sign-in replaces, so completing it cannot
// overwrite a newer edit.
func (m *Monitor) signInCredential(connection, name string) (json.RawMessage, func(context.Context, json.RawMessage) error, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	value := m.table.Connections()[connection].Secrets[name]
	if value == nil {
		return nil, nil, errors.New("credential does not exist")
	}
	id := store.SecretID{Connection: connection, Name: name}
	before := bytes.Clone(m.store.Doc.Credentials.Get(id))
	return before, func(ctx context.Context, raw json.RawMessage) error {
		m.writes.Lock()
		defer m.writes.Unlock()
		return m.writeSettings(ctx, settingsWrite{credentials: store.Secrets{connection: {name: raw}}, check: func() error {
			if m.table.Connections()[connection].Secrets[name] != value || !bytes.Equal(m.store.Doc.Credentials.Get(id), before) {
				return errors.New("credential changed; start again")
			}
			return nil
		}})
	}, nil
}

type signInInput struct {
	Redirect   string          `json:"redirect"`
	Name       string          `json:"name"`
	Credential json.RawMessage `json:"credential"`
}

func (m *Monitor) startSignIn(r *http.Request, req signInInput) (any, error) {
	previous, save, err := m.signInCredential(r.PathValue("name"), req.Name)
	if err != nil {
		return nil, err
	}
	record := previous
	if req.Credential != nil {
		record = req.Credential
	}
	session, _ := CallerFrom(r.Context())
	sign, err := m.signIns.Start(r.Context(), m.settings.Load().Client(), record, req.Redirect, session.ID, save)
	if err != nil {
		return nil, err
	}
	if sign.UserCode != "" {
		return map[string]any{"url": sign.URL, "state": sign.State, "user_code": sign.UserCode, "expires": sign.Expires}, nil
	}
	return map[string]string{"url": sign.URL}, nil
}

func (m *Monitor) finishSignIn(r *http.Request, req credential.SignInResult) (any, error) {
	session, _ := CallerFrom(r.Context())
	pending, err := m.signIns.Finish(r.Context(), r.PathValue("state"), session.ID, req)
	if pending {
		return map[string]bool{"pending": true}, nil
	}
	if err == nil && req.Cancel {
		return nil, nil
	}
	return m.viewAfter(r, err)
}
