package monitor

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base32"
	"encoding/json"
	"errors"
	"slices"
	"strings"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/internal/config"
	"github.com/tinfoilsh/monitor/internal/store"
	"github.com/tinfoilsh/monitor/presets"
)

// Derive references from the existing persisted private key so restarts and
// credential refreshes keep them stable, without storing another set of tokens.
func placeholder(k store.Keys, id store.SecretID) string {
	mac := hmac.New(sha256.New, []byte(k.CAKey))
	mac.Write([]byte("monitor credential placeholder v1\x00"))
	raw, _ := json.Marshal(id)
	mac.Write(raw)
	suffix := strings.ToLower(base32.StdEncoding.EncodeToString(mac.Sum(nil))[:9])
	return "tfm_" + config.ConnectionName(id[0], id[1]) + "_" + suffix
}

// Provider writes preserve the connector and publish only after persistence.
func (m *monitor) replaceValue(ctx context.Context, c *connection, id store.SecretID, before, after json.RawMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.live.Load().connections[c.Name] != c || !bytes.Equal(m.store.Doc.Secrets.Get(id), before) {
		return errors.New("credential changed; start again")
	}
	next := m.store.Doc
	next.Secrets = next.Secrets.Clone()
	next.Secrets.Set(id, bytes.Clone(after))
	return m.store.Commit(ctx, next)
}

// connectionTLS supplies the admitted target when an in-process client omits SNI.
// Worker certificate requests resolve and validate their target in the broker.
func connectionTLS(keys *store.Keys) (*tls.Config, error) {
	config, err := keys.TLS()
	if err != nil {
		return nil, err
	}
	issue := config.GetCertificate
	config.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if stream, ok := hello.Conn.(*connector.Stream); ok && hello.ServerName == "" {
			copy := *hello
			copy.ServerName = stream.Host
			hello = &copy
		}
		return issue(hello)
	}
	return config, nil
}

// credentialID interprets an owner edit path; credential storage only sees its ID.
func credentialID(path []string) (store.SecretID, bool) {
	if len(path) != 7 || path[0] != "accounts" || path[2] != "connections" || path[5] != "secrets" {
		return store.SecretID{}, false
	}
	return store.SecretID{path[1], path[3], path[6]}, true
}

// One catalog field can feed several connections. Capture all destinations so
// a completed sign-in updates them together, without overwriting a newer edit.
func (m *monitor) signInCredential(account string, path []string) (json.RawMessage, func(context.Context, json.RawMessage) error, error) {
	full := append([]string{"accounts", account}, path...)
	id, ok := credentialID(full)
	if !ok {
		return nil, nil, errors.New("invalid credential path")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.live.Load()
	c := s.connections[config.ConnectionName(account, path[1])]
	if c == nil || c.Account != account || c.Protocol != path[2] || c.Secrets[path[4]] == nil {
		return nil, nil, errors.New("connection does not exist")
	}
	requested := presets.CredentialPath{Connection: id[1], Protocol: path[2], Secret: id[2]}
	paths := []presets.CredentialPath{requested}
	fields, err := s.Config.Resolved[s.Config.Accounts[account].Preset].Catalog.CredentialFields()
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
		path       []string
		id         store.SecretID
		before     json.RawMessage
	}
	var destinations []destination
	for _, p := range paths {
		target := s.connections[config.ConnectionName(account, p.Connection)]
		// An account may disable one of the preset's connections.
		if target == nil {
			continue
		}
		if target.Account != account || target.Protocol != p.Protocol || target.Secrets[p.Secret] == nil {
			return nil, nil, errors.New("credential connection does not exist")
		}
		destinationID := store.SecretID{account, p.Connection, p.Secret}
		path := append([]string{"accounts", account}, p.Path()...)
		destinations = append(destinations, destination{target, path, destinationID, bytes.Clone(m.store.Doc.Secrets.Get(destinationID))})
	}
	return bytes.Clone(m.store.Doc.Secrets.Get(id)), func(ctx context.Context, raw json.RawMessage) error {
		m.mu.Lock()
		defer m.mu.Unlock()
		var changes []config.Change
		for _, d := range destinations {
			if m.live.Load().connections[d.connection.Name] != d.connection || !bytes.Equal(m.store.Doc.Secrets.Get(d.id), d.before) {
				return errors.New("credential changed; start again")
			}
			changes = append(changes, config.Change{Path: d.path, Value: raw})
		}
		return m.editPolicy(ctx, changes)
	}, nil
}
