package monitor

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"slices"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/internal/config"
	"github.com/tinfoilsh/monitor/internal/store"
	"golang.org/x/crypto/ssh"
)

type fieldMetadata struct {
	Path        []string `json:"path"`
	Kind        string   `json:"kind"`
	Placeholder string   `json:"placeholder,omitempty"`
	Account     string   `json:"account,omitempty"`
}

// ownerView exposes credential status without credential values.
type ownerView struct {
	Generation uint64                         `json:"generation"`
	Config     json.RawMessage                `json:"config"`
	HostKey    string                         `json:"host_key"`
	HostID     string                         `json:"host_id"`
	CA         string                         `json:"ca"`
	Fields     map[string][]fieldMetadata     `json:"fields"`
	Status     map[string]connectionStatus    `json:"status"`
	Labels     map[string]facts.Label         `json:"labels"`
	CatalogID  string                         `json:"catalog_id"`
	Presets    map[string]config.CatalogEntry `json:"presets,omitempty"`
	Vocabulary map[string]facts.Obligations   `json:"vocabulary"`
}

// view snapshots owner state while the caller holds mu. It never calls a connector.
func (m *monitor) view(err error) (any, error) {
	if err != nil {
		return nil, err
	}
	s := m.live.Load()
	// The persisted CA identifies the host across restarts and SSH key rotation.
	block, _ := pem.Decode([]byte(m.store.Doc.Keys.CACert))
	if block == nil {
		return nil, errors.New("Monitor has no host certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, err := jwk.Import(certificate.PublicKey)
	if err != nil {
		return nil, err
	}
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return nil, err
	}
	v := ownerView{Generation: m.store.Doc.Generation, HostKey: string(ssh.MarshalAuthorizedKey(s.HostKey.PublicKey())), CA: m.store.Doc.Keys.CACert,
		HostID: "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" + base64.RawURLEncoding.EncodeToString(thumbprint),
		Fields: map[string][]fieldMetadata{}, Status: map[string]connectionStatus{}, Labels: map[string]facts.Label{},
		CatalogID: s.CatalogID, Presets: s.Catalog, Vocabulary: facts.Effects}
	if v.Config, err = json.Marshal(s.Config); err != nil {
		return nil, err
	}
	for _, c := range s.connections {
		v.Status[c.Name] = c.status()
		for name, value := range c.Secrets {
			path := []string{"connections", c.Key, c.Protocol, "secrets", name}
			kind, account := credential.Describe(m.store.Doc.Secrets.Get(store.SecretID{c.Account, c.Key, name}))
			v.Fields[c.Account] = append(v.Fields[c.Account], fieldMetadata{Path: path, Kind: kind, Placeholder: value.Placeholder, Account: account})
		}
	}
	for _, fields := range v.Fields {
		slices.SortFunc(fields, func(a, b fieldMetadata) int { return slices.Compare(a.Path, b.Path) })
	}
	for _, p := range s.Principals {
		v.Labels[p.Name] = m.currentLabel(p.Key)
	}
	return v, nil
}
