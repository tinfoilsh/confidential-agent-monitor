package monitor

import (
	"crypto"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"maps"
	"slices"

	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/connector/web"
	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/internal/config"
	"github.com/tinfoilsh/monitor/internal/store"
	"github.com/tinfoilsh/monitor/internal/supervisor"
	"github.com/tinfoilsh/monitor/presets"
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
	Status     map[string]supervisor.Status   `json:"status"`
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
		Fields: map[string][]fieldMetadata{}, Status: map[string]supervisor.Status{}, Labels: map[string]facts.Label{},
		CatalogID: s.CatalogID, Presets: s.Catalog, Vocabulary: facts.Effects}
	if v.Config, err = json.Marshal(s.Config); err != nil {
		return nil, err
	}
	for _, c := range s.connections {
		v.Status[c.Name] = c.Status()
		for name, value := range c.Secrets {
			path := presets.CredentialPath{Connection: c.Key, Protocol: c.Protocol, Secret: name}.Path()
			kind, account := credential.Describe(m.store.Doc.Secrets[store.SecretID{Account: c.Account, Connection: c.Key, Name: name}])
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

// Discovery describes reachable connections, not the owner's configuration or credentials.
// HTTP connections add public routing and placeholder data, never credentials.
type connectionListing struct {
	Name         string            `json:"name"`
	Account      string            `json:"account"`
	Kind         string            `json:"kind"`
	Host         string            `json:"host"`
	State        string            `json:"state"`
	Access       config.Access     `json:"access"`
	Hosts        []string          `json:"hosts"`
	Slots        []web.Slot        `json:"slots"`
	Placeholders map[string]string `json:"placeholders"`
}

// listing snapshots the connections p reaches while the caller holds mu.
func (m *monitor) listing(p config.Principal) any {
	st := m.live.Load()
	result := struct {
		Identity    string              `json:"identity"`
		CA          string              `json:"ca"`
		Connections []connectionListing `json:"connections"`
	}{p.Name, m.store.Doc.Keys.CACert, []connectionListing{}}
	for _, name := range slices.Sorted(maps.Keys(st.connections)) {
		c := st.connections[name]
		if !p.Reaches(c.Account) {
			continue
		}
		l := connectionListing{Name: name, Account: c.Account, Kind: c.Protocol, Host: name + ".monitor",
			State: c.Status().State, Access: p.Accounts[c.Account]}
		if provider, ok := c.Server.(web.HTTPProvider); ok {
			h := provider.HTTPConfig()
			l.Hosts, l.Slots, l.Placeholders = h.Hosts, h.Slots, map[string]string{}
			for secret := range h.Names() {
				l.Placeholders[secret] = h.Placeholder(secret)
			}
		}
		result.Connections = append(result.Connections, l)
	}
	return result
}
