// Package config owns the saved source, validated settings and control views.
package config

import (
	"encoding/json"
	"net/netip"

	"github.com/tinfoilsh/monitor/facts"
)

const AgentConnection = "agent"

// ConnectionSpec supplies one connector's setup and opaque semantic definition.
type ConnectionSpec struct {
	Name, Protocol, Account, Key string
	Config, Definition, Options  json.RawMessage
	PublicScope, CredentialNames []string
}

func ConnectionName(account, key string) string {
	if key != "" {
		return account + "-" + key
	}
	return account
}

type Principal struct {
	Fingerprint, Name string
}

type Identity struct {
	Routes   bool              `json:"routes,omitempty"`
	Key      string            `json:"key"`
	Sandbox  json.RawMessage   `json:"sandbox,omitzero"`
	Effects  map[string]string `json:"effects,omitempty"`
	Accounts map[string]Access `json:"accounts"`
	Rules    map[string]Rule   `json:"rules,omitempty"`
}

type Access struct {
	Level   string            `json:"level"`
	Actions map[string]string `json:"actions,omitempty"`
	Effects map[string]string `json:"effects,omitempty"`
}

// A rule waives requirements for one operation under the definition the owner approved.
type Rule struct {
	Enabled      *bool               `json:"enabled,omitempty"`
	Account      string              `json:"account"`
	Action       string              `json:"action"`
	Operation    string              `json:"operation,omitempty"`
	ApprovalKey  string              `json:"definition,omitempty"`
	Scope        map[string]any      `json:"scope"`
	Requirements []facts.Requirement `json:"requirements"`
}

// PolicyOptions retains the source format. Origin/address also bind local connector semantics.
type PolicyOptions struct {
	Private []string `json:"private,omitempty"`
	Address string   `json:"address,omitempty"`
	Origin  string   `json:"origin,omitempty"`
}

type Account struct {
	Preset        string                                `json:"preset"`
	Effects       map[string]string                     `json:"effects,omitempty"`
	PolicyOptions PolicyOptions                         `json:"policy_options"`
	Contents      string                                `json:"contents"`
	Strangers     bool                                  `json:"strangers"`
	Sends         string                                `json:"sends"`
	Connections   map[string]map[string]json.RawMessage `json:"connections,omitempty"`
}

type Lattices struct {
	Confidentiality bool `json:"confidentiality"`
	Integrity       bool `json:"integrity"`
}

// Config is immutable declared settings. Inheritance and setup defaults are
// projected for their consumers, never written back into these declarations.
type Config struct {
	AllowPaidInference bool                `json:"allow_paid_inference,omitempty"`
	Effects            map[string]string   `json:"effects,omitempty"`
	DefaultAccess      map[string]Access   `json:"default_access,omitempty"`
	Lattices           Lattices            `json:"lattices"`
	AllowNetworks      []netip.Prefix      `json:"allow_networks"`
	Accounts           map[string]Account  `json:"accounts"`
	Identities         map[string]Identity `json:"identities"`
	Policies           map[string]string   `json:"policies"`
	Data               map[string]any      `json:"data"`
	Principals         map[string]string   `json:"-"`
}
