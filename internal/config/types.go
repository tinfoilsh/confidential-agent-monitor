// Package config resolves policy source into immutable settings, principals and connection specifications.
package config

import (
	"encoding/json"
	"net/netip"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/internal/policy"
	"github.com/tinfoilsh/monitor/internal/sandbox"
	"github.com/tinfoilsh/monitor/presets"
)

// AgentConnection is reserved for the Monitor's own agent API.
const AgentConnection = "agent"

// Snapshot is an immutable compiled policy.
type Snapshot struct {
	Config     *Config
	Principals map[string]Principal
	Engine     *policy.Engine
	Catalog    map[string]CatalogEntry
	CatalogID  string
}

// ConnectionSpec describes a connector before runtime resources or credentials are bound.
type ConnectionSpec struct {
	Name, Protocol, Account, Key string
	Config                       json.RawMessage
}

func ConnectionName(account, key string) string {
	if key != "" {
		return account + "-" + key
	}
	return account
}

type Principal struct {
	Key  string
	Name string
	Identity
}

type Identity struct {
	Routes   bool              `json:"routes,omitempty"`
	Key      string            `json:"key"`
	Sandbox  sandbox.Boot      `json:"sandbox,omitzero"`
	Reviewer string            `json:"reviewer,omitempty"`
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
	Enabled      *bool                `json:"enabled,omitempty"`
	Account      string               `json:"account"`
	Action       string               `json:"action"`
	Operation    string               `json:"operation,omitempty"`
	Definition   string               `json:"definition,omitempty"`
	Scope        map[string]any       `json:"scope"`
	Requirements []policy.Requirement `json:"requirements"`
}

type Account struct {
	Preset        string                    `json:"preset"`
	Effects       map[string]string         `json:"effects,omitempty"`
	PolicyOptions connector.PolicyOptions   `json:"policy_options"`
	Contents      string                    `json:"contents"`
	Strangers     bool                      `json:"strangers"`
	Sends         string                    `json:"sends"`
	Connections   map[string]map[string]any `json:"connections,omitempty"`
}

type Reviewer struct {
	Connection   string `json:"connection"`
	Model        string `json:"model"`
	Instructions string `json:"instructions"`
}

// Config is the decoded policy source with presets and inherited access resolved.
type Config struct {
	Reviewer           *Reviewer           `json:"reviewer,omitempty"`
	AllowPaidInference bool                `json:"allow_paid_inference,omitempty"`
	AllowSandboxSSH    bool                `json:"allow_sandbox_ssh,omitempty"`
	Effects            map[string]string   `json:"effects,omitempty"`
	DefaultAccess      map[string]Access   `json:"default_access,omitempty"`
	Lattices           policy.Lattices     `json:"lattices"`
	AllowNetworks      []netip.Prefix      `json:"allow_networks"`
	Accounts           map[string]Account  `json:"accounts"`
	Identities         map[string]Identity `json:"identities"`
	Policies           map[string]string   `json:"policies"`
	Data               map[string]any      `json:"data"`

	// Presets contains the source overrides; Resolved holds the compiled definitions.
	Presets  map[string]map[string]any  `json:"presets,omitempty"`
	Resolved map[string]*presets.Preset `json:"-"`
}
