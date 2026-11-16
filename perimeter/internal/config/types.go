// Package config owns the saved source, validated settings and control views.
package config

import (
	"encoding/json"
	"maps"
	"net/netip"
	"slices"

	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/internal/authz"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/internal/tomledit"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/presets"
)

const AgentConnection = "agent"

// ConnectionSpec supplies one connector's setup and opaque semantic definition.
type ConnectionSpec struct {
	Name, Protocol              string
	Config, Definition, Options json.RawMessage
	PublicScope                 []string
}

type Principal = facts.Principal
type Access struct {
	Level   string            `json:"level"`
	Actions map[string]string `json:"actions,omitempty"`
	Effects map[string]string `json:"effects,omitempty"`
}

// A rule waives the requirements it names for one operation and scope.
type Rule struct {
	Enabled      *bool               `json:"enabled,omitempty"`
	Version      int                 `json:"version"` // facts.Version it was approved under.
	Connection   string              `json:"connection"`
	Action       string              `json:"action"`
	Operation    string              `json:"operation,omitempty"`
	Definition   string              `json:"definition,omitempty"` // Read from rules saved before Version; never matched.
	Scope        map[string]any      `json:"scope"`
	Requirements []authz.Requirement `json:"requirements"`
}
type Change = tomledit.Change

type Identity struct {
	// Stored configs and enrollment clients name this "routes".
	Operator    bool              `json:"routes,omitempty"`
	Key         string            `json:"key"`
	Groups      []string          `json:"groups,omitempty"`
	Effects     map[string]string `json:"effects,omitempty"`
	Connections map[string]Access `json:"connections"`
	Rules       map[string]Rule   `json:"rules,omitempty"`
	// Attributes are an identity's other keys, each checked by the validator registered under its name.
	Attributes map[string]json.RawMessage `json:",embed"`
}

// PolicyOptions retains the source format. Origin/address also bind local connector semantics.
type PolicyOptions struct {
	Private []string `json:"private,omitempty"`
	Address string   `json:"address,omitempty"`
	Origin  string   `json:"origin,omitempty"`
}

// Connection holds one connector's settings, and its setup under the connector's kind.
type Connection struct {
	Preset        string                     `json:"preset"`
	Effects       map[string]string          `json:"effects,omitempty"`
	PolicyOptions PolicyOptions              `json:"policy_options"`
	Contents      string                     `json:"contents"`
	Strangers     bool                       `json:"strangers"`
	Sends         string                     `json:"sends"`
	Setup         map[string]json.RawMessage `json:"-"`
}

type connectionSettings Connection

// settingKeys name a connection's settings; its other key is its connector's kind.
var settingKeys = []string{"preset", "effects", "policy_options", "contents", "strangers", "sends"}

func (c *Connection) UnmarshalJSON(raw []byte) error {
	var setup map[string]json.RawMessage
	if err := json.Unmarshal(raw, &setup); err != nil {
		return err
	}
	var settings connectionSettings
	if err := json.Unmarshal(raw, &settings); err != nil {
		return err
	}
	maps.DeleteFunc(setup, func(key string, _ json.RawMessage) bool { return slices.Contains(settingKeys, key) })
	*c = Connection(settings)
	c.Setup = setup
	return nil
}

func (c Connection) MarshalJSON() ([]byte, error) {
	return marshalWith(connectionSettings(c), c.Setup)
}

// marshalWith adds the keys of extra to the JSON object of value.
func marshalWith(value any, extra map[string]json.RawMessage) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil || len(extra) == 0 {
		return raw, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	maps.Copy(fields, extra)
	return json.Marshal(fields)
}

type Lattices struct {
	Confidentiality bool `json:"confidentiality"`
	Integrity       bool `json:"integrity"`
}

// Config is immutable declared settings. Inheritance and setup defaults are
// projected for their consumers, never written back into these declarations.
type Config struct {
	AllowPaidInference bool                  `json:"allow_paid_inference,omitempty"`
	Effects            map[string]string     `json:"effects,omitempty"`
	DefaultAccess      map[string]Access     `json:"default_access,omitempty"`
	Lattices           Lattices              `json:"lattices"`
	AllowNetworks      []netip.Prefix        `json:"allow_networks"`
	Connections        map[string]Connection `json:"connections"`
	Identities         map[string]Identity   `json:"identities"`
	Policies           map[string]string     `json:"policies"`
	Data               map[string]any        `json:"data"`
	Principals         map[string]string     `json:"-"`
	presets            presets.Set
	Vocabulary         facts.Vocabulary `json:"-"`
}
