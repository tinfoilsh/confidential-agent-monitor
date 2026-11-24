package config

import (
	"context"
	_ "embed"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/format"
)

const FactsVersion = 15

const (
	KindOperation     = "operation"
	KindAdmission     = "admission"
	SendsToConnection = "connection"
	CustomAction      = "request"
	EffectUnknown     = "unknown"
)

var CustomEffects = []string{"execute", "send"}

// Traits place an effect in the integrity and confidentiality lattices.
type Traits struct {
	// Only a trusted agent may do this, so one that has read untrusted content asks first.
	Integrity bool `json:"integrity"`
	// Who can see the data the request carries out: DataService, DataStored or DataDelivered.
	Confidentiality string `json:"confidentiality"`
}

// A connector that names the audience itself overrides these.
const (
	// Only the service sees the data, so the connection's sends audience does.
	DataService = "service"
	// Whoever can see the resource it is stored in does; a public resource means anyone.
	DataStored = "stored"
	// Its recipients do, as well as whoever can see where it is stored; unnamed recipients mean anyone.
	DataDelivered = "delivered"
)

var Vocabulary = map[string]Traits{
	"read":     {Confidentiality: DataService},
	"session":  {Confidentiality: DataService},
	"write":    {Integrity: true, Confidentiality: DataStored},
	"generate": {Integrity: true, Confidentiality: DataStored},
	"delete":   {Integrity: true, Confidentiality: DataStored},
	"admin":    {Integrity: true, Confidentiality: DataStored},
	"execute":  {Integrity: true, Confidentiality: DataStored},
	"pay":      {Integrity: true, Confidentiality: DataStored},
	"send":     {Integrity: true, Confidentiality: DataDelivered},
	"share":    {Integrity: true, Confidentiality: DataDelivered},
	"publish":  {Integrity: true, Confidentiality: DataDelivered},
	// An unrecognized request may do anything, but nothing shows where its data goes.
	EffectUnknown: {Integrity: true, Confidentiality: DataService},
}

const (
	AudienceMe     = "me"
	AudienceTeam   = "team"
	AudienceAnyone = "anyone"
	TrustUntrusted = "untrusted"
	TrustTrusted   = "trusted"
)

var (
	Audiences    = []string{AudienceMe, AudienceTeam, AudienceAnyone}
	Trusts       = []string{TrustUntrusted, TrustTrusted}
	InitialLabel = format.Label{Trust: TrustTrusted, Audience: AudienceAnyone}
)

func ValidLabel(l format.Label) bool {
	return slices.Contains(Audiences, l.Audience) && slices.Contains(Trusts, l.Trust)
}

func Meet(a, b format.Label) format.Label {
	l := format.Label{Because: map[string]string{}}
	axis := func(name string, levels []string, x, y string) string {
		level, because := x, a.Because[name]
		if slices.Index(levels, y) < slices.Index(levels, x) {
			level, because = y, b.Because[name]
		}
		if because != "" {
			l.Because[name] = because
		}
		return level
	}
	l.Audience = axis("audience", Audiences, a.Audience, b.Audience)
	l.Trust = axis("trust", Trusts, a.Trust, b.Trust)
	return l
}

func ValidEffects(effects []string) bool {
	return len(effects) != 0 && !slices.ContainsFunc(effects, func(effect string) bool { _, ok := Vocabulary[effect]; return !ok || effect == EffectUnknown })
}

const (
	standardModule = "perimeter/lib.rego"
	baseModule     = "perimeter/base.rego"
	decisionQuery  = "data.perimeter.decision"
)

var (
	protectedData = []string{"perimeter", "lattices", "levels", "base_policy"}
	basePackage   = []string{"perimeter", "base"}
	retiredRules  = map[string]string{
		"admin_allow": "a call to the Perimeter's API is a request on the perimeter connection, decided by allow and approvals like any request",
		"capable":     "a capability is an action on the perimeter connection, granted in an access block",
	}
)

//go:embed lib.rego
var standardPolicy string

func PreparePolicy(ctx context.Context, cfg *Config, base string) (*Program, error) {
	for _, name := range protectedData {
		if _, ok := cfg.Data[name]; ok {
			return nil, fmt.Errorf("data.%s is reserved for the Perimeter", name)
		}
	}
	data := maps.Clone(cfg.Data)
	if data == nil {
		data = map[string]any{}
	}
	data["levels"] = map[string]any{"audiences": Audiences, "trusts": Trusts, "effects": Vocabulary}
	data["lattices"] = cfg.Lattices
	data["base_policy"] = base != ""
	modules := map[string]string{standardModule: standardPolicy}
	if base != "" {
		if err := checkBase(base); err != nil {
			return nil, err
		}
		modules[baseModule] = base
	}
	for _, name := range slices.Sorted(maps.Keys(cfg.Policies)) {
		filename := "policies/" + name
		_, path, err := regoModule(filename, cfg.Policies[name])
		if err != nil {
			return nil, err
		}
		if slices.Contains(protectedData, path[0]) {
			return nil, fmt.Errorf("policy %s: data.%s is reserved for the Perimeter", name, path[0])
		}
		modules[filename] = cfg.Policies[name]
	}
	return prepareRego(ctx, modules, data)
}

func checkBase(base string) error {
	module, path, err := regoModule(baseModule, base)
	if err != nil {
		return err
	}
	if !slices.Equal(path, basePackage) {
		return fmt.Errorf("the base policy must be package data.%s, not data.%s", strings.Join(basePackage, "."), strings.Join(path, "."))
	}
	for _, rule := range module.Rules {
		name := rule.Head.Ref()[0].String()
		if replaced, retired := retiredRules[name]; retired {
			return fmt.Errorf("the base policy defines %s, which no longer exists: %s", name, replaced)
		}
	}
	return nil
}

type DecisionInput struct {
	Facts         json.RawMessage    `json:"facts"`
	Authorization AuthorizationInput `json:"authorization"`
	Connection    ConnectionInput    `json:"connection"`
}

type AuthorizationInput struct {
	Modes    map[string]Setting `json:"modes"`
	Rules    []Rule             `json:"rules"`
	Approved []string           `json:"approved"`
	Scope    map[string]any     `json:"scope"`
}

type ConnectionInput struct {
	Returns  format.Label `json:"returns"`
	SendsTo  string       `json:"sends_to"`
	Address  string       `json:"address"`
	Private  []string     `json:"private"`
	Resource []string     `json:"resource"`
}

type Outcome string

const (
	OutcomeAllow Outcome = "allow"
	OutcomeAsk   Outcome = "ask"
	OutcomeDeny  Outcome = "deny"
)

type Decision struct {
	Outcome Outcome       `json:"outcome"`
	SendsTo string        `json:"sends_to"`
	Next    *format.Label `json:"next,omitempty"`
	Gaps    []Requirement `json:"gaps,omitempty"`
	Reasons []string      `json:"reasons,omitempty"`
}

func (d Decision) Validate() error {
	own := map[Outcome]string{OutcomeAllow: "next", OutcomeAsk: "gaps", OutcomeDeny: "reasons"}[d.Outcome]
	if own == "" {
		return fmt.Errorf("unknown outcome %q", d.Outcome)
	}
	if d.SendsTo == "" {
		return fmt.Errorf("%s needs sends_to", d.Outcome)
	}
	for field, present := range map[string]bool{"next": d.Next != nil, "gaps": len(d.Gaps) != 0, "reasons": len(d.Reasons) != 0} {
		if present != (field == own) {
			return fmt.Errorf("%s must carry %s and no other outcome's fields", d.Outcome, own)
		}
	}
	return nil
}
