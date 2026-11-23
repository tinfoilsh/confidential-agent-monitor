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
	KindOperation   = "operation"
	KindAdmission   = "admission"
	SendsConnection = "connection"
	CustomAction    = "request"
	EffectUnknown   = "unknown"
)

var CustomEffects = []string{"execute", "send"}

type Obligations struct {
	Change    bool `json:"change"`
	Trust     bool `json:"trust"`
	Ask       bool `json:"ask"`
	Discloses bool `json:"discloses"`
}

var Vocabulary = map[string]Obligations{
	"read":        {},
	"session":     {},
	"write":       {Change: true, Trust: true},
	"generate":    {Change: true, Trust: true},
	"delete":      {Change: true, Trust: true},
	"admin":       {Change: true, Trust: true},
	"execute":     {Change: true, Trust: true},
	"send":        {Change: true, Trust: true, Discloses: true},
	"share":       {Change: true, Trust: true, Discloses: true},
	"publish":     {Change: true, Trust: true, Ask: true, Discloses: true},
	"pay":         {Change: true, Trust: true, Ask: true},
	EffectUnknown: {Trust: true, Ask: true},
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
	Contents    string   `json:"contents"`
	Strangers   bool     `json:"strangers"`
	Sends       string   `json:"sends"`
	Address     string   `json:"address"`
	Private     []string `json:"private"`
	PublicScope []string `json:"public_scope"`
}

type Outcome string

const (
	OutcomeAllow Outcome = "allow"
	OutcomeAsk   Outcome = "ask"
	OutcomeDeny  Outcome = "deny"
)

type Decision struct {
	Outcome Outcome       `json:"outcome"`
	Sends   string        `json:"sends"`
	Next    *format.Label `json:"next,omitempty"`
	Gaps    []Requirement `json:"gaps,omitempty"`
	Reasons []string      `json:"reasons,omitempty"`
}

func (d Decision) Validate() error {
	own := map[Outcome]string{OutcomeAllow: "next", OutcomeAsk: "gaps", OutcomeDeny: "reasons"}[d.Outcome]
	if own == "" {
		return fmt.Errorf("unknown outcome %q", d.Outcome)
	}
	if d.Sends == "" {
		return fmt.Errorf("%s needs sends", d.Outcome)
	}
	for field, present := range map[string]bool{"next": d.Next != nil, "gaps": len(d.Gaps) != 0, "reasons": len(d.Reasons) != 0} {
		if present != (field == own) {
			return fmt.Errorf("%s must carry %s and no other outcome's fields", d.Outcome, own)
		}
	}
	return nil
}
