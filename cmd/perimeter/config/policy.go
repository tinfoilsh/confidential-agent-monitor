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
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/rego"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

const FactsVersion = 13

const (
	KindOperation   = "operation"
	KindAdmission   = "admission"
	SendsConnection = "connection"
)

type Obligations struct {
	Change    bool `json:"change"`
	Trust     bool `json:"trust"`
	Ask       bool `json:"ask"`
	Discloses bool `json:"discloses"`
}

var Vocabulary = map[string]Obligations{
	"read":     {},
	"session":  {},
	"write":    {Change: true, Trust: true},
	"generate": {Change: true, Trust: true},
	"delete":   {Change: true, Trust: true},
	"admin":    {Change: true, Trust: true},
	"execute":  {Change: true, Trust: true},
	"send":     {Change: true, Trust: true, Discloses: true},
	"share":    {Change: true, Trust: true, Discloses: true},
	"publish":  {Change: true, Trust: true, Ask: true, Discloses: true},
	"pay":      {Change: true, Trust: true, Ask: true},
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
	return len(effects) != 0 && !slices.ContainsFunc(effects, func(effect string) bool { _, ok := Vocabulary[effect]; return !ok })
}

const (
	standardModule = "perimeter/lib.rego"
	baseModule     = "perimeter/base.rego"
	QueryDecision  = "decision"
	QueryAdmin     = "admin"
	QueryCapable   = "capable"
)

var (
	policyQueries = map[string]string{QueryDecision: "data.perimeter.decision", QueryAdmin: "data.perimeter.admin_deny", QueryCapable: "data.perimeter.capable"}
	protectedData = []string{"perimeter", "lattices", "levels"}
	basePackage   = []string{"perimeter", "base"}
)

//go:embed lib.rego
var standardPolicy string

func PreparePolicy(ctx context.Context, cfg *Config, base string) (*rego.Program, error) {
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
	modules := map[string]string{standardModule: standardPolicy}
	if base != "" {
		path, err := rego.Package(baseModule, base)
		if err == nil && !slices.Equal(path, basePackage) {
			err = fmt.Errorf("the base policy must be package data.%s, not data.%s", strings.Join(basePackage, "."), strings.Join(path, "."))
		}
		if err != nil {
			return nil, err
		}
		modules[baseModule] = base
	}
	for _, name := range slices.Sorted(maps.Keys(cfg.Policies)) {
		filename := "policies/" + name
		path, err := rego.Package(filename, cfg.Policies[name])
		if err != nil {
			return nil, err
		}
		if slices.Contains(protectedData, path[0]) {
			return nil, fmt.Errorf("policy %s: data.%s is reserved for the Perimeter", name, path[0])
		}
		modules[filename] = cfg.Policies[name]
	}
	return rego.Prepare(ctx, modules, data, policyQueries)
}

type DecisionInput struct {
	Facts         json.RawMessage    `json:"facts"`
	Authorization AuthorizationInput `json:"authorization"`
	Connection    ConnectionInput    `json:"connection"`
}

type AuthorizationInput struct {
	Access             Access              `json:"access"`
	Reaches            bool                `json:"reaches"`
	Effects            []map[string]string `json:"effects"`
	AllowPaidInference bool                `json:"allow_paid_inference"`
	Rules              []Rule              `json:"rules"`
	Approved           []string            `json:"approved"`
	Scope              map[string]any      `json:"grant"`
}

type ConnectionInput struct {
	Contents    string   `json:"contents"`
	Strangers   bool     `json:"strangers"`
	Sends       string   `json:"sends"`
	Private     []string `json:"private"`
	PublicScope []string `json:"public_scope"`
}

type Decision struct {
	Deny         []string      `json:"deny"`
	Requirements []Requirement `json:"requirements"`
	Sends        string        `json:"sends"`
	Next         format.Label  `json:"next"`
}

type AdminCall struct {
	Caller PolicyCaller `json:"caller"`
	Route  string       `json:"route"`
	Answer any          `json:"answer,omitempty"`
	Record any          `json:"record,omitempty"`
}

type PolicyCaller struct {
	Name   string         `json:"name"`
	Owner  bool           `json:"owner"`
	Claims map[string]any `json:"claims"`
}

type CapabilityInput struct {
	Principal  facts.Principal `json:"principal"`
	Routes     bool            `json:"routes"`
	Capability string          `json:"capability"`
}
