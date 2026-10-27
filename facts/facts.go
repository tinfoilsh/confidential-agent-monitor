// Package facts defines the request data shared by connectors, policy, and audit.
package facts

import (
	"cmp"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"slices"
	"strings"
)

// Version identifies the facts schema and approval semantics. Bump it when
// parsing, description, normalization, label, or approval semantics change.
// This invalidates saved approvals; display-only edits do not need a bump.
const Version = 11

// Label levels are ordered from most restrictive to least restrictive.
// Policy derives its rank tables from these same lists.
var (
	Audiences = []string{"me", "team", "anyone"}
	Trusts    = []string{"untrusted", "trusted"}
)

type Kind string

const (
	KindOperation Kind = "operation"
	KindAdmission Kind = "admission"
)

type Principal struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

type Label struct {
	Audience string            `json:"audience"`
	Trust    string            `json:"trust"`
	Because  map[string]string `json:"because,omitempty"`
}

func (l Label) Valid() bool {
	return slices.Contains(Audiences, l.Audience) && slices.Contains(Trusts, l.Trust)
}

func ValidSends(sends string) bool {
	return sends == "" || sends == "account" || slices.Contains(Audiences, sends)
}

type Operation struct {
	ID      string   `json:"id"`
	Action  string   `json:"action"`
	Effects []string `json:"effects"`
	Lineage []string `json:"lineage"`
}

type Action struct {
	Title   string   `json:"title"`
	Effects []string `json:"effects,omitempty"`
}

type Requirement struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}

// Resolve binds an operation to its nearest configured action semantics.
func (op Operation) Resolve(actions map[string]Action) *Operation {
	op.Lineage = nil
	for action := op.Action; action != ""; {
		op.Lineage = append(op.Lineage, action)
		i := strings.LastIndexByte(action, '.')
		if i < 0 {
			break
		}
		action = action[:i]
	}
	effects := op.Effects
	for i := 0; effects == nil && i < len(op.Lineage); i++ {
		effects = actions[op.Lineage[i]].Effects
	}
	if op.Action == "" || effects == nil {
		return nil
	}
	op.Effects, op.ID = slices.Compact(slices.Sorted(slices.Values(effects))), cmp.Or(op.ID, op.Action)
	return &op
}

// Sends and Observes are connector hints; policy resolves them with account settings.
type Context struct {
	Label    Label  `json:"label"`
	Sends    string `json:"sends"`
	Observes Label  `json:"observes"`
}

// Facts is the snapshot shared by authorization and audit.
// Protocol details use typed fields; service parameters remain JSON values.
type Facts struct {
	Scope      map[string]any `json:"-"`
	Definition any            `json:"-"`
	Version    int            `json:"version"`
	Kind       Kind           `json:"kind"`
	Principal  Principal      `json:"principal"`
	Account    string         `json:"account"`
	Service    string         `json:"service"`
	Connection string         `json:"connection"`
	Operation  *Operation     `json:"operation"`
	Parameters map[string]any `json:"parameters"`
	Context    Context        `json:"context"`
	Title      string         `json:"title"`
	Details    any            `json:"details"`
}

// PolicyDiff is an agent proposal to change the owner source.
type PolicyDiff struct {
	SourceDiff    string `json:"source_diff"`
	EffectiveDiff string `json:"effective_diff"`
}

// Obligations describes the requirements carried by an effect.
type Obligations struct {
	Change    bool `json:"change"`
	Trust     bool `json:"trust"`
	Ask       bool `json:"ask"` // Default effect setting; owners may override it.
	Discloses bool `json:"discloses"`
}

// Effects is shared by preset validation, request descriptions, policy, and UI.
var Effects = map[string]Obligations{
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

func ValidEffects(effects []string) bool {
	if len(effects) == 0 {
		return false
	}
	for _, effect := range effects {
		if _, ok := Effects[effect]; !ok {
			return false
		}
	}
	return true
}

// JSON converts through the same encoding used for audit, preserving numbers.
func JSON[T any](value any) (out T, err error) {
	raw, err := json.Marshal(value)
	if err == nil {
		err = DecodeNumbers(raw, &out)
	}
	return
}

// DecodeNumbers keeps numbers as json.Number, so policy compares the values exactly as written.
func DecodeNumbers(raw []byte, dst any) error {
	return jsonv2.Unmarshal(raw, dst, jsonv2.RejectUnknownMembers(true), json.MergeWithLegacySemantics(true), jsonv2.WithUnmarshalers(jsonv2.UnmarshalFromFunc(func(dec *jsontext.Decoder, value *any) error {
		if dec.PeekKind() != '0' {
			return errors.ErrUnsupported
		}
		raw, err := dec.ReadValue()
		if err == nil {
			*value = json.Number(raw)
		}
		return err
	})))
}

// Encode freezes host-enriched facts for audit and produces the same values for
// policy. The record keeps the bytes; it does not need another typed copy.
func Encode(f Facts) (raw json.RawMessage, policy map[string]any, err error) {
	raw, err = json.Marshal(f)
	if err == nil {
		err = DecodeNumbers(raw, &policy)
	}
	return
}
