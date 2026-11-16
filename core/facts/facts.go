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
const Version = 13

type Kind string

const (
	KindOperation Kind = "operation"
	KindAdmission Kind = "admission"
)

type Principal struct {
	Key        string                     `json:"key"`
	Name       string                     `json:"name"`
	Groups     []string                   `json:"groups,omitempty"`
	Attributes map[string]json.RawMessage `json:"attributes,omitempty"`
}

// Same reports whether p and q are one identity, whatever their groups.
func (p Principal) Same(q Principal) bool { return p.Key == q.Key && p.Name == q.Name }

type Label struct {
	Audience string            `json:"audience"`
	Trust    string            `json:"trust"`
	Because  map[string]string `json:"because,omitempty"`
}

// SendsConnection resolves to the connection's configured audience; lib.rego matches the same value.
const SendsConnection = "connection"

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

// Sends and Observes are connector hints; policy resolves them with connection settings.
type Context struct {
	Label    Label  `json:"label"`
	Sends    string `json:"sends"`
	Observes Label  `json:"observes"`
}

// Facts is the snapshot shared by authorization and audit.
// Protocol details use typed fields; service parameters remain JSON values.
type Facts struct {
	Scope      map[string]any `json:"-"`
	Version    int            `json:"version"`
	Kind       Kind           `json:"kind"`
	Principal  Principal      `json:"principal"`
	Service    string         `json:"service"`
	Connection string         `json:"connection"`
	Operation  *Operation     `json:"operation"`
	Parameters map[string]any `json:"parameters"`
	Context    Context        `json:"context"`
	Title      string         `json:"title"`
	Details    any            `json:"details"`
}

// Obligations describes the requirements carried by an effect.
type Obligations struct {
	Change    bool `json:"change"`
	Trust     bool `json:"trust"`
	Ask       bool `json:"ask"` // Default effect setting; owners may override it.
	Discloses bool `json:"discloses"`
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
