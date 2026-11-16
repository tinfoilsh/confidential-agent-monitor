// Package facts defines the observations connectors capture and the JSON they are compared in.
package facts

import (
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
)

type Principal struct {
	Key        string                     `json:"key"`
	Name       string                     `json:"name"`
	Groups     []string                   `json:"groups,omitempty"`
	Attributes map[string]json.RawMessage `json:"attributes,omitempty"`
}

// Same reports whether p and q are one identity, whatever their groups.
func (p Principal) Same(q Principal) bool { return p.Key == q.Key && p.Name == q.Name }

// Operation is what a protocol recognized. Effects are only those a protocol description declares.
type Operation struct {
	ID      string   `json:"id"`
	Action  string   `json:"action"`
	Effects []string `json:"effects"`
}

// Observation is one captured protocol operation, exactly as the connector executes it.
type Observation struct {
	Operation  *Operation     `json:"operation"`
	Parameters map[string]any `json:"parameters"`
	// Scope is the selection of parameters a protocol description names, as captured; nil when it names none.
	Scope   map[string]any `json:"scope"`
	Title   string         `json:"title"`
	Details any            `json:"details"`
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
