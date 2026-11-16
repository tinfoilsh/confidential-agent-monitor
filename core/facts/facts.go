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

func (p Principal) Same(q Principal) bool { return p.Key == q.Key && p.Name == q.Name }

type Operation struct {
	ID      string   `json:"id"`
	Action  string   `json:"action"`
	Effects []string `json:"effects"`
}

type Observation struct {
	Operation  *Operation     `json:"operation"`
	Parameters map[string]any `json:"parameters"`
	Scope      map[string]any `json:"scope"`
	Title      string         `json:"title"`
	Details    any            `json:"details"`
}

func JSON[T any](value any) (out T, err error) {
	raw, err := json.Marshal(value)
	if err == nil {
		err = DecodeNumbers(raw, &out)
	}
	return
}

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
