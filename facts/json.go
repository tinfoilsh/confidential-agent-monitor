package facts

import (
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
)

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

// Snapshot freezes one encoding into independent audit and policy views.
func (f Facts) Snapshot() (owned Facts, policy map[string]any, err error) {
	raw, err := f.MarshalJSON()
	if err == nil {
		err = DecodeNumbers(raw, &owned)
	}
	if err == nil {
		err = DecodeNumbers(raw, &policy)
	}
	owned.encoded = raw
	return
}

// Frozen facts retain the original JSON, including null interface values whose
// typed decoding would otherwise change omitempty behavior.
func (f Facts) MarshalJSON() ([]byte, error) {
	if f.encoded != nil {
		return f.encoded, nil
	}
	type plain Facts
	return json.Marshal(plain(f))
}
