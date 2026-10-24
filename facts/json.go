package facts

import (
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"math/big"
	"reflect"
	"slices"
	"strconv"
	"strings"
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

func ValidJSONType(typ string) bool {
	return slices.Contains([]string{"", "string", "number", "boolean", "object", "array", "null"}, typ)
}

// CheckSelection validates an extracted value. Optional permits absence, never a wrong type.
func CheckSelection(name string, value any, present bool, typ string, optional bool) error {
	if typ == "" {
		typ = "string"
	}
	if present && JSONType(value) == typ || !present && optional {
		return nil
	}
	return fmt.Errorf("the request has no %s of the expected type", name)
}

// ValidJSONPointer checks the supported pointer syntax, which excludes escapes.
func ValidJSONPointer(at string) bool {
	return at == "" || strings.HasPrefix(at, "/") && !strings.Contains(at, "~")
}

func CompilePointer(at string) (func(any) (any, bool), error) {
	if !ValidJSONPointer(at) {
		return nil, fmt.Errorf("invalid selector path %q", at)
	}
	var parts []string
	if at != "" {
		parts = strings.Split(at[1:], "/")
	}
	return func(doc any) (any, bool) { return lookupJSON(doc, parts) }, nil
}

func lookupJSON(doc any, parts []string) (any, bool) {
	for _, s := range parts {
		switch v := doc.(type) {
		case map[string]any:
			var ok bool
			doc, ok = v[s]
			if !ok {
				return nil, false
			}
		case []any:
			i, err := strconv.Atoi(s)
			if err != nil || strconv.Itoa(i) != s || i < 0 || i >= len(v) {
				return nil, false
			}
			doc = v[i]
		default:
			return nil, false
		}
	}
	return doc, true
}

func JSONType(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case string:
		return "string"
	case bool:
		return "boolean"
	case json.Number:
		return "number"
	case []any:
		return "array"
	case map[string]any, map[string][]string:
		return "object"
	}
	return ""
}

// EqualJSON compares values decoded with DecodeNumbers, including exact decimal
// equality across different spellings such as 1, 1.0 and 1e0.
func EqualJSON(a, b any) bool {
	switch x := a.(type) {
	case json.Number:
		y, ok := b.(json.Number)
		if !ok {
			return false
		}
		xDigits, xExponent := decimalParts(x)
		yDigits, yExponent := decimalParts(y)
		return xDigits == yDigits && xExponent.Cmp(yExponent) == 0
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for key, value := range x {
			other, present := y[key]
			if !present || !EqualJSON(value, other) {
				return false
			}
		}
		return true
	case []any:
		y, ok := b.([]any)
		return ok && slices.EqualFunc(x, y, EqualJSON)
	default:
		return reflect.DeepEqual(a, b)
	}
}

// decimalParts normalizes a decoded JSON number without expanding its exponent.
// Even very large exponents use space proportional to their written length.
func decimalParts(n json.Number) (string, *big.Int) {
	mantissa, exponent, _ := strings.Cut(strings.ToLower(string(n)), "e")
	mantissa, negative := strings.CutPrefix(mantissa, "-")
	whole, fraction, _ := strings.Cut(mantissa, ".")
	digits := strings.TrimLeft(whole+fraction, "0")
	coefficient := strings.TrimRight(digits, "0")
	power := new(big.Int)
	if coefficient == "" {
		return "0", power
	}
	if exponent != "" {
		power.SetString(exponent, 10)
	}
	power.Add(power, big.NewInt(int64(len(digits)-len(coefficient)-len(fraction))))
	if negative {
		coefficient = "-" + coefficient
	}
	return coefficient, power
}
