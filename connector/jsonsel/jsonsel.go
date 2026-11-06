// Package jsonsel selects and compares typed values in decoded JSON documents.
package jsonsel

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

// Selector selects a typed value from a JSON document.
type Selector struct {
	At       string `json:"at"`
	Type     string `json:"type,omitempty"`
	Optional bool   `json:"optional,omitempty"`
}

func (s Selector) Valid() bool {
	return slices.Contains([]string{"", "string", "number", "boolean", "object", "array", "null"}, s.Type)
}

// Check validates an extracted value. Optional permits absence, never a wrong type.
func (s Selector) Check(name string, value any, present bool) error {
	typ := s.Type
	if typ == "" {
		typ = "string"
	}
	if present && jsonType(value) == typ || !present && s.Optional {
		return nil
	}
	return fmt.Errorf("the request has no %s of the expected type", name)
}

type Source interface {
	Compile() (Selector, func(any) (any, bool), error)
}

func (s Selector) Compile() (Selector, func(any) (any, bool), error) {
	if !s.Valid() {
		return s, nil, fmt.Errorf("invalid selector type %q", s.Type)
	}
	read, err := CompilePointer(s.At)
	return s, read, err
}

type Compiled struct {
	Selector
	name string
	read func(any) (any, bool)
}

func Compile[S Source](specs map[string]S) ([]Compiled, error) {
	out := make([]Compiled, 0, len(specs))
	for _, name := range slices.Sorted(maps.Keys(specs)) {
		selector, read, err := specs[name].Compile()
		if err != nil {
			return nil, err
		}
		out = append(out, Compiled{selector, name, read})
	}
	return out, nil
}

func Select(selectors []Compiled, doc any) (map[string]any, error) {
	out := make(map[string]any, len(selectors))
	var errs []error
	for _, s := range selectors {
		value, present := s.read(doc)
		if err := s.Check(s.name, value, present); err != nil {
			errs = append(errs, err)
		} else if present {
			out[s.name] = value
		}
	}
	return out, errors.Join(errs...)
}

// validJSONPointer checks the supported pointer syntax, which excludes escapes.
func validJSONPointer(at string) bool {
	return at == "" || strings.HasPrefix(at, "/") && !strings.Contains(at, "~")
}

func CompilePointer(at string) (func(any) (any, bool), error) {
	if !validJSONPointer(at) {
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

func jsonType(v any) string {
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
	case map[string]any:
		return "object"
	}
	return ""
}

// Equal compares values decoded with facts.DecodeNumbers, including exact decimal
// equality across different spellings such as 1, 1.0 and 1e0.
func Equal(a, b any) bool {
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
			if !present || !Equal(value, other) {
				return false
			}
		}
		return true
	case []any:
		y, ok := b.([]any)
		return ok && slices.EqualFunc(x, y, Equal)
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
