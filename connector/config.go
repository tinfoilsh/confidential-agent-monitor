package connector

import (
	"bytes"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"math/big"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/facts"
)

func Decode(raw json.RawMessage, dst any) error {
	return jsonv2.Unmarshal(raw, dst, jsonv2.RejectUnknownMembers(true))
}

// DecodeNumbers keeps numbers as json.Number, so policy compares the values exactly as written.
func DecodeNumbers(raw []byte, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	dec.UseNumber()
	return dec.Decode(dst)
}

type Endpoint struct {
	url.URL  `json:"-"`
	Address  string           `json:"url"`
	User     string           `json:"user"`
	Password credential.Value `json:"password"`
}

func (e *Endpoint) Fields() []Field {
	return []Field{{Path: []string{"password"}, Value: &e.Password, Redact: true}}
}

func (e *Endpoint) UnmarshalJSON(raw []byte) error {
	type plain Endpoint
	if err := Decode(raw, (*plain)(e)); err != nil {
		return err
	}
	u, err := ParseURL(e.Address)
	if err != nil {
		return err
	}
	if e.User != "" {
		u.User = url.User(e.User)
	}
	e.URL = *u
	return nil
}

// Field identifies a config path and its disclosure metadata.
// Value points to the live credential, or is nil for plain strings such as keys.
type Field struct {
	Path   []string
	Value  *credential.Value
	Redact bool
}

// JSONSelector selects a typed value from a JSON document.
type JSONSelector struct {
	At       string `json:"at"`
	Type     string `json:"type,omitempty"`
	Optional bool   `json:"optional,omitempty"`
	read     func(any) (any, bool)
}

func (s JSONSelector) Validate() error {
	if !ValidJSONType(s.Type) {
		return fmt.Errorf("invalid selector type %q", s.Type)
	}
	if !ValidJSONPointer(s.At) {
		return fmt.Errorf("invalid selector path %q", s.At)
	}
	return nil
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

func SelectJSON(doc any, selectors map[string]JSONSelector) (map[string]any, error) {
	out := make(map[string]any, len(selectors))
	var errs []error
	for _, name := range slices.Sorted(maps.Keys(selectors)) {
		spec := selectors[name]
		value, present := spec.Read(doc)
		if err := CheckSelection(name, value, present, spec.Type, spec.Optional); err != nil {
			errs = append(errs, err)
		} else if present {
			out[name] = value
		}
	}
	return out, errors.Join(errs...)
}

func (s JSONSelector) Compile() (JSONSelector, error) {
	if err := s.Validate(); err != nil {
		return s, err
	}
	var err error
	s.read, err = CompilePointer(s.At)
	return s, err
}

func (s JSONSelector) Read(doc any) (any, bool) {
	if s.read != nil {
		return s.read(doc)
	}
	return JSONPointer(doc, s.At)
}

// Project selects the parameter values bound to a saved approval. Nil means
// all parameters; an explicitly empty selection stays empty.
func Project(parameters map[string]any, names []string) map[string]any {
	if names == nil {
		return nil
	}
	out := make(map[string]any, len(names))
	for _, name := range names {
		if value, ok := parameters[name]; ok {
			out[name] = value
		}
	}
	return out
}

// ValidJSONPointer checks the supported pointer syntax, which excludes escapes.
func ValidJSONPointer(at string) bool {
	return at == "" || strings.HasPrefix(at, "/") && !strings.Contains(at, "~")
}

func JSONPointer(doc any, at string) (any, bool) {
	read, err := CompilePointer(at)
	if err != nil {
		return nil, false
	}
	return read(doc)
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
		case map[string][]string:
			value, ok := v[s]
			if !ok {
				return nil, false
			}
			doc = value
		case []string:
			i, err := strconv.Atoi(s)
			if err != nil || strconv.Itoa(i) != s || i < 0 || i >= len(v) {
				return nil, false
			}
			doc = v[i]
		default:
			return nil, false
		}
	}
	// Typed protocol maps and slices represent JSON null when nil.
	switch value := doc.(type) {
	case map[string]any:
		if value == nil {
			doc = nil
		}
	case map[string][]string:
		if value == nil {
			doc = nil
		}
	case []any:
		if value == nil {
			doc = nil
		}
	case []string:
		if value == nil {
			doc = nil
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
	case json.Number, float64, int, int64:
		return "number"
	case []any, []string:
		return "array"
	case map[string]any, map[string][]string, *facts.HTTP:
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

func JSONFields(v any) map[string]any {
	v, _ = facts.CloneJSON(v)
	m, _ := v.(map[string]any)
	return m
}

func (c Context) DecodeConfig(dst any) error {
	if len(c.Config) == 0 {
		return nil
	}
	return json.Unmarshal(c.Config, dst)
}

func (c Context) DecodeOptions(dst any) error {
	if len(c.Options) == 0 {
		return nil
	}
	return json.Unmarshal(c.Options, dst)
}
