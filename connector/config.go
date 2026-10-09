package connector

import (
	"context"
	"encoding/json"
	"fmt"
	"math/big"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/facts"
)

type Endpoint struct {
	SecretConfig
	url.URL `json:"-"`
	Address string `json:"url"`
	User    string `json:"user"`
}

func (e *Endpoint) UnmarshalJSON(raw []byte) error {
	type plain Endpoint
	if err := facts.DecodeNumbers(raw, (*plain)(e)); err != nil {
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

// SecretConfig owns the credential handles shared with the connection runtime.
type SecretConfig struct {
	Secrets map[string]*credential.Value `json:"secrets,omitempty"`
}

func (c *SecretConfig) SecretValues() map[string]*credential.Value {
	if c.Secrets == nil {
		c.Secrets = map[string]*credential.Value{}
	}
	return c.Secrets
}

// Secret returns an empty value for optional, unconfigured authentication.
func (c *SecretConfig) Secret(ctx context.Context, name string) (string, error) {
	if value := c.Secrets[name]; value != nil {
		return value.Value(ctx)
	}
	return "", nil
}
