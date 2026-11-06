package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"time"

	toml "github.com/pelletier/go-toml/v2"
	"github.com/pelletier/go-toml/v2/unstable/edit"
	"github.com/tinfoilsh/monitor/facts"
)

const maxPolicyBytes = 2 << 20

func ReadSource(source string) (map[string]any, error) {
	if len(source) > maxPolicyBytes {
		return nil, errors.New("policy source is too large")
	}
	var v map[string]any
	if err := toml.Unmarshal([]byte(source), &v); err != nil {
		return nil, fmt.Errorf("policy TOML: %w", err)
	}
	decoded, err := sourceValue(v, false)
	if err != nil {
		return nil, err
	}
	if decoded == nil {
		return nil, nil
	}
	v, ok := decoded.(map[string]any)
	if !ok {
		return nil, errors.New("policy source must be an object")
	}
	return v, nil
}

// Change replaces or deletes one source value without reconstructing unrelated text.
type Change struct {
	Path   []string `json:"path"`
	Value  any      `json:"value,omitempty"`
	Delete bool     `json:"delete,omitempty"`
}

// TOML has no null and cannot represent every JSON number exactly. A tagged JSON
// literal preserves those values. Objects using the tag are themselves escaped.
func sourceValue(v any, tomlValue bool) (any, error) {
	literal := func(value any) (any, error) {
		raw, err := json.Marshal(value)
		return map[string]any{"$json": string(raw)}, err
	}
	switch x := v.(type) {
	case nil:
		if tomlValue {
			return literal(nil)
		}
	case json.Number:
		if tomlValue {
			if n, err := x.Int64(); err == nil {
				return n, nil
			}
			return literal(x)
		}
	case map[string]any:
		if encoded, reserved := x["$json"]; reserved {
			if tomlValue {
				return literal(x)
			}
			s, ok := encoded.(string)
			if !ok || len(x) != 1 {
				return nil, errors.New("$json must be the only field of a JSON literal")
			}
			var val any
			err := facts.DecodeNumbers([]byte(s), &val)
			return val, err
		}
		out := map[string]any{}
		for k, val := range x {
			var err error
			if out[k], err = sourceValue(val, tomlValue); err != nil {
				return nil, err
			}
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			var err error
			if out[i], err = sourceValue(val, tomlValue); err != nil {
				return nil, err
			}
		}
		return out, nil
	case time.Time, toml.LocalDate, toml.LocalTime, toml.LocalDateTime:
		if !tomlValue {
			return nil, errors.New("policy dates and times must be quoted strings")
		}
	}
	return v, nil
}

func RenderTOML(v map[string]any) (string, error) {
	encoded, err := sourceValue(v, true)
	if err != nil {
		return "", err
	}
	text, err := toml.Marshal(encoded)
	return string(text), err
}

// EditSource accepts JSON values and preserves unrelated source text. Table
// replacements use headers instead of one inline line; literals stay indivisible.
func EditSource(source string, changes []Change) (string, error) {
	doc, err := edit.Parse([]byte(source))
	if err != nil {
		return "", err
	}
	for _, change := range changes {
		if len(change.Path) == 0 || change.Delete && change.Value != nil {
			return "", errors.New("an edit requires a path and a deletion cannot have a value")
		}
		if change.Delete {
			doc.Delete(change.Path)
			continue
		}
		change.Value, err = facts.JSON[any](change.Value)
		if err == nil {
			change.Value, err = sourceValue(change.Value, true)
		}
		if err != nil {
			return "", err
		}
		edits := []Change{change}
		if table, ok := change.Value.(map[string]any); ok && len(table) > 0 && table["$json"] == nil {
			doc.Delete(change.Path)
			edits = fragmentChanges(table, change.Path)
		}
		for _, field := range edits {
			if err := doc.Set(field.Path, field.Value); err != nil {
				doc.Delete(field.Path)
				if err := doc.Set(field.Path, field.Value); err != nil {
					return "", err
				}
			}
		}
	}
	if len(doc.Bytes()) > maxPolicyBytes {
		return "", errors.New("policy source is too large")
	}
	return doc.String(), nil
}

// EditSourceNormalized applies changes in order while omitting semantic no-ops.
// It preserves the current source text when the editor only changes formatting.
func EditSourceNormalized(source string, changes []Change) (string, []Change, error) {
	parse := func(source string) (map[string]any, error) {
		value, err := ReadSource(source)
		if err != nil {
			return nil, err
		}
		return facts.JSON[map[string]any](value)
	}
	candidate := source
	current, err := parse(candidate)
	if err != nil {
		return "", nil, err
	}
	normalized := make([]Change, 0, len(changes))
	for _, change := range changes {
		next, err := EditSource(candidate, []Change{change})
		if err != nil {
			return "", nil, err
		}
		parsed, err := parse(next)
		if err != nil {
			return "", nil, err
		}
		if reflect.DeepEqual(current, parsed) {
			continue
		}
		normalized = append(normalized, change)
		candidate, current = next, parsed
	}
	return candidate, normalized, nil
}

// Fragment converts a TOML proposal into the same JSON-valued edits as owner calls.
func Fragment(source string) ([]Change, error) {
	v, err := ReadSource(source)
	if err != nil {
		return nil, err
	}
	return fragmentChanges(v, nil), nil
}

// fragmentChanges sets each leaf of a fragment, merging it into the source.
func fragmentChanges(v map[string]any, path []string) (changes []Change) {
	var tables []Change
	for _, key := range slices.Sorted(maps.Keys(v)) {
		at := append(slices.Clone(path), key)
		if table, ok := v[key].(map[string]any); ok && len(table) > 0 && table["$json"] == nil {
			tables = append(tables, fragmentChanges(table, at)...)
		} else {
			changes = append(changes, Change{Path: at, Value: v[key]})
		}
	}
	// A table's own keys come first so its header precedes its subtables'.
	return append(changes, tables...)
}
