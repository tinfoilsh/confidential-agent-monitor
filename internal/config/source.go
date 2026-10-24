package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
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
	if v == nil {
		v = map[string]any{}
	}
	return v, nil
}

func JSONValue(v any) (any, error) {
	switch x := v.(type) {
	case map[string]any:
		if literal, ok := x["$json"]; ok {
			s, ok := literal.(string)
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
			if out[k], err = JSONValue(val); err != nil {
				return nil, err
			}
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			var err error
			if out[i], err = JSONValue(val); err != nil {
				return nil, err
			}
		}
		return out, nil
	case time.Time, toml.LocalDate, toml.LocalTime, toml.LocalDateTime:
		return nil, errors.New("policy dates and times must be quoted strings")
	default:
		return v, nil
	}
}

// Change replaces or deletes one source value. Tables and rules retain
// their names; edits never reconstruct source from a derived configuration.
type Change struct {
	Path   []string `json:"path"`
	Value  any      `json:"value,omitempty"`
	Delete bool     `json:"delete,omitempty"`
}

// TOML has no null and cannot represent every JSON number exactly. A tagged JSON
// literal preserves those values. An object containing the reserved tag is itself
// escaped, so arbitrary request scopes and MCP schemas round-trip without loss.
func TOMLValue(v any) (any, error) {
	switch x := v.(type) {
	case nil:
		return map[string]any{"$json": "null"}, nil
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return n, nil
		}
		return map[string]any{"$json": x.String()}, nil
	case map[string]any:
		if _, reserved := x["$json"]; reserved {
			raw, err := json.Marshal(x)
			return map[string]any{"$json": string(raw)}, err
		}
		out := map[string]any{}
		for k, val := range x {
			var err error
			if out[k], err = TOMLValue(val); err != nil {
				return nil, err
			}
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			var err error
			if out[i], err = TOMLValue(val); err != nil {
				return nil, err
			}
		}
		return out, nil
	default:
		return v, nil
	}
}

func RenderTOML(v map[string]any) (string, error) {
	encoded, err := TOMLValue(v)
	if err != nil {
		return "", err
	}
	text, err := toml.Marshal(encoded)
	return string(text), err
}

// EditSource changes only the requested paths, preserving unrelated source text.
func EditSource(source string, changes []Change) (string, error) {
	doc, err := edit.Parse([]byte(source))
	if err != nil {
		return "", err
	}
	for _, change := range changes {
		if change.Delete {
			doc.Delete(change.Path)
			continue
		}
		if err := doc.Set(change.Path, change.Value); err != nil {
			doc.Delete(change.Path)
			if err := doc.Set(change.Path, change.Value); err != nil {
				return "", err
			}
		}
	}
	if len(doc.Bytes()) > maxPolicyBytes {
		return "", errors.New("policy source is too large")
	}
	return doc.String(), nil
}

// FragmentChanges sets each leaf of a TOML fragment, merging it into the source.
func FragmentChanges(v map[string]any, path []string) (changes []Change) {
	var tables []Change
	for _, key := range slices.Sorted(maps.Keys(v)) {
		at := append(slices.Clone(path), key)
		if table, ok := v[key].(map[string]any); ok && len(table) > 0 && table["$json"] == nil {
			tables = append(tables, FragmentChanges(table, at)...)
		} else {
			changes = append(changes, Change{Path: at, Value: v[key]})
		}
	}
	// A table's own keys come first so its header precedes its subtables'.
	return append(changes, tables...)
}
