package tomledit

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"time"

	toml "github.com/pelletier/go-toml/v2"
	"github.com/pelletier/go-toml/v2/unstable/edit"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

func Read(source string) (map[string]any, error) {
	var v map[string]any
	if err := toml.Unmarshal([]byte(source), &v); err != nil {
		return nil, fmt.Errorf("policy TOML: %w", err)
	}
	decoded, err := fromTOML(v)
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

type Change struct {
	Path   []string `json:"path"`
	Value  any      `json:"value,omitempty"`
	Delete bool     `json:"delete,omitempty"`
	From   []string `json:"from,omitempty"`
}

const jsonLiteral = "$json"

func literal(value any) (any, error) {
	raw, err := json.Marshal(value)
	return map[string]any{jsonLiteral: string(raw)}, err
}

func mapValues(v any, convert func(any) (any, error)) (any, error) {
	switch x := v.(type) {
	case map[string]any:
		out := map[string]any{}
		for k, val := range x {
			var err error
			if out[k], err = convert(val); err != nil {
				return nil, err
			}
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			var err error
			if out[i], err = convert(val); err != nil {
				return nil, err
			}
		}
		return out, nil
	}
	return v, nil
}

func fromTOML(v any) (any, error) {
	switch x := v.(type) {
	case map[string]any:
		if encoded, reserved := x[jsonLiteral]; reserved {
			s, ok := encoded.(string)
			if !ok || len(x) != 1 {
				return nil, errors.New("$json must be the only field of a JSON literal")
			}
			var val any
			err := facts.DecodeNumbers([]byte(s), &val)
			return val, err
		}
	case time.Time, toml.LocalDate, toml.LocalTime, toml.LocalDateTime:
		return nil, errors.New("policy dates and times must be quoted strings")
	}
	return mapValues(v, fromTOML)
}

func toTOML(v any) (any, error) {
	switch x := v.(type) {
	case nil:
		return literal(nil)
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return n, nil
		}
		return literal(x)
	case map[string]any:
		if _, reserved := x[jsonLiteral]; reserved {
			return literal(x)
		}
	}
	return mapValues(v, toTOML)
}

func Render(v map[string]any) (string, error) {
	encoded, err := toTOML(v)
	if err != nil {
		return "", err
	}
	text, err := toml.Marshal(encoded)
	return string(text), err
}

func Edit(source string, changes []Change) (string, error) {
	doc, err := edit.Parse([]byte(source))
	if err != nil {
		return "", err
	}
	for _, change := range changes {
		switch {
		case len(change.Path) == 0 || change.Delete && change.Value != nil || change.From != nil && (change.Delete || change.Value != nil):
			return "", errors.New("an edit requires a path and only one of a value, a deletion or a move")
		case change.Delete:
			doc.Delete(change.Path)
			continue
		case change.From != nil:
			moved, ok := doc.Get(change.From)
			if !ok {
				continue
			}
			doc.Delete(change.From)
			change.Value = moved
		default:
			change.Value, err = facts.JSON[any](change.Value)
			if err == nil {
				change.Value, err = toTOML(change.Value)
			}
			if err != nil {
				return "", err
			}
		}
		edits := []Change{change}
		if table, ok := change.Value.(map[string]any); ok && len(table) > 0 && table[jsonLiteral] == nil {
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
	return doc.String(), nil
}

func Fragment(source string) ([]Change, error) {
	v, err := Read(source)
	if err != nil {
		return nil, err
	}
	return fragmentChanges(v, nil), nil
}

func fragmentChanges(v map[string]any, path []string) (changes []Change) {
	var tables []Change
	for _, key := range slices.Sorted(maps.Keys(v)) {
		at := append(slices.Clone(path), key)
		if table, ok := v[key].(map[string]any); ok && len(table) > 0 && table[jsonLiteral] == nil {
			tables = append(tables, fragmentChanges(table, at)...)
		} else {
			changes = append(changes, Change{Path: at, Value: v[key]})
		}
	}
	return append(changes, tables...)
}
