package catalog

import (
	"bytes"
	"cmp"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"regexp"
	"slices"
	"strings"
)

//go:embed presets/*.json
var embedded embed.FS

var Shipped, _ = fs.Sub(embedded, "presets")

var fragmentKey = regexp.MustCompile(`\A[a-z][a-z0-9_]*\z`)

type Preset struct {
	Title       string            `json:"title"`
	Catalog     *Catalog          `json:"catalog"`
	PublicScope []string          `json:"public_scope,omitempty"`
	Fragments   map[string]string `json:"fragments,omitempty"`
	HTTP        struct {
		Operations map[string]OperationSummary `json:"operations"`
	} `json:"http"`
	Source json.RawMessage `json:"-"`
}

type Catalog struct {
	Group      string                     `json:"group,omitempty"`
	Warning    string                     `json:"warning,omitempty"`
	ReplacedBy string                     `json:"replaced_by,omitempty"`
	Actions    map[string]Action          `json:"actions,omitempty"`
	Connection map[string]json.RawMessage `json:"connection,omitempty"`
	Defaults   json.RawMessage            `json:"defaults,omitempty"`
	Fields     []json.RawMessage          `json:"fields,omitempty"`
}

type OperationSummary struct {
	Action  string   `json:"action"`
	Effects []string `json:"effects,omitempty"`
}

type Action struct {
	Title   string   `json:"title"`
	Effects []string `json:"effects,omitempty"`
}

func (p Preset) MarshalJSON() ([]byte, error) { return p.Source, nil }

func Decode(raw []byte) (*Preset, error) {
	p := Preset{Source: raw}
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	if p.Catalog == nil {
		return nil, errors.New("catalog must be an object")
	}
	return &p, nil
}

func Load(source fs.FS) (map[string]*Preset, error) {
	presets := map[string]*Preset{}
	files, _ := fs.Glob(source, "*.json")
	for _, file := range files {
		raw, err := fs.ReadFile(source, file)
		if err == nil {
			presets[strings.TrimSuffix(file, ".json")], err = Decode(raw)
		}
		if err != nil {
			return nil, fmt.Errorf("preset %s: %w", file, err)
		}
	}
	return presets, nil
}

// File is a directory of presets as the one catalog file a policy lists under its SHA-256.
func File(source fs.FS) ([]byte, error) {
	files, _ := fs.Glob(source, "*.json")
	if len(files) == 0 {
		return nil, errors.New("no presets")
	}
	presets := map[string]json.RawMessage{}
	for _, file := range files {
		raw, err := fs.ReadFile(source, file)
		if err != nil {
			return nil, err
		}
		presets[strings.TrimSuffix(file, ".json")] = raw
	}
	var out bytes.Buffer
	err := json.NewEncoder(&out).Encode(presets)
	return out.Bytes(), err
}

type composite struct {
	Catalog struct {
		Actions map[string]json.RawMessage `json:"actions,omitempty"`
		Rest    map[string]json.RawMessage `json:",embed"`
	} `json:"catalog"`
	HTTP struct {
		Operations     map[string]compositeOperation `json:"operations,omitempty"`
		Origins        map[string]json.RawMessage    `json:"origins,omitempty"`
		SensitiveQuery []string                      `json:"sensitive_query,omitempty"`
		Rest           map[string]json.RawMessage    `json:",embed"`
	} `json:"http"`
	PublicScope []string                   `json:"public_scope,omitempty"`
	Fragments   map[string]string          `json:"fragments,omitempty"`
	Rest        map[string]json.RawMessage `json:",embed"`
}

type compositeOperation struct {
	Action string                     `json:"action"`
	Origin string                     `json:"origin"`
	Rest   map[string]json.RawMessage `json:",embed"`
}

func Compose(presets map[string]*Preset) error {
	composed := map[string]*Preset{}
	for name, p := range presets {
		if len(p.Fragments) == 0 {
			continue
		}
		var err error
		if composed[name], err = compose(p, presets); err != nil {
			return fmt.Errorf("preset %s: %w", name, err)
		}
	}
	maps.Copy(presets, composed)
	return nil
}

func compose(provider *Preset, presets map[string]*Preset) (*Preset, error) {
	var c composite
	if err := json.Unmarshal(provider.Source, &c); err != nil {
		return nil, err
	}
	actions, operations, origins := map[string]json.RawMessage{}, map[string]compositeOperation{}, map[string]json.RawMessage{}
	for key, name := range c.Fragments {
		fragment, f := presets[name], composite{}
		if fragment == nil || !fragmentKey.MatchString(key) || json.Unmarshal(fragment.Source, &f) != nil || len(f.Fragments) != 0 || len(f.HTTP.Operations) == 0 || len(f.PublicScope) != 0 {
			return nil, fmt.Errorf("fragment %s must name a preset with HTTP operations, no fragments and no public scope under a lowercase key", key)
		}
		rename := func(action string) string {
			if action == key || strings.HasPrefix(action, key+".") {
				return action
			}
			return key + "." + action
		}
		set := func(name string) string {
			if name == "origin" {
				return key
			}
			return key + "." + name
		}
		actions[key], _ = json.Marshal(Action{Title: strings.TrimPrefix(fragment.Title, provider.Title+" ")})
		for action, raw := range f.Catalog.Actions {
			action = rename(action)
			if _, dup := actions[action]; dup && action != key {
				return nil, fmt.Errorf("fragment %s defines action %s twice", key, action)
			}
			actions[action] = raw
		}
		for id, o := range f.HTTP.Operations {
			if ref := strings.Trim(o.Origin, "{}"); "{"+ref+"}" == o.Origin {
				if _, defined := f.HTTP.Origins[ref]; !defined {
					return nil, fmt.Errorf("fragment %s operation %s uses undefined origin set %s", key, id, ref)
				}
				o.Origin = "{" + set(ref) + "}"
			}
			o.Action = rename(o.Action)
			operations[key+"."+id] = o
		}
		for name, hosts := range f.HTTP.Origins {
			origins[set(name)] = hosts
		}
		c.HTTP.SensitiveQuery = append(c.HTTP.SensitiveQuery, f.HTTP.SensitiveQuery...)
	}
	if err := errors.Join(merge(actions, c.Catalog.Actions), merge(operations, c.HTTP.Operations), merge(origins, c.HTTP.Origins)); err != nil {
		return nil, err
	}
	c.Catalog.Actions, c.HTTP.Operations, c.HTTP.Origins = actions, operations, origins
	c.HTTP.SensitiveQuery = slices.Compact(slices.Sorted(slices.Values(c.HTTP.SensitiveQuery)))
	c.Fragments = nil
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	return Decode(raw)
}

func merge[V any](into, from map[string]V) error {
	for name, value := range from {
		if _, dup := into[name]; dup {
			return fmt.Errorf("%s is defined by both the preset and a fragment", name)
		}
		into[name] = value
	}
	return nil
}

type Operation struct {
	ID      string   `json:"id"`
	Action  string   `json:"action"`
	Effects []string `json:"effects"`
	Lineage []string `json:"lineage"`
}

// Lineage is an action and each of its dotted prefixes, longest first.
func Lineage(action string) []string {
	var lineage []string
	for a := action; a != ""; {
		lineage = append(lineage, a)
		i := strings.LastIndexByte(a, '.')
		if i < 0 {
			break
		}
		a = a[:i]
	}
	return lineage
}

func (c *Catalog) Resolve(id, action string, effects []string) *Operation {
	op := Operation{ID: id, Action: action, Lineage: Lineage(action)}
	for i := 0; effects == nil && i < len(op.Lineage); i++ {
		effects = c.Actions[op.Lineage[i]].Effects
	}
	if op.Action == "" || effects == nil {
		return nil
	}
	op.Effects, op.ID = slices.Compact(slices.Sorted(slices.Values(effects))), cmp.Or(op.ID, op.Action)
	return &op
}
