// Package presets exposes opaque preset sources and their setup/control metadata.
package presets

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"

	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

//go:embed *.json
var Files embed.FS

// A Preset contains reviewed protocol definitions and connection setup metadata.
type Preset struct {
	Title       string          `json:"title"`
	Catalog     *Catalog        `json:"catalog"`
	PublicScope []string        `json:"public_scope,omitempty"`
	Source      json.RawMessage `json:"-"`
}

type Catalog struct {
	Group      string                     `json:"group,omitempty"`
	Warning    string                     `json:"warning,omitempty"`
	ReplacedBy string                     `json:"replaced_by,omitempty"`
	Actions    map[string]facts.Action    `json:"actions,omitempty"`
	Connection map[string]json.RawMessage `json:"connection,omitempty"`
	Defaults   json.RawMessage            `json:"defaults,omitempty"`
	Fields     []json.RawMessage          `json:"fields,omitempty"`
}

// MarshalJSON preserves protocol definitions without catalog-owned decoding.
func (p Preset) MarshalJSON() ([]byte, error) { return p.Source, nil }

func Decode(raw []byte, vocabulary facts.Vocabulary) (*Preset, error) {
	p := Preset{Source: raw}
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	if p.Catalog == nil || p.Catalog.Defaults == nil {
		return nil, fmt.Errorf("catalog must be an object with defaults")
	}
	for name, a := range p.Catalog.Actions {
		if a.Effects != nil && !vocabulary.ValidEffects(a.Effects) {
			return nil, fmt.Errorf("invalid effects for action %s", name)
		}
	}
	return &p, nil
}

type Set map[string]*Preset

func (s Set) Lookup(name string) (*Preset, error) {
	if preset := s[name]; preset != nil {
		return preset, nil
	}
	return nil, fmt.Errorf("unknown preset %s", name)
}

func Load(vocabulary facts.Vocabulary, sources ...fs.FS) (Set, error) {
	out := Set{}
	for _, source := range sources {
		if source == nil {
			continue
		}
		files, _ := fs.Glob(source, "*.json")
		for _, file := range files {
			name := strings.TrimSuffix(file, ".json")
			if out[name] != nil {
				return nil, fmt.Errorf("preset %s is already shipped", file)
			}
			src, err := fs.ReadFile(source, file)
			if err == nil {
				out[name], err = Decode(src, vocabulary)
			}
			if err != nil {
				return nil, fmt.Errorf("preset %s: %w", file, err)
			}
		}
	}
	return out, nil
}

// Entry is the owner's catalog presentation. Operations are display metadata;
// their protocol definitions remain opaque until a connector decodes them.
type Entry struct {
	*Catalog
	Title      string                             `json:"title"`
	Operations *map[string]facts.OperationSummary `json:"operations,omitempty"`
}

func (p *Preset) Entry(used bool, operations map[string]facts.OperationSummary) Entry {
	metadata := *p.Catalog
	entry := Entry{Catalog: &metadata, Title: p.Title}
	if !used {
		metadata.Actions = nil
	} else if operations != nil {
		entry.Operations = &operations
	}
	return entry
}
