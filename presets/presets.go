// Package presets exposes opaque preset sources and their setup/control metadata.
package presets

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
	"sync"

	"github.com/tinfoilsh/monitor/facts"
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

func Decode(raw []byte) (*Preset, error) {
	p := Preset{Source: raw}
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, err
	}
	if p.Catalog == nil || p.Catalog.Defaults == nil {
		return nil, fmt.Errorf("catalog must be an object with defaults")
	}
	for name, a := range p.Catalog.Actions {
		if a.Effects != nil && !facts.ValidEffects(a.Effects) {
			return nil, fmt.Errorf("invalid effects for action %s", name)
		}
	}
	return &p, nil
}

func Lookup(name string) (*Preset, error) {
	shipped, err := Shipped()
	if err != nil {
		return nil, err
	}
	if preset := shipped[name]; preset != nil {
		return preset, nil
	}
	return nil, fmt.Errorf("unknown preset %s", name)
}

var Shipped = sync.OnceValues(func() (map[string]*Preset, error) {
	out := map[string]*Preset{}
	files, _ := fs.Glob(Files, "*.json")
	for _, file := range files {
		name := strings.TrimSuffix(file, ".json")
		src, err := fs.ReadFile(Files, file)
		if err == nil {
			out[name], err = Decode(src)
		}
		if err != nil {
			return nil, fmt.Errorf("preset %s: %w", file, err)
		}
	}
	return out, nil
})

// Entry is the owner's catalog presentation. Operations are display metadata;
// their protocol definitions remain opaque until a connector decodes them.
type Entry struct {
	*Catalog
	Title      string                `json:"title"`
	Operations *map[string]Operation `json:"operations,omitempty"`
}

type Operation struct {
	Action  string   `json:"action"`
	Effects []string `json:"effects,omitempty"`
}

func (p *Preset) Entry(used bool) (Entry, error) {
	metadata := *p.Catalog
	entry := Entry{Catalog: &metadata, Title: p.Title}
	if !used {
		metadata.Actions = nil
		return entry, nil
	}
	var display struct {
		HTTP *struct {
			Operations map[string]Operation `json:"operations"`
		} `json:"http"`
	}
	if err := json.Unmarshal(p.Source, &display); err != nil {
		return entry, err
	}
	if display.HTTP != nil {
		if display.HTTP.Operations == nil {
			display.HTTP.Operations = map[string]Operation{}
		}
		entry.Operations = &display.HTTP.Operations
	}
	return entry, nil
}
