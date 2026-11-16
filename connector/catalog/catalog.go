// Package catalog decodes preset sources: protocol definitions with their setup and control metadata.
package catalog

import (
	"encoding/json"
	"errors"
)

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
	Actions    map[string]Action          `json:"actions,omitempty"`
	Connection map[string]json.RawMessage `json:"connection,omitempty"`
	// Defaults is whatever a source declares; shipped sources declare none.
	Defaults json.RawMessage   `json:"defaults,omitempty"`
	Fields   []json.RawMessage `json:"fields,omitempty"`
}

type Action struct {
	Title   string   `json:"title"`
	Effects []string `json:"effects,omitempty"`
}

// MarshalJSON preserves protocol definitions without catalog-owned decoding.
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
