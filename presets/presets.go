// Package presets decodes the shipped account presets.
package presets

import (
	"embed"
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
	"sync"

	"github.com/tinfoilsh/monitor/connector/mcp"
	"github.com/tinfoilsh/monitor/connector/web"
	"github.com/tinfoilsh/monitor/facts"
)

//go:embed *.json
var Files embed.FS

// A Preset contains reviewed protocol definitions and account setup metadata.
type Preset struct {
	Title       string          `json:"title"`
	Catalog     *Catalog        `json:"catalog"`
	HTTP        *web.Preset     `json:"http,omitempty"`
	MCP         *mcp.Preset     `json:"mcp,omitempty"`
	PublicScope []string        `json:"public_scope,omitempty"`
	Source      json.RawMessage `json:"-"`
}

type Catalog struct {
	Group       string                     `json:"group,omitempty"`
	ReplacedBy  string                     `json:"replaced_by,omitempty"`
	Actions     map[string]Action          `json:"actions,omitempty"`
	Connections map[string]json.RawMessage `json:"connections,omitempty"`
	Defaults    json.RawMessage            `json:"defaults,omitempty"`
	Fields      []json.RawMessage          `json:"fields,omitempty"`
}

type Action struct {
	Title   string   `json:"title"`
	Effects []string `json:"effects,omitempty"`
}

func Decode(raw []byte) (*Preset, error) {
	p := Preset{Source: raw}
	if err := facts.DecodeNumbers(raw, &p); err != nil {
		return nil, err
	}
	if p.Catalog == nil {
		return nil, fmt.Errorf("catalog must be an object")
	}
	if _, err := p.Catalog.CredentialFields(); err != nil {
		return nil, err
	}
	for name, a := range p.Catalog.Actions {
		if a.Effects != nil && !facts.ValidEffects(a.Effects) {
			return nil, fmt.Errorf("invalid effects for action %s", name)
		}
	}
	return &p, nil
}

func Lineage(action string) []string {
	var lineage []string
	for action != "" {
		lineage = append(lineage, action)
		i := strings.LastIndexByte(action, '.')
		if i < 0 {
			break
		}
		action = action[:i]
	}
	return lineage
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

// CredentialPath identifies a credential within an account's connection settings.
// Connection may be empty for the account's default connection.
type CredentialPath struct {
	Connection string
	Protocol   string
	Secret     string
}

func (p CredentialPath) Path() []string {
	return []string{"connections", p.Connection, p.Protocol, "secrets", p.Secret}
}

// CredentialFields groups the credential destinations of each catalog field.
// Other metadata remains opaque, including display paths with array indexes.
func (c *Catalog) CredentialFields() ([][]CredentialPath, error) {
	var fields [][]CredentialPath
	for i, raw := range c.Fields {
		var field struct {
			Path  []json.RawMessage   `json:"path"`
			Paths [][]json.RawMessage `json:"paths"`
		}
		if err := json.Unmarshal(raw, &field); err != nil {
			return nil, fmt.Errorf("catalog field %d: %w", i, err)
		}
		var paths []CredentialPath
		for _, path := range append(field.Paths, field.Path) {
			// Only credential paths have a meaning to Go consumers of the catalog.
			var root, section string
			if len(path) < 4 || json.Unmarshal(path[0], &root) != nil || root != "connections" ||
				json.Unmarshal(path[3], &section) != nil || section != "secrets" {
				continue
			}
			var p CredentialPath
			if len(path) != 5 || json.Unmarshal(path[1], &p.Connection) != nil ||
				json.Unmarshal(path[2], &p.Protocol) != nil || json.Unmarshal(path[4], &p.Secret) != nil ||
				p.Protocol == "" || p.Secret == "" {
				return nil, fmt.Errorf("catalog field %d: credential path must name a connection, protocol and secret", i)
			}
			paths = append(paths, p)
		}
		if len(paths) != 0 {
			fields = append(fields, paths)
		}
	}
	return fields, nil
}
