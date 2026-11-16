package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/tinfoilsh/confidential-agent-monitor/connector/catalog"
)

// Presets: the shipped protocol descriptions, an organization's own, and the owner catalog.

// connectionDefaults are the settings the owner UI proposes for a new connection of a preset.
type connectionDefaults struct {
	Contents  string `json:"contents"`
	Sends     string `json:"sends"`
	Strangers bool   `json:"strangers"`
}

var (
	privateDefaults    = connectionDefaults{Contents: "me", Sends: "me", Strangers: true}
	personalDefaults   = connectionDefaults{Contents: "me", Sends: "anyone", Strangers: true}
	teamDefaults       = connectionDefaults{Contents: "team", Sends: "team", Strangers: true}
	teamPrivate        = connectionDefaults{Contents: "team", Sends: "me", Strangers: true}
	teamPublicDefaults = connectionDefaults{Contents: "team", Sends: "anyone", Strangers: true}
	publicDefaults     = connectionDefaults{Contents: "anyone", Sends: "anyone", Strangers: true}
)

// shippedDefaults selects a shipped preset's defaults: by service, then by its connection's kind.
// MCP servers and the GitHub API return team data only to the agent; other APIs can publish it.
func shippedDefaults(name string, p *catalog.Preset) connectionDefaults {
	switch name {
	case "tcp", "web":
		return publicDefaults
	case "dropbox", "gmail", "google_calendar", "google_docs", "google_drive", "google_gemini", "google_sheets",
		"microsoft_excel", "microsoft_onedrive", "outlook", "todoist":
		return personalDefaults
	case "google_tasks", "microsoft_todo":
		return privateDefaults
	case "github":
		return teamPrivate
	case "slack_socket_mode":
		return teamDefaults
	}
	switch {
	case p.Catalog.Connection["mcp"] != nil:
		return teamPrivate
	case p.Catalog.Connection["http"] != nil:
		return teamPublicDefaults
	}
	return privateDefaults
}

// LoadPresets decodes the shipped presets and an organization's own; an organization's
// preset keeps the defaults its catalog declares.
func LoadPresets(shipped, extra fs.FS) (map[string]*catalog.Preset, map[string]json.RawMessage, error) {
	out, defaults := map[string]*catalog.Preset{}, map[string]json.RawMessage{}
	for _, source := range []fs.FS{shipped, extra} {
		if source == nil {
			continue
		}
		files, _ := fs.Glob(source, "*.json")
		for _, file := range files {
			name := strings.TrimSuffix(file, ".json")
			if out[name] != nil {
				return nil, nil, fmt.Errorf("preset %s is already shipped", file)
			}
			raw, err := fs.ReadFile(source, file)
			var p *catalog.Preset
			if err == nil {
				p, err = catalog.Decode(raw)
			}
			if err == nil && source == extra {
				if defaults[name] = p.Catalog.Defaults; !bytes.HasPrefix(defaults[name], []byte("{")) {
					err = errors.New("catalog must be an object with defaults")
				}
			} else if err == nil {
				defaults[name], err = json.Marshal(shippedDefaults(name, p))
			}
			if err == nil {
				for action, a := range p.Catalog.Actions {
					if a.Effects != nil && !ValidEffects(a.Effects) {
						err = fmt.Errorf("invalid effects for action %s", action)
					}
				}
			}
			if err != nil {
				return nil, nil, fmt.Errorf("preset %s: %w", file, err)
			}
			out[name] = p
		}
	}
	return out, defaults, nil
}

// OperationSummary is protocol-neutral catalog metadata, never an authorization input.
type OperationSummary struct {
	Action  string   `json:"action"`
	Effects []string `json:"effects,omitempty"`
}

// CatalogEntry is the owner's catalog presentation. Operations are display metadata;
// their protocol definitions remain opaque until a connector decodes them.
type CatalogEntry struct {
	*catalog.Catalog
	Title      string                       `json:"title"`
	Operations *map[string]OperationSummary `json:"operations,omitempty"`
}

// CatalogEntries is a control presentation, never an authorization or runtime registry.
func CatalogEntries(cfg *Config, defaults map[string]json.RawMessage, operations map[string]map[string]OperationSummary) (map[string]CatalogEntry, string, error) {
	used := map[string]bool{}
	for _, connection := range cfg.Connections {
		used[connection.Preset] = true
	}
	entries := map[string]CatalogEntry{}
	for name, p := range cfg.presets {
		metadata := *p.Catalog
		metadata.Defaults = defaults[name]
		entry := CatalogEntry{Catalog: &metadata, Title: p.Title}
		if !used[name] {
			metadata.Actions = nil
		} else if ops := operations[name]; ops != nil {
			entry.Operations = &ops
		}
		entries[name] = entry
	}
	raw, err := json.Marshal(entries)
	return entries, fmt.Sprintf("%x", sha256.Sum256(raw)), err
}
