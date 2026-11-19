package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"slices"

	"github.com/tinfoilsh/confidential-agent-monitor/connector/catalog"
)

type connectionDefaults struct {
	Contents  string `json:"contents"`
	Sends     string `json:"sends"`
	Strangers bool   `json:"strangers"`
}

var (
	privateDefaults     = connectionDefaults{Contents: AudienceMe, Sends: AudienceMe, Strangers: true}
	personalDefaults    = connectionDefaults{Contents: AudienceMe, Sends: AudienceAnyone, Strangers: true}
	teamDefaults        = connectionDefaults{Contents: AudienceTeam, Sends: AudienceTeam, Strangers: true}
	teamPrivateDefaults = connectionDefaults{Contents: AudienceTeam, Sends: AudienceMe, Strangers: true}
	teamPublicDefaults  = connectionDefaults{Contents: AudienceTeam, Sends: AudienceAnyone, Strangers: true}
	publicDefaults      = connectionDefaults{Contents: AudienceAnyone, Sends: AudienceAnyone, Strangers: true}
)

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
		return teamPrivateDefaults
	case "slack_socket_mode":
		return teamDefaults
	}
	switch {
	case p.Catalog.Connection["mcp"] != nil:
		return teamPrivateDefaults
	case p.Catalog.Connection["http"] != nil:
		return teamPublicDefaults
	}
	return privateDefaults
}

func LoadPresets(extra fs.FS) (map[string]*catalog.Preset, map[string]json.RawMessage, error) {
	out, defaults := map[string]*catalog.Preset{}, map[string]json.RawMessage{}
	for _, source := range []fs.FS{catalog.Shipped, extra} {
		if source == nil {
			continue
		}
		loaded, err := catalog.Load(source)
		if err != nil {
			return nil, nil, err
		}
		for _, name := range slices.Sorted(maps.Keys(loaded)) {
			p := loaded[name]
			if out[name] != nil {
				return nil, nil, fmt.Errorf("preset %s.json is already shipped", name)
			}
			if source == extra {
				if defaults[name] = p.Catalog.Defaults; !bytes.HasPrefix(defaults[name], []byte("{")) {
					err = errors.New("catalog must be an object with defaults")
				}
			} else {
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
				return nil, nil, fmt.Errorf("preset %s.json: %w", name, err)
			}
			out[name] = p
		}
	}
	if err := catalog.Compose(out); err != nil {
		return nil, nil, err
	}
	return out, defaults, nil
}

type OperationSummary struct {
	Action  string   `json:"action"`
	Effects []string `json:"effects,omitempty"`
}

type CatalogEntry struct {
	*catalog.Catalog
	Title      string                       `json:"title"`
	Operations *map[string]OperationSummary `json:"operations,omitempty"`
}

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
