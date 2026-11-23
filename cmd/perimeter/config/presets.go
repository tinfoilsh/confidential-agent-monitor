package config

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/tinfoilsh/confidential-agent-monitor/connector/catalog"
)

type connectionDefaults struct {
	Contents  string `json:"contents"`
	Sends     string `json:"sends"`
	Strangers bool   `json:"strangers"`
}

// A preset that states no defaults takes those of its protocol.
func Compose(presets map[string]*catalog.Preset) error {
	if err := catalog.Compose(presets); err != nil {
		return err
	}
	for name, p := range presets {
		for action, a := range p.Catalog.Actions {
			if a.Effects != nil && !ValidEffects(a.Effects) {
				return fmt.Errorf("preset %s: invalid effects for action %s", name, action)
			}
		}
		if p.Catalog.Defaults != nil {
			var stated map[string]any
			if json.Unmarshal(p.Catalog.Defaults, &stated) != nil || stated == nil {
				return fmt.Errorf("preset %s: defaults must be an object", name)
			}
			continue
		}
		defaults := connectionDefaults{Contents: AudienceMe, Sends: AudienceMe, Strangers: true}
		switch {
		case p.Catalog.Connection["mcp"] != nil:
			defaults.Contents = AudienceTeam
		case p.Catalog.Connection["http"] != nil:
			defaults.Contents, defaults.Sends = AudienceTeam, AudienceAnyone
		}
		p.Catalog.Defaults, _ = json.Marshal(defaults)
	}
	return nil
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

func CatalogEntries(cfg *Config) (map[string]CatalogEntry, string, error) {
	used := map[string]bool{}
	for _, connection := range cfg.Connections {
		used[connection.Preset] = true
	}
	entries := map[string]CatalogEntry{}
	for name, p := range cfg.Presets {
		metadata := *p.Catalog
		entry := CatalogEntry{Catalog: &metadata, Title: p.Title}
		if !used[name] {
			metadata.Actions = nil
		} else if ops := cfg.Operations[name]; ops != nil {
			entry.Operations = &ops
		}
		entries[name] = entry
	}
	raw, err := json.Marshal(entries)
	return entries, fmt.Sprintf("%x", sha256.Sum256(raw)), err
}
