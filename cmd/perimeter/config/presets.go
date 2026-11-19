package config

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/tinfoilsh/confidential-agent-monitor/connector/catalog"
)

// A catalog resolves fragments and replacements among its own presets only.
func AddCatalog(prefix string, loaded, out map[string]*catalog.Preset) error {
	for name, p := range loaded {
		if !bytes.HasPrefix(p.Catalog.Defaults, []byte("{")) {
			return fmt.Errorf("preset %s: catalog must be an object with defaults", name)
		}
		for action, a := range p.Catalog.Actions {
			if a.Effects != nil && !ValidEffects(a.Effects) {
				return fmt.Errorf("preset %s: invalid effects for action %s", name, action)
			}
		}
	}
	if err := catalog.Compose(loaded); err != nil {
		return err
	}
	for name, p := range loaded {
		if p.Catalog.ReplacedBy != "" {
			p.Catalog.ReplacedBy = prefix + p.Catalog.ReplacedBy
		}
		out[prefix+name] = p
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

func CatalogEntries(cfg *Config, operations map[string]map[string]OperationSummary) (map[string]CatalogEntry, string, error) {
	used := map[string]bool{}
	for _, connection := range cfg.Connections {
		used[connection.Preset] = true
	}
	entries := map[string]CatalogEntry{}
	for name, p := range cfg.presets {
		metadata := *p.Catalog
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
