//go:build monitor_dev

package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/tinfoilsh/monitor/presets"
)

// Custom preset authoring and automated review remain available only in
// explicit development builds. Release decoders reject these fields.
type developmentIdentity struct {
	Reviewer string `json:"reviewer,omitempty"`
}

type Reviewer struct {
	Connection   string `json:"connection"`
	Model        string `json:"model"`
	Instructions string `json:"instructions"`
}

type developmentConfig struct {
	Reviewer *Reviewer                 `json:"reviewer,omitempty"`
	Presets  map[string]map[string]any `json:"presets,omitempty"`
}

func (c *Config) validateDevelopmentPresets() error {
	for name := range c.Presets {
		if _, err := c.Preset(name); err != nil {
			return err
		}
	}
	return nil
}

func (c *Config) validateDevelopment(connections map[string]string) error {
	for name, identity := range c.Identities {
		if identity.Reviewer != "" && (identity.Reviewer != "tinfoil" || c.Reviewer == nil) {
			return fmt.Errorf("identity %s: configure Tinfoil review before assigning it", name)
		}
	}
	if c.Reviewer == nil {
		return nil
	}
	r := c.Reviewer
	if connections[r.Connection] != "tinfoil" {
		return errors.New("reviewer requires a Tinfoil connection")
	}
	if strings.TrimSpace(r.Model) == "" || len(r.Model) > 200 || strings.TrimSpace(r.Instructions) == "" || len(r.Instructions) > 8192 {
		return errors.New("reviewer requires a model and instructions of 1-8192 bytes")
	}
	return nil
}

func (c *Config) developmentPresetNames() []string {
	names := make([]string, 0, len(c.Presets))
	for name := range c.Presets {
		names = append(names, name)
	}
	return names
}

func (c *Config) DevelopmentIdentityAuthority(name string) any {
	return c.Identities[name].Reviewer
}

func (c *Config) DevelopmentAuthority() any { return c.Reviewer }

func (c *Config) resolvePreset(shipped map[string]*presets.Preset, name string) (*presets.Preset, error) {
	preset, override := shipped[name], c.Presets[name]
	if override == nil {
		if preset == nil {
			return nil, fmt.Errorf("unknown preset %s", name)
		}
		return preset, nil
	}
	base := json.RawMessage(`{}`)
	if preset != nil {
		base = preset.Source
	}
	patch, err := json.Marshal(override)
	if err == nil {
		base, err = jsonpatch.MergePatch(base, patch)
	}
	if err != nil {
		return nil, err
	}
	resolved, err := presets.Decode(base)
	if err != nil {
		return nil, fmt.Errorf("preset %s: %w", name, err)
	}
	return resolved, nil
}
