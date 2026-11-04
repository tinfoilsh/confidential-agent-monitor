//go:build !monitor_dev

package config

import (
	"fmt"

	"github.com/tinfoilsh/monitor/presets"
)

// Unsupported configuration is absent from release decoding and rendering.
type developmentIdentity struct{}
type developmentConfig struct{}

func (c *Config) validateDevelopmentPresets() error           { return nil }
func (c *Config) validateDevelopment(map[string]string) error { return nil }
func (c *Config) developmentPresetNames() []string            { return nil }
func (c *Config) DevelopmentIdentityAuthority(string) any     { return nil }
func (c *Config) DevelopmentAuthority() any                   { return nil }

func (c *Config) resolvePreset(shipped map[string]*presets.Preset, name string) (*presets.Preset, error) {
	preset := shipped[name]
	if preset == nil {
		return nil, fmt.Errorf("unknown preset %s", name)
	}
	return preset, nil
}
