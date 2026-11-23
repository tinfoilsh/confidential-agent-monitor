package config

import (
	_ "embed"
	"fmt"
	"maps"

	"github.com/tinfoilsh/confidential-agent-monitor/connector/catalog"
	"github.com/tinfoilsh/confidential-agent-monitor/core/tomledit"
)

const PerimeterConnection = "perimeter"

const (
	RoutesPublish   = "routes.publish"
	PolicyRead      = "policy.read"
	ProposalsOthers = "proposals.others"
	RequestsRead    = "requests.read"
	AuditRead       = "audit.read"
)

// Enrolling a device grants these on the perimeter connection.
func DeviceActions() map[string]string {
	return map[string]string{RoutesPublish: "allow", PolicyRead: "allow", ProposalsOthers: "allow"}
}

//go:embed perimeter.json
var perimeterJSON []byte

// Built in rather than in the preset catalog, since no policy configures the connection.
var perimeterPreset = func() *catalog.Preset {
	p, err := catalog.Decode(perimeterJSON)
	if err != nil {
		panic(err)
	}
	return p
}()

func perimeterTable(decoded map[string]any) error {
	for key := range tomledit.Table(decoded, "connections", PerimeterConnection) {
		if key != "limits" {
			return fmt.Errorf("%s: the built-in %s connection accepts only limits", tomlPath("connections", PerimeterConnection, key), PerimeterConnection)
		}
	}
	return nil
}

func (c *Config) builtIn() error {
	if p, listed := c.Presets[PerimeterConnection]; listed && p != perimeterPreset {
		return fmt.Errorf("preset %s is the Perimeter's own; a catalog cannot list one of that name", PerimeterConnection)
	}
	presets := map[string]*catalog.Preset{PerimeterConnection: perimeterPreset}
	maps.Copy(presets, c.Presets)
	c.Presets = presets
	if c.Connections == nil {
		c.Connections = map[string]Connection{}
	}
	c.Connections[PerimeterConnection] = Connection{Preset: PerimeterConnection, Limits: c.Connections[PerimeterConnection].Limits,
		Contents: AudienceMe, Sends: AudienceMe}
	return nil
}
