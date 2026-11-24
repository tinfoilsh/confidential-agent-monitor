package config

import (
	_ "embed"
	"fmt"
	"maps"

	"github.com/tinfoilsh/confidential-agent-monitor/connector/catalog"
	"github.com/tinfoilsh/confidential-agent-monitor/core/tomledit"
)

const (
	PerimeterConnection = "perimeter"
	DeviceGroup         = "device"
)

const (
	RoutesPublish   = "routes.publish"
	PolicyRead      = "policy.read"
	ProposalsOthers = "proposals.others"
	RequestsRead    = "requests.read"
	AuditRead       = "audit.read"
)

// Enrolling a device grants these on the perimeter connection.
var deviceActions = map[string]string{RoutesPublish: "allow", PolicyRead: "allow", ProposalsOthers: "allow"}

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
	if len(tomledit.Table(decoded, "connections", PerimeterConnection)) != 0 {
		return fmt.Errorf("%s: the built-in %s connection takes no settings", tomlPath("connections", PerimeterConnection), PerimeterConnection)
	}
	return nil
}

func (c *Config) builtIn() error {
	if p, listed := c.Presets[PerimeterConnection]; listed && p != perimeterPreset {
		return fmt.Errorf("preset %s is the Perimeter's own; a catalog cannot list one of that name", PerimeterConnection)
	}
	if _, defined := c.Groups[DeviceGroup]; defined {
		return fmt.Errorf("%s: the %s group is built in", tomlPath("groups", DeviceGroup), DeviceGroup)
	}
	presets := map[string]*catalog.Preset{PerimeterConnection: perimeterPreset}
	maps.Copy(presets, c.Presets)
	c.Presets = presets
	if c.Connections == nil {
		c.Connections = map[string]Connection{}
	}
	c.Connections[PerimeterConnection] = Connection{Preset: PerimeterConnection, Contents: AudienceMe, Sends: AudienceMe}
	if c.Groups == nil {
		c.Groups = map[string]Group{}
	}
	c.Groups[DeviceGroup] = Group{Connections: map[string]Access{PerimeterConnection: {Actions: deviceActions}}}
	return nil
}
