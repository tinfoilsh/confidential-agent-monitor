package config

import (
	_ "embed"
	"maps"
	"slices"

	"github.com/tinfoilsh/confidential-agent-monitor/connector/catalog"
)

const (
	PerimeterConnection = "perimeter"
	DeviceGroup         = "device"
)

// Actions on the perimeter connection, as perimeter.json defines them.
const (
	OverviewRead       = "overview.read"
	PolicyRead         = "policy.read"
	PolicyPreview      = "policy.preview"
	PolicyWrite        = "policy.write"
	CredentialsWrite   = "credentials.write"
	ConnectionsControl = "connections.control"
	EnrollIdentities   = "enroll"
	LabelsWrite        = "labels.write"
	RequestsRead       = "requests.read"
	RequestsAnswer     = "requests.answer"
	RequestsSave       = "requests.save"
	ProposalsAnswer    = "proposals.answer"
	ProposalsOthers    = "proposals.others"
	AuditRead          = "audit.read"
	CatalogsRead       = "catalogs.read"
	ExplainIdentity    = "explain"
	BunkersRelay       = "bunkers.relay"
	RoutesPublish      = "routes.publish"
)

// Enrolling a device grants these on the perimeter connection.
var deviceActions = map[string]Mode{RoutesPublish: ModeAllow, PolicyRead: ModeAllow, ProposalsOthers: ModeAllow}

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

var (
	perimeterConnection = Connection{Preset: PerimeterConnection, Contents: AudienceMe, Sends: AudienceMe}
	deviceGroup         = Group{Connections: map[string]Access{PerimeterConnection: {Actions: deviceActions}}}
)

// Connection is a configured connection or the built-in one for the Perimeter's own API.
func (c *Config) Connection(name string) (Connection, bool) {
	if name == PerimeterConnection {
		return perimeterConnection, true
	}
	conn, ok := c.Connections[name]
	return conn, ok
}

func (c *Config) Preset(connection string) *catalog.Preset {
	if connection == PerimeterConnection {
		return perimeterPreset
	}
	return c.Presets[c.Connections[connection].Preset]
}

func (c *Config) group(name string) Group {
	if name == DeviceGroup {
		return deviceGroup
	}
	return c.Groups[name]
}

func (c *Config) connectionNames() []string {
	return append(slices.Collect(maps.Keys(c.Connections)), PerimeterConnection)
}
