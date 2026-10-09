// Package facts defines the request data shared by connectors, policy, and audit.
package facts

import (
	"maps"
	"net/http"
	"net/url"
	"slices"
)

// Version identifies the facts schema and approval semantics. Bump it when
// parsing, description, normalization, label, or approval semantics change.
// This invalidates saved approvals; display-only edits do not need a bump.
const Version = 6

// Label levels are ordered from most restrictive to least restrictive.
// Policy derives its rank tables from these same lists.
var (
	Audiences = []string{"me", "team", "anyone"}
	Trusts    = []string{"untrusted", "trusted"}
)

type Kind string

const (
	KindOperation Kind = "operation"
	KindAdmission Kind = "admission"
)

type Principal struct {
	Key  string `json:"key"`
	Name string `json:"name"`
}

type Label struct {
	Audience string            `json:"audience"`
	Trust    string            `json:"trust"`
	Because  map[string]string `json:"because,omitempty"`
}

func (l Label) Valid() bool {
	return slices.Contains(Audiences, l.Audience) && slices.Contains(Trusts, l.Trust)
}

type Operation struct {
	ID          string      `json:"id"`
	Action      string      `json:"action"`
	Effects     []string    `json:"effects"`
	Obligations Obligations `json:"obligations"`
	Lineage     []string    `json:"lineage"`
}

type Context struct {
	Label    Label  `json:"label"`
	Sends    string `json:"sends"`
	Observes Label  `json:"observes"`
	Cause    string `json:"cause"`
}

// Facts is the snapshot shared by authorization and audit.
// Protocol details use typed fields; service parameters remain JSON values.
type Facts struct {
	Scope      map[string]any `json:"-"`
	Definition any            `json:"-"`
	encoded    []byte         // The immutable audit encoding after Snapshot.
	Version    int            `json:"version"`
	Kind       Kind           `json:"kind"`
	Principal  Principal      `json:"principal"`
	Account    string         `json:"account"`
	Service    string         `json:"service"`
	Connection string         `json:"connection"`
	Operation  *Operation     `json:"operation"`
	Parameters map[string]any `json:"parameters"`
	Context    Context        `json:"context"`
	Title      string         `json:"title"`
	Details    Details        `json:"details"`
}

// Details holds parsed protocol data. The Go fields and JSON names are shared
// by connectors, authorization, and audit.
type Details struct {
	HTTP     *HTTP     `json:"http,omitempty"`
	GraphQL  *GraphQL  `json:"graphql,omitempty"`
	MCP      *MCP      `json:"mcp,omitempty"`
	SSH      *SSH      `json:"ssh,omitempty"`
	Command  *Command  `json:"command,omitempty"`
	Payload  *Git      `json:"payload,omitempty"`
	SFTP     *SFTP     `json:"sftp,omitempty"`
	SMTP     *SMTP     `json:"smtp,omitempty"`
	Mail     *Mail     `json:"mail,omitempty"`
	IMAP     *IMAP     `json:"imap,omitempty"`
	Browser  *Browser  `json:"browser,omitempty"`
	NATS     *NATS     `json:"nats,omitempty"`
	MQTT     *MQTT     `json:"mqtt,omitempty"`
	Redis    *Redis    `json:"redis,omitempty"`
	Postgres *Postgres `json:"postgres,omitempty"`
	Sign     *Sign     `json:"sign,omitempty"`
	TCP      *TCP      `json:"tcp,omitempty"`
}

type HTTP struct {
	Method   string      `json:"method"`
	Origin   string      `json:"origin"`
	Host     string      `json:"host"`
	Path     string      `json:"path"`
	Query    url.Values  `json:"query"`
	Headers  http.Header `json:"headers"`
	Secrets  []string    `json:"secrets"`
	BodyKind string      `json:"body_kind"`
	Body     any         `json:"body,omitempty"`
	Form     url.Values  `json:"form,omitempty"`
	// HeaderJSON holds single header values that are JSON objects, as Dropbox-API-Arg is.
	HeaderJSON map[string]any `json:"header_json,omitempty"`
}

type GraphQL struct {
	Kind   string         `json:"kind"`
	Fields []GraphQLField `json:"fields"`
}

type GraphQLField struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

type SSH struct {
	Request   string  `json:"request"`
	Command   string  `json:"command,omitempty"`
	Subsystem string  `json:"subsystem,omitempty"`
	Term      string  `json:"term,omitempty"`
	Env       *SSHEnv `json:"env,omitempty"`
}

type SSHEnv struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type Command struct {
	Argv []string `json:"argv"`
}

type Git struct {
	Type       string   `json:"type"`
	Tree       string   `json:"tree,omitempty"`
	Object     string   `json:"object,omitempty"`
	ObjectType string   `json:"object_type,omitempty"`
	Tag        string   `json:"tag,omitempty"`
	Parents    []string `json:"parents"`
	Author     string   `json:"author,omitempty"`
	Committer  string   `json:"committer,omitempty"`
	Tagger     string   `json:"tagger,omitempty"`
	Message    string   `json:"message"`
}

type SMTP struct {
	From string   `json:"from"`
	To   []string `json:"to"`
}

type Mail struct {
	From        []string `json:"from"`
	To          []string `json:"to"`
	Cc          []string `json:"cc"`
	Subject     string   `json:"subject"`
	Attachments []string `json:"attachments"`
}

type IMAP struct {
	Command string `json:"command"`
	Args    string `json:"args"`
	Mailbox string `json:"mailbox,omitempty"`
}

type SFTP struct {
	Command    string            `json:"command"`
	Path       string            `json:"path"`
	Target     string            `json:"target,omitempty"`
	Read       bool              `json:"read,omitempty"`
	Write      bool              `json:"write,omitempty"`
	Flags      uint32            `json:"flags,omitempty"`
	Offset     uint64            `json:"offset,omitempty"`
	Size       uint32            `json:"size,omitempty"`
	Attributes map[string]uint64 `json:"attributes,omitempty"`
}

type Browser struct {
	Command string   `json:"command"`
	URL     string   `json:"url"`
	Host    string   `json:"host"`
	Text    string   `json:"text,omitempty"`
	Secrets []string `json:"secrets,omitempty"`
}

type NATS struct {
	Command string              `json:"command"`
	Subject string              `json:"subject"`
	Reply   string              `json:"reply,omitempty"`
	Queue   string              `json:"queue,omitempty"`
	Headers map[string][]string `json:"headers,omitempty"`
	Payload []byte              `json:"payload,omitempty"`
}

type MQTT struct {
	Command string `json:"command"`
	Topic   string `json:"topic"`
	QoS     byte   `json:"qos"`
	Retain  bool   `json:"retain"`
	Payload []byte `json:"payload,omitempty"`
}

type Redis struct {
	Command string   `json:"command"`
	Argv    []string `json:"argv"`
}

type Postgres struct {
	SQL string `json:"sql"`
}

type Sign struct {
	Agent     string `json:"agent"`
	Key       string `json:"key,omitempty"`
	Purpose   string `json:"purpose,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	User      string `json:"user,omitempty"`
	Hash      string `json:"hash,omitempty"`
	Op        string `json:"op,omitempty"`
}

type TCP struct {
	Host string `json:"host"`
	Port uint32 `json:"port"`
}

type MCP struct {
	Tool      string `json:"tool"`
	Arguments any    `json:"arguments"`
	ReadOnly  bool   `json:"read_only"`
}

// Obligations describes the requirements carried by an effect.
type Obligations struct {
	Change    bool `json:"change"`
	Trust     bool `json:"trust"`
	Ask       bool `json:"ask"`
	Discloses bool `json:"discloses"`
}

// Effects is shared by preset validation, request descriptions, policy, and UI.
var Effects = map[string]Obligations{
	"read":     {},
	"session":  {},
	"write":    {Change: true, Trust: true},
	"generate": {Change: true, Trust: true},
	"delete":   {Change: true, Trust: true},
	"admin":    {Change: true, Trust: true},
	"execute":  {Change: true, Trust: true},
	"send":     {Change: true, Trust: true, Discloses: true},
	"share":    {Change: true, Trust: true, Discloses: true},
	"publish":  {Change: true, Trust: true, Ask: true, Discloses: true},
	"pay":      {Change: true, Trust: true, Ask: true},
}

func ValidEffects(effects []string) bool {
	if len(effects) == 0 {
		return false
	}
	for _, effect := range effects {
		if _, ok := Effects[effect]; !ok {
			return false
		}
	}
	return true
}

// ObligationsFor combines the requirements of all effects on an operation.
func ObligationsFor(effects []string) (out Obligations) {
	for _, effect := range effects {
		o := Effects[effect]
		out.Change = out.Change || o.Change
		out.Trust = out.Trust || o.Trust
		out.Ask = out.Ask || o.Ask
		out.Discloses = out.Discloses || o.Discloses
	}
	return out
}

// Observe joins request observations, preserving provenance
// on axes that do not become more restrictive. Both labels must be valid.
func (l Label) Observe(observed Label, cause string) Label {
	l.Because = maps.Clone(l.Because)
	if l.Because == nil {
		l.Because = map[string]string{}
	}
	if slices.Index(Audiences, observed.Audience) < slices.Index(Audiences, l.Audience) {
		l.Audience, l.Because["audience"] = observed.Audience, cause
	}
	if slices.Index(Trusts, observed.Trust) < slices.Index(Trusts, l.Trust) {
		l.Trust, l.Because["trust"] = observed.Trust, cause
	}
	return l
}
