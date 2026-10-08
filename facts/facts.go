// Package facts defines the request data shared by connectors, policy, and audit.
package facts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
)

// Version identifies the public facts schema.
const Version = 4

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
	KindMessage   Kind = "message"
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
	ID            string   `json:"id"`
	Action        string   `json:"action"`
	Effects       []string `json:"effects"`
	RequiresTrust bool     `json:"requires_trust"`
}

type Context struct {
	Label    Label  `json:"label"`
	Sends    string `json:"sends"`
	Observes Label  `json:"observes"`
	Cause    string `json:"cause"`
	Channel  *Label `json:"channel,omitempty"`
}

// Facts is the snapshot shared by authorization and audit.
// Protocol details use typed fields; service parameters remain JSON values.
type Facts struct {
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
	Message  *Message  `json:"message,omitempty"`
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

type Message struct {
	Action  string `json:"action"`
	Peer    string `json:"peer"`
	From    string `json:"from"`
	To      string `json:"to"`
	ID      string `json:"id,omitempty"`
	Body    any    `json:"body,omitempty"`
	Channel Label  `json:"channel"`
	Cause   string `json:"cause"`
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
	"write":    {Change: true},
	"generate": {Change: true},
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

// Observe joins request observations and mailbox history, preserving provenance
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

// Validate checks the resolved snapshot for every connector before policy
// runs. Unknown requests have no operation; malformed descriptions are denied.
func (f Facts) Validate() error {
	var errs []error
	if !slices.Contains([]Kind{KindOperation, KindAdmission, KindMessage}, f.Kind) {
		errs = append(errs, fmt.Errorf("invalid request kind %q", f.Kind))
	}
	if op := f.Operation; op != nil && (op.ID == "" || op.Action == "" || !ValidEffects(op.Effects)) {
		errs = append(errs, errors.New("the recognized operation is malformed"))
	}
	if !f.Context.Label.Valid() {
		errs = append(errs, errors.New("the agent label is invalid"))
	}
	if !f.Context.Observes.Valid() {
		errs = append(errs, errors.New("the observation label is invalid"))
	}
	if !slices.Contains(Audiences, f.Context.Sends) {
		errs = append(errs, errors.New("the disclosure audience is invalid"))
	}
	if channel := f.Context.Channel; channel != nil && !channel.Valid() {
		errs = append(errs, errors.New("the message channel label is invalid"))
	}
	if f.Kind == KindMessage && (f.Context.Channel == nil || f.Operation == nil) {
		errs = append(errs, errors.New("a message requires an operation and channel label"))
	}
	if f.Kind == KindAdmission && f.Operation == nil {
		errs = append(errs, errors.New("admission requires an operation"))
	}
	return errors.Join(errs...)
}

// CloneJSON owns the mutable parts of a JSON value while retaining immutable
// strings and exact numbers. Other Go values retain encoding/json's
// representation through the fallback.
func CloneJSON(value any) (any, error) {
	switch v := value.(type) {
	case nil, string, bool:
		return v, nil
	case json.Number:
		if _, err := json.Marshal(v); err != nil {
			return nil, err
		}
		return v, nil
	case map[string]any:
		if v == nil {
			return nil, nil
		}
		out := make(map[string]any, len(v))
		for key, field := range v {
			frozen, err := CloneJSON(field)
			if err != nil {
				return nil, err
			}
			out[key] = frozen
		}
		return out, nil
	case map[string][]string:
		if v == nil {
			return nil, nil
		}
		out := make(map[string]any, len(v))
		for key, field := range v {
			frozen, _ := CloneJSON(field)
			out[key] = frozen
		}
		return out, nil
	case []any:
		if v == nil {
			return nil, nil
		}
		out := make([]any, len(v))
		for i, field := range v {
			frozen, err := CloneJSON(field)
			if err != nil {
				return nil, err
			}
			out[i] = frozen
		}
		return out, nil
	case []string:
		if v == nil {
			return nil, nil
		}
		out := make([]any, len(v))
		for i, field := range v {
			out[i] = field
		}
		return out, nil
	default:
		raw, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		var out any
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		if err := decoder.Decode(&out); err != nil {
			return nil, err
		}
		return out, nil
	}
}

// Clone freezes the mutable values shared with a parsed request. Protocol fields
// stay typed; only service-defined JSON bodies and parameters need a JSON copier.
func (f Facts) Clone() (Facts, error) {
	var err error
	f.Parameters, err = cloneObject(f.Parameters)
	if err != nil {
		return f, err
	}
	f.Operation = clone(f.Operation)
	if f.Operation != nil {
		f.Operation.Effects = slices.Clone(f.Operation.Effects)
	}
	f.Context.Label.Because = maps.Clone(f.Context.Label.Because)
	f.Context.Observes.Because = maps.Clone(f.Context.Observes.Because)
	f.Context.Channel = clone(f.Context.Channel)
	if f.Context.Channel != nil {
		f.Context.Channel.Because = maps.Clone(f.Context.Channel.Because)
	}
	d := &f.Details
	d.HTTP = clone(d.HTTP)
	if h := d.HTTP; h != nil {
		h.Query, h.Headers, h.Form = cloneValues(h.Query), cloneValues(h.Headers), cloneValues(h.Form)
		h.Secrets = slices.Clone(h.Secrets)
		h.Body, err = CloneJSON(h.Body)
		if err != nil {
			return f, err
		}
		h.HeaderJSON, err = cloneObject(h.HeaderJSON)
		if err != nil {
			return f, err
		}
	}
	d.GraphQL = clone(d.GraphQL)
	if g := d.GraphQL; g != nil {
		g.Fields = slices.Clone(g.Fields)
		for i := range g.Fields {
			g.Fields[i].Arguments, err = cloneObject(g.Fields[i].Arguments)
			if err != nil {
				return f, err
			}
		}
	}
	d.MCP = clone(d.MCP)
	if m := d.MCP; m != nil {
		m.Arguments, err = CloneJSON(m.Arguments)
		if err != nil {
			return f, err
		}
	}
	d.SSH = clone(d.SSH)
	if d.SSH != nil {
		d.SSH.Env = clone(d.SSH.Env)
	}
	d.Command = clone(d.Command)
	if d.Command != nil {
		d.Command.Argv = slices.Clone(d.Command.Argv)
	}
	d.Payload = clone(d.Payload)
	if d.Payload != nil {
		d.Payload.Parents = slices.Clone(d.Payload.Parents)
	}
	d.SMTP = clone(d.SMTP)
	if d.SMTP != nil {
		d.SMTP.To = slices.Clone(d.SMTP.To)
	}
	d.Mail = clone(d.Mail)
	if m := d.Mail; m != nil {
		m.From, m.To, m.Cc, m.Attachments = slices.Clone(m.From), slices.Clone(m.To), slices.Clone(m.Cc), slices.Clone(m.Attachments)
	}
	d.SFTP = clone(d.SFTP)
	if d.SFTP != nil {
		d.SFTP.Attributes = maps.Clone(d.SFTP.Attributes)
	}
	d.Browser = clone(d.Browser)
	if d.Browser != nil {
		d.Browser.Secrets = slices.Clone(d.Browser.Secrets)
	}
	d.Redis = clone(d.Redis)
	if d.Redis != nil {
		d.Redis.Argv = slices.Clone(d.Redis.Argv)
	}
	d.MQTT = clone(d.MQTT)
	if d.MQTT != nil {
		d.MQTT.Payload = slices.Clone(d.MQTT.Payload)
	}
	d.NATS = clone(d.NATS)
	if d.NATS != nil {
		d.NATS.Payload = slices.Clone(d.NATS.Payload)
		d.NATS.Headers = cloneValues(d.NATS.Headers)
	}
	d.IMAP, d.Postgres, d.Sign, d.TCP = clone(d.IMAP), clone(d.Postgres), clone(d.Sign), clone(d.TCP)
	d.Message = clone(d.Message)
	if m := d.Message; m != nil {
		m.Body, err = CloneJSON(m.Body)
		if err != nil {
			return f, err
		}
		m.Channel.Because = maps.Clone(m.Channel.Because)
	}
	return f, nil
}

func clone[T any](value *T) *T {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func cloneValues[M ~map[string][]string](values M) M {
	if values == nil {
		return nil
	}
	out := make(M, len(values))
	for key, value := range values {
		out[key] = slices.Clone(value)
	}
	return out
}

func cloneObject(value map[string]any) (map[string]any, error) {
	frozen, err := CloneJSON(value)
	out, _ := frozen.(map[string]any)
	return out, err
}
