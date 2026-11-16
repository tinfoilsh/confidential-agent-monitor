// Command perimeter serves the Perimeter: agents reach their connections through SSH under the
// owner's policy, and the owner manages it over the owner API. This file is the Perimeter's only
// composition root; every product decision lives here.
package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"embed"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"code.dny.dev/ssrf"
	"filippo.io/edwards25519"
	"github.com/coder/websocket"
	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/flynn/noise"
	"github.com/klauspost/compress/gzhttp"
	"github.com/lestrrat-go/jwx/v3/jwk"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/pmezard/go-difflib/difflib"
	"github.com/tinfoilsh/confidential-agent-monitor/admission"
	"github.com/tinfoilsh/confidential-agent-monitor/approval"
	"github.com/tinfoilsh/confidential-agent-monitor/attestation"
	"github.com/tinfoilsh/confidential-agent-monitor/catalog"
	"github.com/tinfoilsh/confidential-agent-monitor/certificates"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/email"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/mcp"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/mqtt"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/nats"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/postgres"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/redis"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/session"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/signer"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/tcp"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/web"
	"github.com/tinfoilsh/confidential-agent-monitor/core"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/credential"
	"github.com/tinfoilsh/confidential-agent-monitor/document"
	"github.com/tinfoilsh/confidential-agent-monitor/httpjson"
	"github.com/tinfoilsh/confidential-agent-monitor/identity"
	"github.com/tinfoilsh/confidential-agent-monitor/messages"
	"github.com/tinfoilsh/confidential-agent-monitor/netx"
	"github.com/tinfoilsh/confidential-agent-monitor/noisetransport"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeterformat"
	"github.com/tinfoilsh/confidential-agent-monitor/policy/opa"
	"github.com/tinfoilsh/confidential-agent-monitor/sealedlog"
	"github.com/tinfoilsh/confidential-agent-monitor/slots"
	"github.com/tinfoilsh/confidential-agent-monitor/sshtransport"
	"github.com/tinfoilsh/confidential-agent-monitor/ui"
	"github.com/tinfoilsh/confidential-agent-monitor/worker"
	"github.com/tinfoilsh/tinfoil-go/verify"
	tinfoildoc "github.com/tinfoilsh/tinfoil-go/verify/document"
	"gocloud.dev/blob"
	_ "gocloud.dev/blob/fileblob"
	_ "gocloud.dev/blob/s3blob"
	"gocloud.dev/gcerrors"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
)

const (
	storageBucketEnv  = "TINFOIL_STORAGE_BUCKET"
	bucketEnv         = "MONITOR_BUCKET"
	ownerPublicKeyEnv = "MONITOR_OWNER_PUBLIC_KEY"
	defaultListen     = "127.0.0.1:2223"
	defaultAPI        = "127.0.0.1:8080"
	defaultWorkerRoot = "/opt/monitor/worker"
	serveWorkerFlag   = "serve-connector-worker"
)

var (
	listen           = flag.String("listen", defaultListen, "SSH address; it refuses agents until unlock")
	api              = flag.String("api", defaultAPI, "owner API address")
	bucketURL        = flag.String("bucket", cmp.Or(os.Getenv(storageBucketEnv), os.Getenv(bucketEnv)), "blob URL holding the encrypted state")
	production       = flag.Bool("production", false, "disable development features, including with a file:// bucket")
	uiDevURL         = flag.String("ui-dev-url", "", "proxy local UI development to a loopback Vite server (bun dev/run.ts)")
	ownerPublicKey   = flag.String("owner-public-key", os.Getenv(ownerPublicKeyEnv), "Ed25519 owner public key")
	ownerSessionKey  = flag.String("owner-session-key", "", "runtime attested X25519 key for owner sessions")
	connectorWorkers = flag.Bool("connector-workers", false, "run all connectors in isolated worker processes")
	workerRoot       = flag.String("worker-root", defaultWorkerRoot, "prepared read-only filesystem for connector workers")
	serveWorker      = flag.Bool(serveWorkerFlag, false, "serve one connector on inherited descriptors")
)

// The product configuration flags select, fixed before serving.
var (
	sshHostKey     ssh.Signer // nil: the stored host key
	unlockKey      []byte
	extraPresets   fs.FS
	identityCA     ssh.PublicKey // signs expiring SSH certificates that name an identity and its groups; nil: only registered keys connect
	basePolicy     string
	policyFile     string // loaded at each unlock in place of the stored policy
	secretFiles    *os.Root
	ownerOrigins   []string
	development    bool
	passphraseKeys bool          // only bearer development accepts storage passphrases
	workers        *worker.Local // nil: connectors run in this process
	presets        map[string]*catalog.Preset
	presetDefaults map[string]json.RawMessage
	adminRoutes    map[string]http.Handler // owner-only admin routes by ServeMux pattern
	// identityAttributes validate an identity's other keys, each by its name.
	identityAttributes = map[string]func(json.RawMessage) error{sandboxAttribute: validateBoot}
	// events is the stream a collector reads: one JSON line on stdout for each settled record.
	events = slog.New(slog.NewJSONHandler(os.Stdout, nil))
)

func init() {
	flag.Func("ssh-host-key", "runtime attested SSH private key", func(path string) error {
		data, err := os.ReadFile(path)
		if err == nil {
			sshHostKey, err = ssh.ParsePrivateKey(data)
		}
		return err
	})
	flag.Func("owner-key-file", "development owner key to unlock with at start", func(path string) error {
		key, err := os.ReadFile(path)
		if err == nil {
			unlockKey, err = base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(key)))
		}
		return err
	})
	flag.Func("owner-origins", "comma-separated browser origins allowed to call the owner API, such as https://console.example.com", func(list string) error {
		for _, origin := range strings.Split(list, ",") {
			if origin = strings.TrimSpace(origin); origin == "" {
				continue
			}
			u, err := url.Parse(origin)
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Scheme+"://"+u.Host != origin {
				return fmt.Errorf("owner origin %q must be scheme://host[:port]", origin)
			}
			ownerOrigins = append(ownerOrigins, origin)
		}
		return nil
	})
	flag.Func("identity-ca", "file holding one SSH CA public key in authorized_keys format; its expiring user certificates name identities and their groups. A label follows the certified key, so the issuer must not certify a second key for a running workload", func(path string) error {
		data, err := os.ReadFile(path)
		if err == nil {
			identityCA, _, _, _, err = ssh.ParseAuthorizedKey(data)
		}
		return err
	})
	flag.Func("base-policy", "Rego file in package perimeter.base; its deny and approvals apply to every decision as owner policy's do, its admin_allow and admin_deny to every admin call, and its capable grants identities the routes, config and propose capabilities; owner policy cannot change it", func(path string) error {
		base, err := os.ReadFile(path)
		basePolicy = string(base)
		return err
	})
	flag.Func("policy-file", "TOML policy loaded at each unlock in place of the stored one; the admin API then cannot change the policy", func(path string) error {
		policyFile = path
		return nil
	})
	flag.Func("presets", "directory of an organization's own preset definitions, added to the shipped ones", func(path string) error {
		extraPresets = os.DirFS(path)
		_, err := fs.Stat(extraPresets, ".")
		return err
	})
	flag.Func("secrets", "directory that file credentials are read from at each use", func(path string) (err error) {
		secretFiles, err = os.OpenRoot(path)
		return err
	})
}

// ---------------------------------------------------------------------------
// Standard policy and its vocabulary.

// factsVersion identifies the request facts schema and approval semantics. Bump it when
// parsing, description, normalization, label, or approval semantics change.
// This invalidates saved approvals; display-only edits do not need a bump.
const factsVersion = 13

const (
	kindOperation = "operation"
	kindAdmission = "admission"
	// sendsConnection resolves to the connection's configured audience; the standard policy matches the same value.
	sendsConnection = "connection"
)

// obligations describes the requirements carried by an effect.
type obligations struct {
	Change    bool `json:"change"`
	Trust     bool `json:"trust"`
	Ask       bool `json:"ask"` // Default effect setting; owners may override it.
	Discloses bool `json:"discloses"`
}

// vocabulary is shared by preset validation, request descriptions, policy, and UI.
var vocabulary = map[string]obligations{
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

var (
	audiences    = []string{"me", "team", "anyone"}
	trusts       = []string{"untrusted", "trusted"}
	initialLabel = perimeterformat.Label{Trust: "trusted", Audience: "anyone"}
)

func validLabel(l perimeterformat.Label) bool {
	return slices.Contains(audiences, l.Audience) && slices.Contains(trusts, l.Trust)
}

func validEffects(effects []string) bool {
	return len(effects) != 0 && !slices.ContainsFunc(effects, func(effect string) bool { _, ok := vocabulary[effect]; return !ok })
}

// Policy modules and queries. Owner policy may not use the protected data names or packages;
// the base policy is exactly basePackage.
const (
	standardModule = "perimeter/lib.rego"
	baseModule     = "perimeter/base.rego"
	queryDecision  = "decision"
	queryAdmin     = "admin"
	queryCapable   = "capable"
)

var (
	policyQueries = map[string]string{queryDecision: "data.perimeter.decision", queryAdmin: "data.perimeter.admin_deny", queryCapable: "data.perimeter.capable"}
	protectedData = []string{"perimeter", "lattices", "levels"}
	basePackage   = []string{"perimeter", "base"}
)

const standardPolicy = `package perimeter

import input.authorization as auth
import input.connection as conn
import input.facts
import input.facts.context as hint
import input.facts.context.label
import input.facts.operation as op

# Each axis orders its levels from most to least restrictive.
rank := {
	"audience": {name: i | some i, name in data.levels.audiences},
	"trust": {name: i | some i, name in data.levels.trusts},
}

obligations contains name if {
	some effect in op.effects
	some name, true in data.levels.effects[effect]
}

unknown if op == null
admission if facts.kind == "admission"
changes if "change" in obligations
discloses if "discloses" in obligations

default request := "read"

request := "unknown" if {
	unknown
} else := "change" if {
	changes
}

grants := {
	"read": {"unknown": "off", "read": "allow", "change": "off"},
	"ask": {"unknown": "ask", "read": "allow", "change": "ask"},
	"allow": {"unknown": "ask", "read": "allow", "change": "allow"},
}

# Lineage runs from the operation's own action up through its ancestors.
overrides := [m | some action in op.lineage; m := auth.access.actions[action]]

default mode := "off"

mode := overrides[0] if {
	overrides != []
} else := "allow" if {
	# A session opens to any service the bunker reaches.
	admission
	auth.reaches
} else := grants[auth.access.level][request] if {
	grants[auth.access.level]
}

effect_defaults := {effect: {true: "ask", false: "allow"}[o.ask] | some effect, o in data.levels.effects}

# Paid model operations carry both generate and pay; an explicit pay setting at any scope still wins.
paid := {"pay": "allow"} if {
	auth.allow_paid_inference
	"generate" in op.effects
	"pay" in op.effects
} else := {}

# Scopes run from global settings to this bunker's access on this service; the most specific wins.
effects := object.union_n(array.concat([effect_defaults, paid], auth.effects))

# A preset's public scope lists the parameters that together name one resource, such as owner and repo.
names := [v | some key in conn.public_scope; v := facts.parameters[key]; is_string(v); v != ""]

resource := concat("/", names) if {
	names != []
	count(names) == count(conn.public_scope)
}

# The owner marks resources private with globs such as tinfoilsh/*; any other named resource is public.
private if {
	some pattern in conn.private
	glob.match(pattern, ["/"], resource)
}

public if {
	resource
	not private
}

target := resource if changes

# A change to a public resource reaches anyone, whatever the connector hints; so does an unplaced disclosure.
sends := "anyone" if {
	changes
	public
} else := "anyone" if {
	hint.sends == ""
	discloses
	not target
} else := conn.sends if {
	hint.sends in {"", "connection"}
} else := hint.sends

expected := object.union(
	{"audience": conn.contents, "trust": {true: "untrusted", false: "trusted"}[conn.strangers]},
	{axis: level | some axis, _ in rank; level := hint.observes[axis]; level != ""},
)

# An unrecognized request may return anything; a public resource holds nothing private.
observes := {"audience": "me", "trust": "untrusted"} if {
	unknown
} else := object.union(expected, {"audience": "anyone"}) if {
	public
} else := expected

# The label keeps each axis's provenance unless this request makes it more restrictive.
lowered[axis] := level if {
	some axis, level in observes
	rank[axis][level] < rank[axis][label[axis]]
}

because := object.get(label, "because", {})

next := {
	"audience": object.get(lowered, "audience", label.audience),
	"trust": object.get(lowered, "trust", label.trust),
	"because": object.union(because, {axis: facts.connection | some axis, _ in lowered}),
}

# Owner policy is package sentinel. The base policy is package perimeter.base, which owner policy cannot change.
denies["owner"] := data.sentinel.deny

denies["base"] := data.perimeter.base.deny

collection(x) if is_array(x)

collection(x) if is_set(x)

approvals["owner"] := data.sentinel.approvals

approvals["base"] := data.perimeter.base.approvals

valid_approvals contains source if {
	some source, a in approvals
	collection(a)
	every r in a {
		regex.match(sprintf(` + "`" + `^%s\.[a-zA-Z0-9][a-zA-Z0-9_.-]*$` + "`" + `, [source]), r.id)
		trim_space(r.message) != ""
	}

	# Repeated identical entries are harmless; conflicting messages for one ID are not.
	count({r.id | some r in a}) == count({r | some r in a})
}

deny contains "This bunker does not have permission for this action." if mode == "off"

deny contains sprintf("The %s effect is set to Deny.", [effect]) if {
	some effect in op.effects
	effects[effect] == "off"
}

# Element types are checked when the decision is decoded; a wrong container would deny nothing.
deny contains sprintf("%s policy deny must be a set or array of strings", [source]) if {
	some source, hook in denies
	not collection(hook)
}

deny contains msg if some msg in denies[_]

deny contains sprintf("%s policy approvals must be a set or array of {id, message} objects with unique %s.* IDs and nonempty messages", [source, source]) if {
	some source, _ in approvals
	not source in valid_approvals
}

# A waiver of this gap covers only the audience it was approved for.
disclosure := concat(".", ["audience", sends])

needs_trust if unknown
needs_trust if "trust" in obligations

builtin contains "ask" if mode != "allow"

# Confidentiality: what the agent has seen goes to no wider an audience than its label.
builtin contains disclosure if {
	data.lattices.confidentiality
	not rank.audience[sends] <= rank.audience[label.audience]
}

# Integrity: an agent that has read untrusted content does nothing that requires trust.
builtin contains "trust" if {
	data.lattices.integrity
	label.trust == "untrusted"
	needs_trust
}

waived contains id if some id in auth.approved

waived contains requirement.id if {
	some r in auth.rules
	not r.enabled == false
	r.version == facts.version
	r.connection == facts.connection
	r.operation == op.id
	r.scope == auth.grant
	some requirement in r.requirements
}

base_gaps := builtin - waived if not admission
base_gaps := set() if admission

ask_message := sprintf("This request has no recognized operation on %s.", [facts.connection]) if unknown
ask_message := sprintf("This request needs your approval on %s.", [facts.connection]) if not unknown

recipients := {"me": "you", "team": "your team", "anyone": "anyone"}

messages := {
	"ask": ask_message,
	disclosure: sprintf("This agent has seen private data from %s; this request can disclose it to %s.", [object.get(because, "audience", "an earlier request"), object.get(recipients, sends, "an unknown audience")]),
	"trust": sprintf("This agent has read untrusted content from %s; this operation requires trust.", [object.get(because, "trust", "an earlier request")]),
}

requirements contains {"id": id, "message": message} if some id, message in object.filter(messages, base_gaps)

requirements contains {"id": id, "message": sprintf("The %s effect requires approval (Ask).", [effect])} if {
	some effect in op.effects
	effects[effect] == "ask"
	id := concat("", ["effect.", effect])
	not id in waived
}

requirements contains r if {
	some source in valid_approvals
	some r in approvals[source]
	not r.id in waived
}

gaps contains r.id if some r in requirements

decision := {"deny": deny, "requirements": requirements, "sends": sends, "next": next}

# input is an admin call: its caller and route, plus the answer and record of an answer.
# An identity calling under the agent API's /admin/ is a non-owner caller whose claims are its key and groups.
default admin_allow := false

admin_allow if input.caller.owner

admin_allow if data.perimeter.base.admin_allow == true

admin_deny contains "The base policy does not allow this caller to make this call." if not admin_allow

admin_deny contains "base policy admin_deny must be a set or array of strings" if {
	hook := data.perimeter.base.admin_deny
	not collection(hook)
}

admin_deny contains msg if some msg in data.perimeter.base.admin_deny

admin_deny contains "An identity cannot answer its own request." if {
	not input.caller.owner
	input.record.facts.principal.name == input.caller.name
}

# input is an identity's capability: its principal, its stored routes flag and the capability's name.
default capable := false

capable if input.routes

capable if data.perimeter.base.capable == true
`

// ---------------------------------------------------------------------------
// Settings: the owner's TOML policy source, validated and projected.

const (
	agentConnection = "agent"
	maxPolicyBytes  = 2 << 20
)

var (
	accessLevels = []string{"off", "read", "ask", "allow"}
	effectModes  = []string{"off", "ask", "allow"}
)

// ConnectionSpec supplies one connector's setup and opaque semantic definition.
type ConnectionSpec struct {
	Name, Protocol              string
	Config, Definition, Options json.RawMessage
	PublicScope                 []string
}

type Access struct {
	Level   string            `json:"level"`
	Actions map[string]string `json:"actions,omitempty"`
	Effects map[string]string `json:"effects,omitempty"`
}

// Requirement IDs bind approval waivers; messages explain them without granting authority.
type Requirement struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}

// A rule waives the requirements it names for one operation and scope.
type Rule struct {
	Enabled      *bool          `json:"enabled,omitempty"`
	Version      int            `json:"version"` // factsVersion it was approved under.
	Connection   string         `json:"connection"`
	Action       string         `json:"action"`
	Operation    string         `json:"operation,omitempty"`
	Definition   string         `json:"definition,omitempty"` // Read from rules saved before Version; never matched.
	Scope        map[string]any `json:"scope"`
	Requirements []Requirement  `json:"requirements"`
}

type Identity struct {
	// Stored configs and enrollment clients name this "routes".
	Operator    bool              `json:"routes,omitempty"`
	Key         string            `json:"key"`
	Groups      []string          `json:"groups,omitempty"`
	Effects     map[string]string `json:"effects,omitempty"`
	Connections map[string]Access `json:"connections"`
	Rules       map[string]Rule   `json:"rules,omitempty"`
	// Attributes are an identity's other keys, each checked by the validator registered under its name.
	Attributes map[string]json.RawMessage `json:",embed"`
}

// PolicyOptions retains the source format. Origin/address also bind local connector semantics.
type PolicyOptions struct {
	Private []string `json:"private,omitempty"`
	Address string   `json:"address,omitempty"`
	Origin  string   `json:"origin,omitempty"`
}

// Connection holds one connector's settings, and its setup under the connector's kind.
type Connection struct {
	Preset        string                     `json:"preset"`
	Effects       map[string]string          `json:"effects,omitempty"`
	PolicyOptions PolicyOptions              `json:"policy_options"`
	Contents      string                     `json:"contents"`
	Strangers     bool                       `json:"strangers"`
	Sends         string                     `json:"sends"`
	Setup         map[string]json.RawMessage `json:"-"`
}

type connectionSettings Connection

// settingKeys name a connection's settings; its other key is its connector's kind.
var settingKeys = []string{"preset", "effects", "policy_options", "contents", "strangers", "sends"}

func (c *Connection) UnmarshalJSON(raw []byte) error {
	var setup map[string]json.RawMessage
	if err := json.Unmarshal(raw, &setup); err != nil {
		return err
	}
	var settings connectionSettings
	if err := json.Unmarshal(raw, &settings); err != nil {
		return err
	}
	maps.DeleteFunc(setup, func(key string, _ json.RawMessage) bool { return slices.Contains(settingKeys, key) })
	*c = Connection(settings)
	c.Setup = setup
	return nil
}

func (c Connection) MarshalJSON() ([]byte, error) {
	raw, err := json.Marshal(connectionSettings(c))
	if err != nil || len(c.Setup) == 0 {
		return raw, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return nil, err
	}
	maps.Copy(fields, c.Setup)
	return json.Marshal(fields)
}

type Lattices struct {
	Confidentiality bool `json:"confidentiality"`
	Integrity       bool `json:"integrity"`
}

// Config is immutable declared settings. Inheritance and setup defaults are
// projected for their consumers, never written back into these declarations.
type Config struct {
	AllowPaidInference bool                  `json:"allow_paid_inference,omitempty"`
	Effects            map[string]string     `json:"effects,omitempty"`
	DefaultAccess      map[string]Access     `json:"default_access,omitempty"`
	Lattices           Lattices              `json:"lattices"`
	AllowNetworks      []netip.Prefix        `json:"allow_networks"`
	Connections        map[string]Connection `json:"connections"`
	Identities         map[string]Identity   `json:"identities"`
	Policies           map[string]string     `json:"policies"`
	Data               map[string]any        `json:"data"`
	Principals         map[string]string     `json:"-"`
}

func validateEffects(name string, effects map[string]string) error {
	for effect, mode := range effects {
		if _, ok := vocabulary[effect]; !ok {
			return fmt.Errorf("%s: unknown effect %q", name, effect)
		}
		if !slices.Contains(effectModes, mode) {
			return fmt.Errorf("%s: effect %s must be off, ask or allow", name, effect)
		}
	}
	return nil
}

func inheritModes(defaults, overrides map[string]string) map[string]string {
	merged := make(map[string]string, len(defaults)+len(overrides))
	maps.Copy(merged, defaults)
	maps.Copy(merged, overrides)
	return merged
}

// loadConfig validates declared settings without retaining expanded connections or identities.
// Protocol decoding and credential binding remain at the connector boundary.
func loadConfig(text string) (*Config, error) {
	if len(text) > maxPolicyBytes {
		return nil, errors.New("policy source is too large")
	}
	decoded, err := perimeterformat.ReadTOML(text)
	if err != nil {
		return nil, err
	}
	cfg := &Config{Lattices: Lattices{Confidentiality: true}}
	raw, err := json.Marshal(decoded)
	if err == nil {
		err = facts.DecodeNumbers(raw, cfg)
	}
	if err != nil {
		return nil, err
	}
	if err := validateEffects("global settings", cfg.Effects); err != nil {
		return nil, err
	}
	for name, c := range cfg.Connections {
		if err := validateEffects("service "+name, c.Effects); err != nil {
			return nil, err
		}
		if !slices.Contains(audiences, c.Contents) || !slices.Contains(audiences, c.Sends) {
			return nil, fmt.Errorf("service %s: contents and sends must be one of %v", name, audiences)
		}
		if name == agentConnection {
			return nil, fmt.Errorf("service name %s is reserved", name)
		}
		if _, err := cfg.Spec(name); err != nil {
			return nil, err
		}
	}
	validateAccess := func(name string, connections map[string]Access) error {
		for connection, a := range connections {
			if _, ok := cfg.Connections[connection]; !ok || !slices.Contains(accessLevels, a.Level) {
				return fmt.Errorf("%s: service %s must exist and have a level in %v", name, connection, accessLevels)
			}
			if err := validateEffects(name+" on "+connection, a.Effects); err != nil {
				return err
			}
			for action, level := range a.Actions {
				if !slices.Contains(effectModes, level) {
					return fmt.Errorf("%s: action %s must be off, ask or allow", name, action)
				}
			}
		}
		return nil
	}
	if err := validateAccess("default access", cfg.DefaultAccess); err != nil {
		return nil, err
	}
	cfg.Principals = map[string]string{}
	for name, id := range cfg.Identities {
		if err := validateEffects("agent "+name, id.Effects); err != nil {
			return nil, err
		}
		if err := validateAccess("identity "+name, cfg.Accesses(name)); err != nil {
			return nil, err
		}
		fingerprint, err := keyFingerprint(id.Key)
		if err != nil {
			return nil, fmt.Errorf("identity %s: %w", name, err)
		}
		if _, exists := cfg.Principals[fingerprint]; exists {
			return nil, fmt.Errorf("identity %s shares another identity's public key", name)
		}
		cfg.Principals[fingerprint] = name
	}
	return cfg, nil
}

// keyFingerprint names the principal an identity's authorized key authenticates.
func keyFingerprint(authorizedKey string) (string, error) {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(authorizedKey))
	if err != nil {
		return "", err
	}
	return ssh.FingerprintSHA256(key), nil
}

func (c *Config) Principal(key string) (facts.Principal, bool) {
	name, ok := c.Principals[key]
	return facts.Principal{Key: key, Name: name, Groups: c.Identities[name].Groups, Attributes: c.Identities[name].Attributes}, ok
}

// An explicit level replaces defaults; an omitted level inherits and overlays them.
func (c *Config) Access(agent, connection string) Access {
	a := c.Identities[agent].Connections[connection]
	if a.Level == "" {
		base := c.DefaultAccess[connection]
		a.Level = base.Level
		a.Actions = inheritModes(base.Actions, a.Actions)
		a.Effects = inheritModes(base.Effects, a.Effects)
	}
	return a
}

func (c *Config) Accesses(agent string) map[string]Access {
	connections := map[string]Access{}
	maps.Copy(connections, c.DefaultAccess)
	maps.Copy(connections, c.Identities[agent].Connections)
	for connection := range connections {
		connections[connection] = c.Access(agent, connection)
	}
	return connections
}

func (c *Config) Reaches(agent, connection string) bool {
	a := c.Access(agent, connection)
	if a.Level != "" && a.Level != "off" {
		return true
	}
	for _, mode := range a.Actions {
		if mode != "off" {
			return true
		}
	}
	return false
}

// Spec projects only this connection's setup; the returned definition remains opaque.
func (c *Config) Spec(name string) (ConnectionSpec, error) {
	connection := c.Connections[name]
	preset := presets[connection.Preset]
	if preset == nil {
		return ConnectionSpec{}, fmt.Errorf("service %s: unknown preset %s", name, connection.Preset)
	}
	// Parsers consume title, action effects and their opaque protocol roots.
	// Keep those roots as RawMessages so grant encodings retain their inner order;
	// catalog labels/defaults are control data, while title remains facts input.
	var definition map[string]json.RawMessage
	if err := json.Unmarshal(preset.Source, &definition); err != nil {
		return ConnectionSpec{}, err
	}
	actions := map[string]map[string][]string{}
	for name, action := range preset.Catalog.Actions {
		if action.Effects != nil {
			actions[name] = map[string][]string{"effects": action.Effects}
		}
	}
	definition["catalog"], _ = json.Marshal(map[string]any{"actions": actions})
	semantic, _ := json.Marshal(definition)
	raw, _ := json.Marshal(preset.Catalog.Connection)
	if preset.Catalog.Connection == nil {
		raw = []byte(`{}`)
	}
	if connection.Setup != nil {
		patch, _ := json.Marshal(connection.Setup)
		var err error
		if raw, err = jsonpatch.MergePatch(raw, patch); err != nil {
			return ConnectionSpec{}, err
		}
	}
	var kinds map[string]any
	if err := facts.DecodeNumbers(raw, &kinds); err != nil {
		return ConnectionSpec{}, err
	}
	if len(kinds) != 1 {
		return ConnectionSpec{}, fmt.Errorf("service %s must have one kind", name)
	}
	local := connection.PolicyOptions
	local.Private = nil // Private patterns affect Gate, not connector interpretation.
	options, _ := json.Marshal(local)
	spec := ConnectionSpec{Name: name, Definition: semantic, Options: options, PublicScope: preset.PublicScope}
	for kind, value := range kinds {
		spec.Protocol = kind
		spec.Config, _ = json.Marshal(value) // Setup bytes retain the deployed canonical grant encoding.
	}
	return spec, nil
}

// Edit applies changes to source and reports which connections' connector setup
// then differs from c's, and which connections it moved from which name. Rules
// approved for a connection whose setup differs are removed in the same edit.
// Changes that alter no setting leave source as it was.
func (c *Config) Edit(source string, changes []perimeterformat.Change) (string, func(connection string) bool, map[string]string, error) {
	edited, err := perimeterformat.EditTOML(source, changes)
	if err != nil {
		return "", nil, nil, err
	}
	next, err := loadConfig(edited)
	if err != nil {
		return "", nil, nil, err
	}
	if reflect.DeepEqual(next, c) {
		return source, func(string) bool { return false }, nil, nil
	}
	networks := !slices.Equal(c.AllowNetworks, next.AllowNetworks)
	renamed := map[string]string{}
	for _, change := range changes {
		if len(change.Path) != 2 || len(change.From) != 2 || change.Path[0] != "connections" || change.From[0] != "connections" {
			continue
		}
		_, was := c.Connections[change.From[1]]
		if _, still := next.Connections[change.From[1]]; was && !still {
			renamed[change.Path[1]] = change.From[1]
		}
	}
	setup := func(connection string) bool {
		before, _ := c.Spec(cmp.Or(renamed[connection], connection))
		after, _ := next.Spec(connection)
		before.Name = after.Name
		return !reflect.DeepEqual(before, after)
	}
	var stale []perimeterformat.Change
	for _, name := range slices.Sorted(maps.Keys(next.Identities)) {
		rules := next.Identities[name].Rules
		for _, id := range slices.Sorted(maps.Keys(rules)) {
			if setup(rules[id].Connection) {
				stale = append(stale, perimeterformat.Change{Path: []string{"identities", name, "rules", id}, Delete: true})
			}
		}
	}
	if stale != nil {
		edited, err = perimeterformat.EditTOML(edited, stale)
	}
	return edited, func(connection string) bool { return networks || setup(connection) }, renamed, err
}

// View expands the existing owner wire representation only while rendering it.
// No caller uses this presentation as settings or connector authority.
func (c *Config) View() (map[string]any, error) {
	v := *c
	v.Identities, v.Connections = maps.Clone(c.Identities), maps.Clone(c.Connections)
	for name, id := range v.Identities {
		id.Connections = c.Accesses(name)
		v.Identities[name] = id
	}
	for name, connection := range v.Connections {
		spec, err := c.Spec(name)
		if err != nil {
			return nil, err
		}
		connection.Setup = map[string]json.RawMessage{spec.Protocol: spec.Config}
		v.Connections[name] = connection
	}
	return facts.JSON[map[string]any](v)
}

// Effective preserves the expanded TOML control view, never compiling policy.
func (c *Config) Effective() (string, error) {
	v, err := c.View()
	if err != nil {
		return "", err
	}
	ps := map[string]any{}
	for _, connection := range c.Connections {
		if ps[connection.Preset], err = facts.JSON[map[string]any](presets[connection.Preset]); err != nil {
			return "", err
		}
	}
	v["presets"] = ps
	return perimeterformat.RenderTOML(v)
}

// AgentView is the restricted configuration returned to an agent. Proposals may
// request broader changes, but never reveal owner-only state.
func (c *Config) AgentView(p facts.Principal) (map[string]any, error) {
	identity := map[string]any{"connections": c.Accesses(p.Name)}
	if rules := c.Identities[p.Name].Rules; len(rules) != 0 {
		identity["rules"] = rules
	}
	connections := map[string]any{}
	for name, connection := range c.Connections {
		if c.Reaches(p.Name, name) {
			connections[name] = map[string]any{"contents": connection.Contents, "strangers": connection.Strangers, "sends": connection.Sends, "policy_options": connection.PolicyOptions}
		}
	}
	return facts.JSON[map[string]any](map[string]any{"lattices": c.Lattices, "identities": map[string]any{p.Name: identity}, "connections": connections})
}

// proposalTarget names the connection whose setup or access path changes.
func proposalTarget(path []string) (string, bool) {
	switch {
	case len(path) >= 2 && (path[0] == "connections" || path[0] == "default_access") && path[1] != "":
		return path[1], true
	case len(path) >= 4 && path[0] == "identities" && path[1] != "" && path[2] == "connections" && path[3] != "":
		return path[3], true
	}
	return "", false
}

// proposalChanges groups p's changes by connection; only others lets them reach other identities and default access.
func proposalChanges(p facts.Principal, changes []perimeterformat.Change, others bool) (map[string][]perimeterformat.Change, error) {
	groups := map[string][]perimeterformat.Change{}
	for _, change := range changes {
		target, ok := proposalTarget(change.Path)
		if !ok || change.From != nil {
			return nil, errors.New("proposals may change only service setup and access")
		}
		if !others && (change.Path[0] == "default_access" || change.Path[0] == "identities" && change.Path[1] != p.Name) {
			return nil, errors.New("this identity may propose only service setup and its own access")
		}
		groups[target] = append(groups[target], change)
	}
	return groups, nil
}

// ---------------------------------------------------------------------------
// Presets: the shipped protocol descriptions, an organization's own, and the owner catalog.

//go:embed presets/*.json
var shippedPresets embed.FS

// connectionDefaults are the settings the owner UI proposes for a new connection of a preset.
type connectionDefaults struct {
	Contents  string `json:"contents"`
	Sends     string `json:"sends"`
	Strangers bool   `json:"strangers"`
}

var (
	privateDefaults    = connectionDefaults{Contents: "me", Sends: "me", Strangers: true}
	personalDefaults   = connectionDefaults{Contents: "me", Sends: "anyone", Strangers: true}
	teamDefaults       = connectionDefaults{Contents: "team", Sends: "team", Strangers: true}
	teamPrivate        = connectionDefaults{Contents: "team", Sends: "me", Strangers: true}
	teamPublicDefaults = connectionDefaults{Contents: "team", Sends: "anyone", Strangers: true}
	publicDefaults     = connectionDefaults{Contents: "anyone", Sends: "anyone", Strangers: true}
)

// shippedDefaults selects a shipped preset's defaults: by service, then by its connection's kind.
// MCP servers and the GitHub API return team data only to the agent; other APIs can publish it.
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
		return teamPrivate
	case "slack_socket_mode":
		return teamDefaults
	}
	switch {
	case p.Catalog.Connection["mcp"] != nil:
		return teamPrivate
	case p.Catalog.Connection["http"] != nil:
		return teamPublicDefaults
	}
	return privateDefaults
}

// loadPresets decodes the shipped presets and an organization's own; an organization's
// preset keeps the defaults its catalog declares.
func loadPresets(extra fs.FS) (map[string]*catalog.Preset, map[string]json.RawMessage, error) {
	shipped, err := fs.Sub(shippedPresets, "presets")
	if err != nil {
		return nil, nil, err
	}
	out, defaults := map[string]*catalog.Preset{}, map[string]json.RawMessage{}
	for _, source := range []fs.FS{shipped, extra} {
		if source == nil {
			continue
		}
		files, _ := fs.Glob(source, "*.json")
		for _, file := range files {
			name := strings.TrimSuffix(file, ".json")
			if out[name] != nil {
				return nil, nil, fmt.Errorf("preset %s is already shipped", file)
			}
			raw, err := fs.ReadFile(source, file)
			var p *catalog.Preset
			if err == nil {
				p, err = catalog.Decode(raw)
			}
			if err == nil && source == extra {
				if defaults[name] = p.Catalog.Defaults; defaults[name] == nil {
					err = errors.New("catalog must be an object with defaults")
				}
			} else if err == nil {
				defaults[name], err = json.Marshal(shippedDefaults(name, p))
			}
			if err == nil {
				for action, a := range p.Catalog.Actions {
					if a.Effects != nil && !validEffects(a.Effects) {
						err = fmt.Errorf("invalid effects for action %s", action)
					}
				}
			}
			if err != nil {
				return nil, nil, fmt.Errorf("preset %s: %w", file, err)
			}
			out[name] = p
		}
	}
	return out, defaults, nil
}

// catalogEntry is the owner's catalog presentation. Operations are display metadata;
// their protocol definitions remain opaque until a connector decodes them.
type catalogEntry struct {
	*catalog.Catalog
	Title      string                       `json:"title"`
	Operations *map[string]operationSummary `json:"operations,omitempty"`
}

// catalogEntries is a control presentation, never an authorization or runtime registry.
func catalogEntries(cfg *Config, operations map[string]map[string]operationSummary) (map[string]catalogEntry, string, error) {
	used := map[string]bool{}
	for _, connection := range cfg.Connections {
		used[connection.Preset] = true
	}
	entries := map[string]catalogEntry{}
	for name, p := range presets {
		metadata := *p.Catalog
		metadata.Defaults = presetDefaults[name]
		entry := catalogEntry{Catalog: &metadata, Title: p.Title}
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

// ---------------------------------------------------------------------------
// State: the encrypted document, its settings, records and admissions.

const (
	stateObject = "monitor.enc"
	caName      = "perimeter dev CA"
	caLifetime  = 10 * 365 * 24 * time.Hour
	// Connection leaves are minted per handshake.
	leafLifetime = 24 * time.Hour
	leafBackdate = time.Hour
)

// Settled records are batched into immutable segments named by upload time, so
// storage credentials never need delete or overwrite access to the log.
var auditLimits = sealedlog.Limits{FlushInterval: time.Minute, WriteTimeout: 30 * time.Second, SegmentBytes: 8 << 20, MaxBacklog: 64 << 20, PageRecords: 200}

var errOwner error = httpError{perimeterformat.ErrKey, http.StatusUnauthorized}

// state is the running Perimeter. mu guards the document, records and admissions, and
// approval waits release it; writes serializes settings preparation, commit, delivery and
// final teardown. When both are needed, take writes before mu. The table's lock is taken
// inside either. Everything unlock creates is nil while locked.
type state struct {
	bucket     *blob.Bucket
	life       context.Context // ends the audit log's flushing
	flushing   sync.WaitGroup
	mu         sync.Mutex
	writes     sync.Mutex
	doc        document.Value[perimeterformat.Document]
	owner      []byte
	sealer     perimeterformat.Sealer
	audit      *sealedlog.Log
	settings   atomic.Pointer[settings]
	table      *core.Table
	routes     forwarder
	identities identity.Registry
	admissions admission.Set[*admitted]
	records    *approval.Records[*record]
	signIns    *credential.SignIns
}

func newState(life context.Context, bucket *blob.Bucket) *state {
	s := &state{bucket: bucket, life: life, signIns: credential.NewSignIns(signInClient, signInLimits)}
	s.records = approval.NewRecords(&s.mu, maxRecords, func(r *record) bool { return r.State == statePending })
	s.table = core.New(s.reaches, s.admit, selectTarget, connectorOpenTimeout)
	return s
}

func (s *state) generation() (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.doc.Get().Generation, s.settings.Load() != nil
}

func (s *state) snapshot() (perimeterformat.Document, *settings) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.doc.Get(), s.settings.Load()
}

// commit changes the document only after the encrypted write succeeds.
func (s *state) commit(ctx context.Context, next perimeterformat.Document) error {
	next.Generation++
	return s.doc.Commit(ctx, next, func(ctx context.Context, d perimeterformat.Document) error {
		plain, err := perimeterformat.EncodeDocument(d)
		if err != nil {
			return err
		}
		return s.bucket.WriteAll(ctx, stateObject, s.sealer.SealState(plain), nil)
	})
}

// load reads the stored document with key, or starts one if storage confirms there is none and
// no generation was saved. It changes nothing and rejects rollback below minimum.
func (s *state) load(ctx context.Context, key []byte, minimum uint64) (perimeterformat.Document, perimeterformat.Sealer, bool, error) {
	var doc perimeterformat.Document
	if len(key) < perimeterformat.MinKeyBytes || len(key) > perimeterformat.MaxKeyBytes {
		return doc, perimeterformat.Sealer{}, false, errOwner
	}
	raw, err := s.bucket.ReadAll(ctx, stateObject)
	missing := false
	if err != nil {
		if missing, err = stateMissing(ctx, s.bucket, err); err != nil {
			return doc, perimeterformat.Sealer{}, false, err
		}
	}
	if missing && minimum != 0 {
		return doc, perimeterformat.Sealer{}, false, fmt.Errorf("the Perimeter has no saved state, but generation %d was saved", minimum)
	}
	var sealer perimeterformat.Sealer
	if missing {
		sealer, err = perimeterformat.NewSealer(key)
		doc = perimeterformat.Document{Version: perimeterformat.StateVersion, Labels: map[string]perimeterformat.Label{}}
	} else {
		var plain []byte
		if sealer, plain, err = perimeterformat.OpenState(key, raw); err == nil {
			doc, err = perimeterformat.DecodeDocument(plain, v1Presets())
		}
	}
	if errors.Is(err, perimeterformat.ErrKey) {
		err = errOwner
	}
	if err == nil && doc.Generation < minimum {
		err = fmt.Errorf("stored generation %d is older than %d", doc.Generation, minimum)
	}
	return doc, sealer, missing, err
}

// v1Presets tells the version 1 upgrade which presets declare a connection.
func v1Presets() map[string]bool {
	declared := map[string]bool{}
	for name, p := range presets {
		declared[name] = p.Catalog.Connection != nil
	}
	return declared
}

// stateMissing confirms that a failed read means no state exists. S3 hides missing
// objects behind AccessDenied when ListBucket is scoped by prefix, so absence is
// confirmed with an authorized prefix listing. A denied listing or an existing
// unreadable object must never reset the state.
func stateMissing(ctx context.Context, bucket *blob.Bucket, err error) (bool, error) {
	switch gcerrors.Code(err) {
	case gcerrors.NotFound:
		return true, nil
	case gcerrors.PermissionDenied:
		items := bucket.List(&blob.ListOptions{Prefix: stateObject})
		for {
			item, listErr := items.Next(ctx)
			if errors.Is(listErr, io.EOF) {
				return true, nil
			}
			if listErr != nil {
				return false, errors.Join(err, listErr)
			}
			if item.Key == stateObject {
				return false, err
			}
		}
	}
	return false, err
}

// stateExists reports whether state is stored; a failed probe is never absence.
func stateExists(ctx context.Context, bucket *blob.Bucket) (bool, error) {
	_, err := bucket.Attributes(ctx, stateObject)
	if err == nil {
		return true, nil
	}
	missing, err := stateMissing(ctx, bucket, err)
	return !missing, err
}

func (s *state) isOwnerKey(key []byte) bool { return subtle.ConstantTimeCompare(key, s.owner) == 1 }

// unlock reports whether it created the Perimeter's state.
func (s *state) unlock(ctx context.Context, key []byte, minimum uint64) (bool, error) {
	s.writes.Lock()
	defer s.writes.Unlock()
	s.mu.Lock()
	if !passphraseKeys && len(key) != perimeterformat.KeyBytes {
		s.mu.Unlock()
		return false, errOwner
	}
	if s.settings.Load() != nil {
		defer s.mu.Unlock()
		if !s.isOwnerKey(key) {
			return false, errOwner
		}
		if generation := s.doc.Get().Generation; generation < minimum {
			return false, fmt.Errorf("live generation %d is older than %d", generation, minimum)
		}
		return false, nil
	}
	s.mu.Unlock()
	doc, sealer, created, err := s.load(ctx, key, minimum)
	if err != nil {
		return false, err
	}
	tlsConfig, err := connectionTLS(&doc.Keys)
	if err != nil {
		return false, err
	}
	signer := sshHostKey
	if signer == nil {
		if signer, err = storedHostKey(&doc.Keys); err != nil {
			return false, err
		}
	}
	source := doc.Policy
	if policyFile != "" {
		file, err := os.ReadFile(policyFile)
		if err != nil {
			return false, err
		}
		source = string(file)
	}
	plan, err := s.prepareSettings(ctx, source, everyConnection, nil, nil, tlsConfig, signer)
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	s.doc.Commit(ctx, doc, func(context.Context, perimeterformat.Document) error { return nil })
	s.owner, s.sealer = bytes.Clone(key), sealer
	s.audit = sealedlog.New(sealedlog.Storage{Write: s.bucketWrite, Read: s.bucket.ReadAll, List: s.bucketList}, auditPrefix, auditLimits, sealer.Seal, sealer.Open,
		func(err error) { log.Printf("audit: %v", err) })
	err = s.commitSettings(ctx, plan, nil)
	if err != nil {
		s.doc.Commit(ctx, perimeterformat.Document{}, func(context.Context, perimeterformat.Document) error { return nil })
		s.owner, s.sealer, s.audit = nil, perimeterformat.Sealer{}, nil
	} else {
		s.flushing.Go(func() { s.audit.Run(s.life) })
		s.recordAdmin(ctx, "Unlock", nil, nil)
	}
	s.mu.Unlock()
	if err != nil {
		return false, err
	}
	s.table.Start()
	return created, nil
}

func (s *state) bucketWrite(ctx context.Context, key string, data []byte) error {
	return s.bucket.WriteAll(ctx, key, data, nil)
}

func (s *state) bucketList(ctx context.Context, prefix, delimiter string) ([]string, error) {
	keys := []string{}
	items := s.bucket.List(&blob.ListOptions{Prefix: prefix, Delimiter: delimiter})
	for {
		item, err := items.Next(ctx)
		if errors.Is(err, io.EOF) {
			return keys, nil
		}
		if err != nil {
			return nil, err
		}
		keys = append(keys, item.Key)
	}
}

// close stops connectors and waits for the audit log's final flush once life has ended.
func (s *state) close() {
	s.writes.Lock()
	defer s.writes.Unlock()
	s.table.Close()
	s.flushing.Wait()
}

// isOwner reports whether key is a well-formed storage key and, once unlocked, the owner's.
// While locked any well-formed key passes; only unlock can check a key then.
func (s *state) isOwner(key []byte) bool {
	if len(key) < perimeterformat.MinKeyBytes || len(key) > perimeterformat.MaxKeyBytes {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settings.Load() == nil || s.isOwnerKey(key)
}

// connectionTLS mints connection leaves from the stored CA, creating it if keys have none.
func connectionTLS(keys *perimeterformat.Keys) (*tls.Config, error) {
	if keys.CACert == "" {
		created, err := certificates.NewAuthority(caName, caLifetime)
		if err != nil {
			return nil, err
		}
		keys.CACert, keys.CAKey = created.PEM()
	}
	authority, err := certificates.LoadAuthority(keys.CACert, keys.CAKey)
	if err != nil {
		return nil, err
	}
	return &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return authority.Issue(hello.ServerName, leafLifetime, leafBackdate)
	}}, nil
}

// storedHostKey is the stored SSH host key, created if keys have none.
func storedHostKey(keys *perimeterformat.Keys) (ssh.Signer, error) {
	if keys.HostKey == "" {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		block, err := ssh.MarshalPrivateKey(private, "")
		if err != nil {
			return nil, err
		}
		keys.HostKey = string(pem.EncodeToMemory(block))
	}
	return ssh.ParsePrivateKey([]byte(keys.HostKey))
}

func (s *state) hostKey() ssh.Signer {
	if st := s.settings.Load(); st != nil {
		return st.hostKey
	}
	return sshHostKey
}

// ---------------------------------------------------------------------------
// Settings snapshots: prepared outside s.mu, committed under it, and delivered to connectors
// after it. Stored maps and snapshots are immutable once published.

// settings is an immutable snapshot of the saved settings, published as a whole.
// Mutable connector availability and stream authority belong to the table and admissions.
type settings struct {
	*Config
	policy      *opa.Program
	catalog     map[string]catalogEntry
	catalogID   string
	tls         *tls.Config
	hostKey     ssh.Signer
	publicScope map[string][]string
	connections map[string]*installed
}

// installed is a connection's parsed setup with the credentials bound to it at commit, and the
// public placeholders agents send in their place.
type installed struct {
	*parsed
	secrets      map[string]*credential.Value
	placeholders map[string]string
}

type connectionPlan struct {
	ConnectionSpec
	*installed
}

// settingsPlan contains parsed settings, never candidate runtime instances.
type settingsPlan struct {
	next        *settings
	source      string
	credentials perimeterformat.Secrets
	renamed     map[string]string
	updates     []connectionPlan
	remove      []string
}

// settingsWrite replaces the policy source, or edits it with changes, and stages
// credentials, nil clearing one. check runs under s.mu before validation and again
// before persistence. A saved approval is answered atomically with the durable change.
type settingsWrite struct {
	source      *string
	changes     []perimeterformat.Change
	credentials perimeterformat.Secrets
	check       func() error
	saved       *savedAnswer
}

func (w settingsWrite) checked() error {
	if w.check == nil {
		return nil
	}
	return w.check()
}

var (
	errPolicyConflict = httpError{errors.New("policy changed; reload it and review a new diff before applying"), http.StatusConflict}
	errPolicyFile     = refused("the policy is loaded from a file; change it there")
)

func everyConnection(string) bool { return true }

// preparePolicy compiles the standard policy, the base policy and owner policy over owner data.
func preparePolicy(ctx context.Context, cfg *Config) (*opa.Program, error) {
	for _, name := range protectedData {
		if _, ok := cfg.Data[name]; ok {
			return nil, fmt.Errorf("data.%s is reserved for the Perimeter", name)
		}
	}
	data := maps.Clone(cfg.Data)
	if data == nil {
		data = map[string]any{}
	}
	data["levels"] = map[string]any{"audiences": audiences, "trusts": trusts, "effects": vocabulary}
	data["lattices"] = cfg.Lattices
	modules := map[string]string{standardModule: standardPolicy}
	if basePolicy != "" {
		path, err := opa.Package(baseModule, basePolicy)
		if err == nil && !slices.Equal(path, basePackage) {
			err = fmt.Errorf("the base policy must be package data.%s, not data.%s", strings.Join(basePackage, "."), strings.Join(path, "."))
		}
		if err != nil {
			return nil, err
		}
		modules[baseModule] = basePolicy
	}
	for _, name := range slices.Sorted(maps.Keys(cfg.Policies)) {
		filename := "policies/" + name
		path, err := opa.Package(filename, cfg.Policies[name])
		if err != nil {
			return nil, err
		}
		if slices.Contains(protectedData, path[0]) {
			return nil, fmt.Errorf("policy %s: data.%s is reserved for the Perimeter", name, path[0])
		}
		modules[filename] = cfg.Policies[name]
	}
	return opa.Prepare(ctx, modules, data, policyQueries)
}

// prepareSettings validates source and parses the connector setups to rebuild
// under s.writes, without s.mu. It creates no runtime instances. Credential refreshes
// can still commit while validation runs.
func (s *state) prepareSettings(ctx context.Context, source string, rebuild func(connection string) bool, renamed map[string]string, credentials perimeterformat.Secrets, tlsConfig *tls.Config, hostKey ssh.Signer) (*settingsPlan, error) {
	cfg, err := loadConfig(source)
	if err != nil {
		return nil, err
	}
	for name, id := range cfg.Identities {
		for key, value := range id.Attributes {
			validate := identityAttributes[key]
			if validate == nil {
				return nil, fmt.Errorf("identity %s has no field %s", name, key)
			}
			if err := validate(value); err != nil {
				return nil, fmt.Errorf("identity %s %s: %w", name, key, err)
			}
		}
	}
	program, err := preparePolicy(ctx, cfg)
	if err != nil {
		return nil, err
	}
	next := &settings{Config: cfg, policy: program, tls: tlsConfig, hostKey: hostKey, publicScope: map[string][]string{}, connections: map[string]*installed{}}
	operations := map[string]map[string]operationSummary{}
	plan := &settingsPlan{next: next, source: source, credentials: credentials, renamed: renamed}
	var current map[string]*installed
	if st := s.settings.Load(); st != nil {
		current = st.connections
	}
	status := s.table.Connections()
	for _, name := range slices.Sorted(maps.Keys(next.Connections)) {
		spec, err := next.Spec(name)
		if err != nil {
			return nil, err
		}
		next.publicScope[spec.Name] = spec.PublicScope
		if !slices.Contains(protocols, spec.Protocol) || !development && slices.Contains(hostProtocols, spec.Protocol) {
			return nil, fmt.Errorf("service %s has unknown kind %s", spec.Name, spec.Protocol)
		}
		c, exists := current[spec.Name]
		if exists && c.Protocol != spec.Protocol {
			plan.remove = append(plan.remove, spec.Name)
		}
		if exists && c.Protocol == spec.Protocol && !rebuild(spec.Name) && len(credentials[spec.Name]) == 0 {
			next.connections[spec.Name] = c
			operations[next.Connections[spec.Name].Preset] = c.operations
			if status[spec.Name].State != core.Ready {
				plan.updates = append(plan.updates, connectionPlan{spec, c})
			}
			continue
		}
		p, err := parseConnection(spec)
		if err != nil {
			return nil, fmt.Errorf("service %s: %w", spec.Name, err)
		}
		operations[next.Connections[spec.Name].Preset] = p.operations
		handles := map[string]*credential.Value{}
		for _, name := range p.secretNames {
			handles[name] = nil
		}
		for name, raw := range credentials[spec.Name] {
			if _, uses := handles[name]; raw != nil && !uses {
				return nil, fmt.Errorf("service %s does not use credential %s", spec.Name, name)
			}
		}
		c = &installed{parsed: p, secrets: handles, placeholders: map[string]string{}}
		next.connections[spec.Name] = c
		plan.updates = append(plan.updates, connectionPlan{spec, c})
	}
	if next.catalog, next.catalogID, err = catalogEntries(cfg, operations); err != nil {
		return nil, err
	}
	for name := range credentials {
		if _, present := next.Connections[name]; !present {
			return nil, fmt.Errorf("service %s does not exist", name)
		}
	}
	for name := range current {
		if _, present := next.Connections[name]; !present {
			plan.remove = append(plan.remove, name)
		}
	}
	return plan, nil
}

// commitSettings runs under s.writes and s.mu: rebase the planned changes, persist them,
// publish the settings and revoke lost authority. Changed connectors remain
// unavailable until installation. A saved approval is answered after persistence
// and before general settings invalidation.
func (s *state) commitSettings(ctx context.Context, plan *settingsPlan, saved *savedAnswer) (err error) {
	current := s.doc.Get()
	next := current
	next.Policy = plan.source
	next.Credentials = next.Credentials.Clone()
	for to, from := range plan.renamed {
		if values, ok := current.Credentials[from]; ok {
			next.Credentials[to] = maps.Clone(values)
		}
	}
	for connection, values := range plan.credentials {
		for name, raw := range values {
			next.Credentials.Set(perimeterformat.SecretID{Connection: connection, Name: name}, raw)
		}
	}
	maps.DeleteFunc(next.Credentials, func(connection string, _ map[string]json.RawMessage) bool {
		_, ok := plan.next.Connections[connection]
		return !ok
	})
	// Bind new handles to the latest durable record exactly once, before commit.
	// This is pure credential validation; it takes no Value lock or network call.
	client := plan.next.client()
	for _, update := range plan.updates {
		for name, value := range update.secrets {
			if value != nil {
				continue
			}
			id := perimeterformat.SecretID{Connection: update.Name, Name: name}
			var v *credential.Value
			if v, err = bindCredential(next.Credentials.Get(id), client, func(ctx context.Context, before, after json.RawMessage) error {
				return s.replaceValue(ctx, id, v, before, after)
			}); err != nil {
				return fmt.Errorf("credential %s/%s: %w", update.Name, name, err)
			}
			update.secrets[name], update.placeholders[name] = v, placeholder(next.Keys, id)
		}
	}
	next.Enrolled = maps.Clone(next.Enrolled)
	if next.Enrolled == nil {
		next.Enrolled = map[string]bool{}
	}
	for key := range plan.next.Principals {
		next.Enrolled[key] = true
	}
	next.Revision++
	// Persist before publishing authority.
	if err := s.commit(ctx, next); err != nil {
		return err
	}
	if saved != nil {
		s.saved(saved.record, saved.answer)
	}
	for _, name := range plan.remove {
		s.table.Remove(name)
	}
	for _, update := range plan.updates {
		s.table.Stage(update.Name, update.claim, update.perMessage, s.opener(plan.next, update.installed))
	}
	previous := s.settings.Swap(plan.next)
	if previous != nil {
		for key := range previous.Principals {
			if _, kept := plan.next.Principals[key]; !kept {
				s.identities.Unregister(key)
			}
		}
	}
	for key := range plan.next.Principals {
		p, _ := plan.next.Config.Principal(key)
		s.identities.Register(key, p, true)
	}
	for r := range s.records.All() {
		if r.State != statePending || r.Changes == nil {
			continue
		}
		f := summarize(r).Facts
		if _, raw, err := s.proposal(plan.next, plan.source, f.Principal, f.Connection, r.Requirements[0].Message, r.Changes); err == nil {
			r.Facts = raw
		} else {
			s.outdateRecord(r)
		}
	}
	s.recheckAll()
	return nil
}

// writeSettings is the single ordered settings path; s.writes is held, s.mu is not.
func (s *state) writeSettings(ctx context.Context, w settingsWrite) error {
	if policyFile != "" && (w.source != nil || len(w.changes) != 0) {
		return errPolicyFile
	}
	s.mu.Lock()
	source, current, err := s.doc.Get().Policy, s.settings.Load(), w.checked()
	s.mu.Unlock()
	if err != nil {
		return err
	}
	before := source
	if w.source != nil {
		source = *w.source
	}
	source, rebuild, renamed, err := current.Edit(source, w.changes)
	if err != nil {
		return err
	}
	plan, err := s.prepareSettings(ctx, source, rebuild, renamed, w.credentials, current.tls, current.hostKey)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if err = w.checked(); err == nil {
		err = s.commitSettings(ctx, plan, w.saved)
	}
	if source != before || len(w.credentials) != 0 {
		s.recordAdmin(ctx, "Change settings", map[string]any{"policy": policyDiff{SourceDiff: sourceDiff(before, source)}, "credentials": slices.Sorted(maps.Keys(w.credentials))}, err)
	}
	s.mu.Unlock()
	if err == nil {
		s.table.Start()
	}
	return err
}

// reviewed checks, under s.mu, that an owner write naming a revision was made against current settings.
func (s *state) reviewed(revision *uint64) func() error {
	return func() error {
		if revision != nil && *revision != s.doc.Get().Revision {
			return errPolicyConflict
		}
		return nil
	}
}

// policyDiff compares the owner source and its expanded settings.
type policyDiff struct {
	SourceDiff    string `json:"source_diff"`
	EffectiveDiff string `json:"effective_diff"`
}

func sourceDiff(a, b string) string {
	text, _ := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{A: difflib.SplitLines(a), B: difflib.SplitLines(b), FromFile: "active/policy.toml", ToFile: "proposed/policy.toml", Context: 3})
	return text
}

func (s *state) previewPolicy(ctx context.Context, base perimeterformat.Document, before *settings, source string) (*policyDiff, error) {
	source, _, _, err := before.Edit(source, nil)
	if err != nil {
		return nil, err
	}
	plan, err := s.prepareSettings(ctx, source, everyConnection, nil, nil, before.tls, before.hostKey)
	if err != nil {
		return nil, err
	}
	beforeText, err := before.Config.Effective()
	if err != nil {
		return nil, err
	}
	afterText, err := plan.next.Config.Effective()
	if err != nil {
		return nil, err
	}
	return &policyDiff{SourceDiff: sourceDiff(base.Policy, source), EffectiveDiff: sourceDiff(beforeText, afterText)}, nil
}

// ---------------------------------------------------------------------------
// Policy proposals and enrollment.

const (
	maxProposalChanges = 256
	maxPolicyProposals = 32
)

type proposalInput struct {
	Source  string                   `json:"source,omitempty"`
	Changes []perimeterformat.Change `json:"changes,omitempty"`
	Reason  string                   `json:"reason"`
	Delete  [][]string               `json:"delete,omitempty"`
}

type proposalReceipt struct {
	ID         string `json:"id"`
	State      string `json:"state"`
	Connection string `json:"connection"`
}

func receipt(r *record) proposalReceipt {
	return proposalReceipt{ID: r.ID, State: r.State, Connection: summarize(r).Facts.Connection}
}

// proposal renders p's changes to one connection against source for review under st. It
// fails when they no longer apply, change nothing, or p may not propose them.
func (s *state) proposal(st *settings, source string, p facts.Principal, target, reason string, changes []perimeterformat.Change) (string, json.RawMessage, error) {
	current, ok := s.identities.Lookup(p.Key)
	if !ok || !current.Same(p) {
		return "", nil, errNoAgent
	}
	if _, err := proposalChanges(p, changes, st.capable(current, capabilityPropose)); err != nil {
		return "", nil, err
	}
	candidate, _, _, err := st.Edit(source, changes)
	if err == nil && candidate == source {
		err = errors.New("proposal does not change policy")
	}
	if err != nil {
		return "", nil, err
	}
	raw, err := json.Marshal(requestFacts{Version: factsVersion, Principal: p, Connection: target,
		Service: "policy-proposal", Title: reason, Parameters: map[string]any{},
		Details: map[string]any{"policy": policyDiff{SourceDiff: sourceDiff(source, candidate)}}})
	return candidate, raw, err
}

// proposePolicy publishes one pending record per connection, or none if any fails.
// The owner answers it like a request; approval writes its changes.
func (s *state) proposePolicy(ctx context.Context, key string, input proposalInput) ([]proposalReceipt, error) {
	reason := strings.TrimSpace(input.Reason)
	if reason == "" || len(reason) > maxReason {
		return nil, fmt.Errorf("proposal needs a reason of 1-%d bytes", maxReason)
	}
	if (input.Source != "" || input.Delete != nil) == (input.Changes != nil) {
		return nil, errors.New("proposal requires exactly one of a TOML fragment or structured changes")
	}
	changes := input.Changes
	if changes == nil {
		var err error
		if changes, err = perimeterformat.FragmentTOML(input.Source); err != nil {
			return nil, err
		}
		for _, path := range input.Delete {
			changes = append(changes, perimeterformat.Change{Path: path, Delete: true})
		}
	}
	if len(changes) == 0 || len(changes) > maxProposalChanges {
		return nil, fmt.Errorf("proposal must contain 1-%d changes", maxProposalChanges)
	}
	if policyFile != "" {
		return nil, errPolicyFile
	}
	s.writes.Lock()
	defer s.writes.Unlock()
	base, before := s.snapshot()
	p, known := s.identities.Lookup(key)
	if !known {
		return nil, errNoAgent
	}
	groups, err := proposalChanges(p, changes, before.capable(p, capabilityPropose))
	if err != nil {
		return nil, err
	}
	var proposals []*record
	for _, target := range slices.Sorted(maps.Keys(groups)) {
		candidate, raw, err := s.proposal(before, base.Policy, p, target, reason, groups[target])
		if err == nil {
			_, err = s.prepareSettings(ctx, candidate, everyConnection, nil, nil, before.tls, before.hostKey)
		}
		if err != nil {
			return nil, fmt.Errorf("service %s: %w", target, err)
		}
		proposals = append(proposals, &record{Changes: groups[target], Facts: raw,
			Decision: Decision{Requirements: []Requirement{{ID: "policy", Message: reason}}}})
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	// A principal has one pending proposal per connection; a new one replaces it.
	var replaced []*record
	pending := len(proposals)
	for r := range s.records.All() {
		if r.State != statePending || r.Changes == nil {
			continue
		}
		f := summarize(r).Facts
		if _, again := groups[f.Connection]; again && f.Principal.Same(p) {
			replaced = append(replaced, r)
		} else {
			pending++
		}
	}
	if pending > maxPolicyProposals {
		return nil, errors.New("too many pending policy proposals")
	}
	for _, r := range replaced {
		s.outdateRecord(r)
	}
	receipts := make([]proposalReceipt, 0, len(proposals))
	for _, proposal := range proposals {
		s.addRecord(proposal).State = statePending
		s.announce(proposal)
		receipts = append(receipts, receipt(proposal))
	}
	return receipts, nil
}

type identityEnrollment struct {
	Key      string `json:"key"`
	Operator bool   `json:"routes"`
	Restore  bool   `json:"restore"`
	// Attributes are the enrollment's other keys.
	Attributes map[string]json.RawMessage `json:",embed"`
}

// enrollmentChanges adds new identities; a revoked key or route access returns only when restored.
// The caller holds s.mu.
func (s *state) enrollmentChanges(input map[string]identityEnrollment) ([]perimeterformat.Change, error) {
	var changes []perimeterformat.Change
	st := s.settings.Load()
	for name, id := range input {
		fingerprint, err := keyFingerprint(id.Key)
		if err != nil {
			return nil, err
		}
		attributes := map[string]any{}
		for key, raw := range id.Attributes {
			if identityAttributes[key] == nil {
				return nil, fmt.Errorf("an enrollment has no field %s", key)
			}
			if attributes[key], err = facts.JSON[any](raw); err != nil {
				return nil, err
			}
		}
		maps.DeleteFunc(attributes, func(_ string, value any) bool { return value == nil })
		if principal, ok := st.Config.Principal(fingerprint); ok {
			existing := st.Identities[principal.Name]
			if id.Operator && !existing.Operator {
				if !id.Restore {
					return nil, errors.New("device route access was revoked")
				}
				changes = append(changes, perimeterformat.Change{Path: []string{"identities", principal.Name, "routes"}, Value: true})
			}
			for key, value := range attributes {
				if before, _ := facts.JSON[any](existing.Attributes[key]); !reflect.DeepEqual(value, before) {
					changes = append(changes, perimeterformat.Change{Path: []string{"identities", principal.Name, key}, Value: value})
				}
			}
			continue
		}
		if s.doc.Get().Enrolled[fingerprint] && !id.Restore {
			return nil, errors.New("identity was revoked; restore access explicitly in the Perimeter")
		}
		if _, exists := st.Config.Identities[name]; exists {
			return nil, errors.New("identity name belongs to another key")
		}
		value := map[string]any{"key": id.Key, "routes": id.Operator}
		maps.Copy(value, attributes)
		changes = append(changes, perimeterformat.Change{Path: []string{"identities", name}, Value: value})
	}
	return changes, nil
}

// restoreDevice lets owner unlock restore its device; ordinary enrollment still honors revocation.
// Authentication and unlocking precede this independent settings write.
func (s *state) restoreDevice(ctx context.Context, public string) error {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(public))
	if err != nil {
		return fmt.Errorf("device public key: %w", err)
	}
	public = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	digest := sha256.Sum256([]byte(public))
	return s.enroll(ctx, map[string]identityEnrollment{fmt.Sprintf("device-%x", digest[:8]): {Key: public, Operator: true, Restore: true}})
}

func (s *state) enroll(ctx context.Context, identities map[string]identityEnrollment) error {
	s.writes.Lock()
	defer s.writes.Unlock()
	s.mu.Lock()
	changes, err := s.enrollmentChanges(identities)
	s.mu.Unlock()
	if err != nil {
		return err
	}
	return s.writeSettings(ctx, settingsWrite{changes: changes})
}

// ---------------------------------------------------------------------------
// Authorization. Admissions and operations are decided under the current settings' policy;
// the owner answers what policy requires, and a later policy or label revokes what it no longer
// allows. All of it runs under s.mu, which only approval waits release.

var (
	errRemoved      = errors.New("this agent's identity was removed")
	errChanged      = errors.New("configuration changed; retry the request")
	errAuditBacklog = errors.New("the Perimeter cannot write its audit log; requests are refused until storage recovers")
	errRuleSaved    = errors.New("approval rule saved; retry the request")
	errNoAccess     = errors.New("key has no agent access")
)

const (
	statePending  = "pending"
	stateExpired  = "expired"
	stateOutdated = "outdated"
	stateAllowed  = "allowed"
	stateRefused  = "refused"
	stateApproved = "approved"
	stateDenied   = "denied"

	answerOnce = "once"
	answerSave = "save"
	answerDeny = "deny"

	approvalWait = 2 * time.Minute
	maxRecords   = 1000
)

type Answer struct {
	Choice string `json:"decision"`
	Reason string `json:"reason,omitempty"`
}

type Review struct {
	By string `json:"by"`
	Answer
	Time time.Time `json:"time"`
}

type Decision struct {
	Deny         []string              `json:"deny"`
	Requirements []Requirement         `json:"requirements"`
	Sends        string                `json:"sends"`
	Next         perimeterformat.Label `json:"next"`
}

// A record is one decision or policy proposal; requests are the pending and expired ones.
// Its JSON is the deployed activity and audit representation.
type record struct {
	ID      string          `json:"id"`
	State   string          `json:"state"`
	Invalid bool            `json:"invalid,omitempty"`
	Time    time.Time       `json:"time"`
	Expires time.Time       `json:"expires,omitzero"`
	Facts   json.RawMessage `json:"facts"`
	Decision
	Grant   map[string]any           `json:"grant"`
	Reviews []Review                 `json:"reviews,omitempty"`
	Changes []perimeterformat.Change `json:"changes,omitempty"`
}

// settle marks a failed execution without replacing an owner's answer or expiration.
func (r *record) settle(err error) {
	if err != nil && r.State != stateDenied && r.State != stateExpired {
		r.State = stateRefused
		if len(r.Deny) == 0 {
			r.Deny = []string{err.Error()}
		}
	}
}

// An admitted is one key's stream to one connection, or its lease of a capability.
type admitted struct {
	key, connection string
	// capability makes the admission a lease of it, which a label change never revokes.
	capability string
	// perMessage streams gate every operation, so they outlive a change to their key's label.
	perMessage bool
	// valid reports, under s.mu, that the connection still serves this admission.
	valid func() bool
	// The admission, then the latest operation.
	grants []*grant
}

// A grant is an allowed request a settings write re-decides, with the label it was
// decided under and the requirements the owner answered for it alone.
type grant struct {
	kind     string
	event    facts.Event   // an operation's captured bytes
	admit    *requestFacts // an admission's description
	label    perimeterformat.Label
	approved []string
}

// requestFacts is the snapshot shared by authorization and audit, in its deployed JSON form.
type requestFacts struct {
	Scope      map[string]any  `json:"-"`
	Version    int             `json:"version"`
	Kind       string          `json:"kind"`
	Principal  facts.Principal `json:"principal"`
	Service    string          `json:"service"`
	Connection string          `json:"connection"`
	Operation  *operation      `json:"operation"`
	Parameters map[string]any  `json:"parameters"`
	Context    requestContext  `json:"context"`
	Title      string          `json:"title"`
	Details    any             `json:"details"`
}

type operation struct {
	ID      string   `json:"id"`
	Action  string   `json:"action"`
	Effects []string `json:"effects"`
	Lineage []string `json:"lineage"`
}

// Sends and Observes are protocol hints; policy resolves them with connection settings.
type requestContext struct {
	Label    perimeterformat.Label `json:"label"`
	Sends    string                `json:"sends"`
	Observes perimeterformat.Label `json:"observes"`
}

// resolveOperation binds an observed action to its nearest preset action effects.
func resolveOperation(id, action string, effects []string, actions map[string]catalog.Action) *operation {
	op := operation{ID: id, Action: action}
	for a := action; a != ""; {
		op.Lineage = append(op.Lineage, a)
		i := strings.LastIndexByte(a, '.')
		if i < 0 {
			break
		}
		a = a[:i]
	}
	for i := 0; effects == nil && i < len(op.Lineage); i++ {
		effects = actions[op.Lineage[i]].Effects
	}
	if op.Action == "" || effects == nil {
		return nil
	}
	op.Effects, op.ID = slices.Compact(slices.Sorted(slices.Values(effects))), cmp.Or(op.ID, op.Action)
	return &op
}

type decisionInput struct {
	Facts         json.RawMessage    `json:"facts"` // the bytes the audit record stores
	Authorization authorizationInput `json:"authorization"`
	Connection    connectionInput    `json:"connection"`
}

type authorizationInput struct {
	Access             Access              `json:"access"`
	Reaches            bool                `json:"reaches"`
	Effects            []map[string]string `json:"effects"` // global, connection, identity, access
	AllowPaidInference bool                `json:"allow_paid_inference"`
	Rules              []Rule              `json:"rules"`
	Approved           []string            `json:"approved"`
	Grant              map[string]any      `json:"grant"`
}

type connectionInput struct {
	Contents    string   `json:"contents"`
	Strangers   bool     `json:"strangers"`
	Sends       string   `json:"sends"`
	Private     []string `json:"private"`
	PublicScope []string `json:"public_scope"`
}

type adminCall struct {
	Caller policyCaller `json:"caller"`
	Route  string       `json:"route"`
	Answer any          `json:"answer,omitempty"`
	Record any          `json:"record,omitempty"`
}

type policyCaller struct {
	Name   string         `json:"name"`
	Owner  bool           `json:"owner"`
	Claims map[string]any `json:"claims"`
}

type capabilityInput struct {
	Principal  facts.Principal `json:"principal"`
	Routes     bool            `json:"routes"`
	Capability string          `json:"capability"`
}

// Capabilities that policy grants an identity; its stored routes flag grants each.
const (
	capabilityConfig  = "config"
	capabilityPropose = "propose"
	capabilityRoutes  = "routes"
)

// capable reports whether policy grants p capability, refusing it when policy fails.
func (st *settings) capable(p facts.Principal, capability string) bool {
	var ok bool
	err := st.policy.Eval(context.Background(), queryCapable, capabilityInput{Principal: p, Routes: st.Identities[p.Name].Operator, Capability: capability}, &ok)
	return ok && err == nil
}

func (st *settings) enforced() bool { return st.Lattices.Confidentiality || st.Lattices.Integrity }

// describe binds a grant's request to the principal, connection and label it is decided for.
func (st *settings) describe(p facts.Principal, connection string, gr *grant) (requestFacts, error) {
	var f requestFacts
	var err error
	if gr.admit != nil {
		f = *gr.admit
	} else {
		f, err = st.observe(connection, gr.event)
	}
	f.Version, f.Kind = factsVersion, gr.kind
	f.Service, f.Connection = st.Connections[connection].Preset, connection
	f.Principal, f.Context.Label = p, gr.label
	if f.Parameters == nil {
		f.Parameters = map[string]any{}
	}
	if f.Scope == nil {
		f.Scope = f.Parameters
	}
	return f, err
}

// decide fills a record with a request's facts and grant and, unless they are invalid, policy's decision.
func (st *settings) decide(ctx context.Context, p facts.Principal, connection string, gr *grant) (*record, error) {
	f, describeErr := st.describe(p, connection, gr)
	if describeErr != nil {
		f.Operation = nil
		raw, err := json.Marshal(f)
		if err != nil {
			return nil, err
		}
		return &record{Facts: raw, Invalid: true}, describeErr
	}
	encoded, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	access, settings := st.Access(p.Name, connection), st.Connections[connection]
	// Policy reads unset scopes as {} and unset lists as [], never null.
	effects := []map[string]string{st.Effects, settings.Effects, st.Identities[p.Name].Effects, access.Effects}
	for i, scope := range effects {
		if scope == nil {
			effects[i] = map[string]string{}
		}
	}
	input := decisionInput{
		Facts: encoded,
		Authorization: authorizationInput{Access: access, Reaches: st.Reaches(p.Name, connection), Effects: effects, AllowPaidInference: st.AllowPaidInference,
			Rules: slices.Collect(maps.Values(st.Identities[p.Name].Rules)), Approved: gr.approved, Grant: f.Scope},
		Connection: connectionInput{Contents: settings.Contents, Strangers: settings.Strangers, Sends: settings.Sends,
			Private: append([]string{}, settings.PolicyOptions.Private...), PublicScope: append([]string{}, st.publicScope[connection]...)},
	}
	next := &record{Facts: encoded, Grant: f.Scope}
	err = st.policy.Eval(ctx, queryDecision, input, &next.Decision)
	return next, err
}

func (s *state) label(key string) perimeterformat.Label {
	if l, ok := s.doc.Get().Labels[key]; ok {
		return l
	}
	return initialLabel
}

// decideGrant evaluates gr under current settings, without waiting or recording.
// An invalid request yields its record with the error.
func (s *state) decideGrant(ctx context.Context, a *admitted, gr *grant) (*record, error) {
	p, ok := s.identities.Lookup(a.key)
	if !ok {
		return nil, errRemoved
	}
	if !a.valid() {
		return nil, errChanged
	}
	return s.settings.Load().decide(ctx, p, a.connection, gr)
}

// authorize releases s.mu only around approval waits.
// Callers settle its record after any label persistence, before execution begins.
func (s *state) authorize(ctx context.Context, a *admitted, gr *grant) (*record, error) {
	var r *record
	gr.approved = []string{}
	for {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		if s.audit.Backlogged() {
			return r, errAuditBacklog
		}
		gr.label = s.label(a.key)
		next, err := s.decideGrant(ctx, a, gr)
		if next != nil && next.Invalid {
			s.addRecord(next)
			return next, err
		}
		if err != nil {
			return r, err
		}
		if r == nil {
			s.addRecord(next)
			r = next
		}
		r.Facts, r.Decision, r.Grant = next.Facts, next.Decision, next.Grant
		if len(r.Deny) != 0 {
			return r, errors.New(strings.Join(r.Deny, "; "))
		}
		if len(r.Requirements) == 0 {
			if r.State == statePending {
				r.State = stateAllowed
			}
			return r, ctx.Err()
		}
		if err := s.awaitAnswer(ctx, r); err != nil {
			return r, err
		}
		if r.State == stateApproved {
			for _, requirement := range r.Requirements {
				gr.approved = append(gr.approved, requirement.ID)
			}
		}
	}
}

// awaitAnswer publishes a pending record and releases s.mu until it is answered,
// expires or anything changes; a record still pending is checked again.
func (s *state) awaitAnswer(ctx context.Context, r *record) error {
	if r.State != statePending {
		r.State, r.Expires = statePending, time.Now().Add(approvalWait)
		s.announce(r)
	}
	expired := s.records.Wait(ctx, r.Expires)
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.State == stateDenied {
		return errors.New("this request was denied")
	}
	if r.State == stateApproved || !expired {
		return nil
	}
	r.State = stateExpired
	return errors.New("waiting for approval in the Perimeter timed out")
}

// admit decides a stream's admission, waiting for any approval it requires.
func (s *state) admit(ctx context.Context, p facts.Principal, req core.Request) (core.Watch, error) {
	a := &admitted{key: p.Key, connection: req.Connection, perMessage: req.PerMessage, valid: req.Valid}
	gr := &grant{kind: kindAdmission, admit: &requestFacts{
		Operation:  &operation{Action: "session.admit", Effects: []string{"session"}},
		Title:      "Open " + req.Connection,
		Parameters: map[string]any{"host": req.Host, "port": req.Port},
		Details:    map[string]any{"tcp": map[string]any{"host": req.Host, "port": req.Port}},
		Context:    requestContext{Observes: initialLabel},
	}}
	s.mu.Lock()
	r, err := s.authorize(ctx, a, gr)
	if r != nil {
		s.settleRecord(r, err)
	}
	a.grants = []*grant{gr}
	s.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, end func()) (core.Gate, bool) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if !s.recheck(a) {
			return nil, false
		}
		remove := s.admissions.Add(a, end)
		context.AfterFunc(ctx, func() { s.mu.Lock(); remove(); s.mu.Unlock() })
		return func(op context.Context, event facts.Event) error { return s.operation(op, ctx, a, event) }, true
	}, nil
}

// operation keeps the latest allowed operation with its stream.
func (s *state) operation(ctx, stream context.Context, a *admitted, event facts.Event) error {
	if err := stream.Err(); err != nil {
		return err
	}
	ctx, cancel := netx.Bind(ctx, stream)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	gr := &grant{kind: kindOperation, event: event}
	r, err := s.authorize(ctx, a, gr)
	if r != nil {
		if err == nil {
			err = s.relabel(ctx, a.key, r.Next, a)
		}
		s.settleRecord(r, err)
	}
	if err != nil {
		return err
	}
	a.grants = append(a.grants[:1], gr)
	return nil
}

// recheck reports that a's key, access and connection remain, and that its admission
// and latest operation would be allowed outright under current settings.
func (s *state) recheck(a *admitted) bool {
	if a.capability != "" {
		return s.capable(a.key, a.capability)
	}
	for _, gr := range a.grants {
		if d, err := s.decideGrant(context.Background(), a, gr); err != nil || len(d.Deny) != 0 || len(d.Requirements) != 0 {
			return false
		}
	}
	return true
}

// relabel persists key's label; a failed write never publishes an observation.
// source is the admission whose operation produced l, or nil for an owner reset.
func (s *state) relabel(ctx context.Context, key string, l perimeterformat.Label, source *admitted) error {
	if old := s.label(key); old.Trust == l.Trust && old.Audience == l.Audience {
		return nil
	}
	next := s.doc.Get()
	next.Labels = maps.Clone(next.Labels)
	next.Labels[key] = l
	if err := s.commit(ctx, next); err != nil {
		return err
	}
	// With both lattices off a label is recorded but never enforced, so a
	// change in it is no reason to cut anything.
	if source != nil && !s.settings.Load().enforced() {
		return nil
	}
	// An opaque source may finish the session it just admitted. Other opaque
	// sessions cannot recheck their bytes, so revoke them.
	// Close every connector stream so old deliveries cannot recontaminate a reset.
	s.admissions.Recheck(func(a *admitted) bool {
		return a.key != key || a.capability != "" || a == source || source != nil && a.perMessage
	})
	return nil
}

func (s *state) capable(key, capability string) bool {
	p, known := s.identities.Lookup(key)
	st := s.settings.Load()
	return known && st != nil && st.capable(p, capability)
}

// hold leases capability while key holds it. The context it returns ends when that identity
// is unregistered or a settings change takes the capability away.
func (s *state) hold(ctx context.Context, key, capability string) (context.Context, context.CancelFunc, bool) {
	ctx, release, ok := s.identities.Hold(ctx, key)
	if !ok {
		return nil, nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.capable(key, capability) {
		release()
		return nil, nil, false
	}
	ctx, cancel := context.WithCancel(ctx)
	remove := s.admissions.Add(&admitted{key: key, capability: capability}, cancel)
	context.AfterFunc(ctx, func() { s.mu.Lock(); remove(); s.mu.Unlock() })
	return ctx, func() { cancel(); release() }, true
}

// recheckAll revokes the admissions current settings no longer allow and wakes waiting requests.
func (s *state) recheckAll() {
	s.admissions.Recheck(s.recheck)
	s.records.Notify()
}

// ---------------------------------------------------------------------------
// Records: one retained collection for gated requests and policy proposals, settled into
// the sealed audit log.

const (
	maxReason       = 4096
	maxSummaryTitle = 512
	auditPrefix     = "audit/"
	adminService    = "admin"
)

var (
	errRecordGone = httpError{errors.New("this request is no longer in the activity log"), http.StatusNotFound}
	errNoAgent    = httpError{errRemoved, http.StatusForbidden}
)

// savedAnswer carries the answer to publish with its durable settings change.
type savedAnswer struct {
	record *record
	answer Review
}

// Activity never needs request bodies, policy parameters or saved-rule grants.
// Keep those in the existing audit record and load one through /requests/{id}.
type recordSummary struct {
	ID      string    `json:"id"`
	State   string    `json:"state"`
	Invalid bool      `json:"invalid,omitempty"`
	Time    time.Time `json:"time"`
	Expires time.Time `json:"expires,omitzero"`
	Summary bool      `json:"summary"`
	Reviews []Review  `json:"reviews,omitempty"`
	Segment string    `json:"segment,omitempty"`
	Facts   struct {
		Principal  facts.Principal `json:"principal"`
		Connection string          `json:"connection"`
		Service    string          `json:"service"`
		Operation  *operation      `json:"operation"`
		Title      string          `json:"title"`
	} `json:"facts"`
}

func summarize(r *record) recordSummary {
	v := recordSummary{ID: r.ID, State: r.State, Invalid: r.Invalid, Time: r.Time, Expires: r.Expires, Summary: true}
	for _, review := range r.Reviews {
		review.Reason = ""
		v.Reviews = append(v.Reviews, review)
	}
	_ = json.Unmarshal(r.Facts, &v.Facts)
	// SQL and other protocol titles can contain the entire request.
	if len(v.Facts.Title) > maxSummaryTitle {
		v.Facts.Title = strings.ToValidUTF8(v.Facts.Title[:maxSummaryTitle], "") + "…"
	}
	return v
}

// addRecord retains r before it can wait or settle; pending records are never evicted. Under s.mu.
func (s *state) addRecord(r *record) *record {
	r.ID, r.Time, r.State = rand.Text(), time.Now(), stateAllowed
	s.records.Add(r)
	return r
}

func (s *state) findRecord(id string) *record {
	r, _ := s.records.Find(func(r *record) bool { return r.ID == id })
	return r
}

func (s *state) announce(r *record) {
	events.Info("record", "record", summarize(r), "generation", s.doc.Get().Generation)
}

// settleRecord writes the record's outcome to the audit log even if retention has evicted it.
func (s *state) settleRecord(r *record, err error) {
	r.settle(err)
	if line, err := json.Marshal(r); err != nil {
		log.Printf("audit record %s: %v", r.ID, err)
	} else {
		s.audit.Append(line)
	}
	s.announce(r)
}

func (s *state) outdateRecord(r *record) {
	r.State = stateOutdated
	s.settleRecord(r, nil)
}

// recordAdmin audits an admin action and its outcome; the caller holds s.mu.
func (s *state) recordAdmin(ctx context.Context, title string, details any, err error) {
	c, _ := callerFrom(ctx)
	raw, encodeErr := json.Marshal(requestFacts{Version: factsVersion, Principal: facts.Principal{Name: c.Name}, Service: adminService,
		Title: title, Parameters: map[string]any{}, Details: details})
	if encodeErr != nil {
		log.Printf("audit admin action %s: %v", title, encodeErr)
		return
	}
	s.settleRecord(s.addRecord(&record{Facts: raw}), err)
}

// ruleChange derives a saved rule only from frozen audit/grant data under s.mu.
func (s *state) ruleChange(r *record) (perimeterformat.Change, error) {
	f := summarize(r).Facts
	if f.Operation == nil || f.Operation.ID == "" {
		return perimeterformat.Change{}, errors.New("a request without a known operation cannot be saved")
	}
	p, exists := s.identities.Lookup(f.Principal.Key)
	if !exists || p.Name != f.Principal.Name {
		return perimeterformat.Change{}, errors.New("the requesting identity was revoked or replaced")
	}
	if _, declared := s.settings.Load().Identities[p.Name]; !declared {
		return perimeterformat.Change{}, errors.New("an approval for a certified identity cannot be saved as a rule")
	}
	return perimeterformat.Change{Path: []string{"identities", p.Name, "rules", r.ID}, Value: Rule{Version: factsVersion, Connection: f.Connection, Action: f.Operation.Action, Operation: f.Operation.ID,
		Scope: r.Grant, Requirements: slices.Clone(r.Requirements)}}, nil
}

// answerable validates an answer under s.mu; callers recheck it after pure
// preparation so a concurrent answer cannot be overwritten by a saved rule.
func (s *state) answerable(id string, input Answer, revision uint64) (*record, error) {
	if revision != s.doc.Get().Revision {
		return nil, errPolicyConflict
	}
	choices := []string{answerOnce, answerSave, answerDeny}
	if !slices.Contains(choices, input.Choice) {
		return nil, fmt.Errorf("decision must be one of %s", strings.Join(choices, ", "))
	}
	if len(input.Reason) > maxReason {
		return nil, fmt.Errorf("a reason must be at most %d bytes", maxReason)
	}
	r := s.findRecord(id)
	if r == nil {
		return nil, fmt.Errorf("no request %s", id)
	}
	if r.State != statePending && !(r.State == stateExpired && input.Choice == answerSave) {
		return nil, fmt.Errorf("request %s is %s", id, r.State)
	}
	return r, nil
}

// answer records review and wakes the request waiting on r.
func (s *state) answer(r *record, review Review) {
	review.Time = time.Now()
	r.Reviews = append(r.Reviews, review)
	r.State = stateApproved
	if review.Choice == answerDeny {
		r.State = stateDenied
	}
	s.records.Notify()
}

// saved records review once its rule is durable: a pending request is approved, and an expired one must be retried.
func (s *state) saved(r *record, review Review) {
	if r.State == statePending {
		r.State = stateApproved
	} else {
		r.State, r.Deny = stateRefused, []string{errRuleSaved.Error()}
	}
	review.Time = time.Now()
	r.Reviews = append(r.Reviews, review)
}

func (s *state) answerRequest(ctx context.Context, id string, input Answer, revision uint64) error {
	input.Reason = strings.TrimSpace(input.Reason)
	c, _ := callerFrom(ctx)
	s.mu.Lock()
	r := s.findRecord(id)
	applies := input.Choice == answerSave || input.Choice == answerOnce && r != nil && r.Changes != nil
	var refusal error
	if r != nil {
		refusal = s.admitCall(ctx, s.settings.Load(), adminCall{Answer: input, Record: r})
	}
	s.mu.Unlock()
	if refusal != nil {
		return refusal
	}
	review := Review{By: c.Name, Answer: input}
	if applies {
		s.writes.Lock()
		defer s.writes.Unlock()
		s.mu.Lock()
		r, err := s.answerable(id, input, revision)
		var change perimeterformat.Change
		if err == nil && input.Choice == answerSave {
			change, err = s.ruleChange(r)
		}
		s.mu.Unlock()
		if err != nil {
			return err
		}
		changes := r.Changes
		if input.Choice == answerSave {
			changes = []perimeterformat.Change{change}
		}
		err = s.writeSettings(ctx, settingsWrite{changes: changes, check: func() error {
			current, err := s.answerable(id, input, revision)
			if err == nil && current != r {
				return errRecordGone
			}
			return err
		}, saved: &savedAnswer{record: r, answer: review}})
		if err == nil && r.Changes != nil {
			s.mu.Lock()
			s.settleRecord(r, nil)
			s.mu.Unlock()
		}
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, err := s.answerable(id, input, revision)
	if err != nil {
		return err
	}
	s.answer(r, review)
	if r.Changes != nil {
		s.settleRecord(r, nil)
	}
	return nil
}

// auditPage is one page of settled records, newest first.
type auditPage struct {
	Records []recordSummary `json:"records"`
	Next    string          `json:"next,omitempty"`
}

// readAuditPage returns settled records older than the segment named by before, newest first.
// Records still in the live log are skipped, so the page continues where the live log ends.
func (s *state) readAuditPage(ctx context.Context, before string) (auditPage, error) {
	s.mu.Lock()
	live := map[string]bool{}
	for r := range s.records.All() {
		live[r.ID] = true
	}
	s.mu.Unlock()
	page := auditPage{Records: []recordSummary{}}
	var err, malformed error
	page.Next, err = s.audit.Page(ctx, before, func(segment string, line []byte) bool {
		r, err := decodeRecord(line)
		malformed = cmp.Or(malformed, err)
		if err != nil || live[r.ID] {
			return false
		}
		summary := summarize(r)
		summary.Segment = segment
		page.Records = append(page.Records, summary)
		return true
	})
	return page, cmp.Or(err, malformed)
}

func (s *state) readAuditRecord(ctx context.Context, segment, id string) (*record, error) {
	lines, err := s.audit.Read(ctx, segment)
	if err != nil {
		return nil, err
	}
	for _, line := range lines {
		r, err := decodeRecord(line)
		if err != nil {
			return nil, err
		}
		if r.ID == id {
			return r, nil
		}
	}
	return nil, errRecordGone
}

func decodeRecord(line []byte) (*record, error) {
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.UseNumber()
	r := new(record)
	return r, decoder.Decode(r)
}

// ---------------------------------------------------------------------------
// Owner and agent APIs.

const (
	ownerName        = "owner"
	maxDocumentBytes = 16 << 20
	// Base64 inflates an owner RPC call by a third.
	maxCallBytes  = 2 * maxDocumentBytes
	maxAgentBytes = 96 << 10
	adminPrefix   = "/admin"
	agentHost     = agentConnection + connectionDomain
	agentPort     = 80
)

var errLocked = httpError{errors.New("the Perimeter is locked"), http.StatusLocked}

// caller is an authenticated admin request, at the generation its client has saved.
type caller struct {
	Name        string
	Owner       bool           // Holds the owner key.
	Claims      map[string]any // Verified by the caller's transport, for policy to read.
	Minimum     uint64
	Acknowledge func() error
	ID          string
	Key         []byte // The storage key the transport authenticated with.
}

type callerKey struct{}

type routeKey struct{}

func withCaller(ctx context.Context, c caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

func callerFrom(ctx context.Context) (caller, bool) {
	c, ok := ctx.Value(callerKey{}).(caller)
	return c, ok
}

// jsonHandler decodes a POST body into T and answers fn's value as JSON.
func jsonHandler[T any](limit int64, fn func(*http.Request, T) (any, error)) http.HandlerFunc {
	return gzhttp.GzipHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		var req T
		if r.Method == http.MethodPost {
			if err := httpjson.Decode(w, r, limit, &req); err != nil {
				fail(w, err)
				return
			}
		}
		value, err := fn(r, req)
		var response []byte
		if err == nil {
			response, err = json.Marshal(value)
		}
		if c, ok := callerFrom(r.Context()); ok && c.Acknowledge != nil && err == nil {
			err = c.Acknowledge()
		}
		if err != nil {
			fail(w, err)
			return
		}
		// Validate only after authentication and the SSH generation acknowledgement.
		// A weak validator covers both identity and compressed representations of this JSON.
		if r.Method == http.MethodGet {
			tag := fmt.Sprintf(`W/"%x"`, sha256.Sum256(response))
			w.Header().Set("ETag", tag)
			for _, known := range strings.Split(r.Header.Get("If-None-Match"), ",") {
				known = strings.TrimSpace(known)
				if known == "*" || strings.TrimPrefix(known, "W/") == strings.TrimPrefix(tag, "W/") {
					w.WriteHeader(http.StatusNotModified)
					return
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(response)
	}))
}

// fail answers err with the status its HTTPStatus() picks, or 400.
func fail(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	var specific interface{ HTTPStatus() int }
	if errors.As(err, &specific) {
		status = specific.HTTPStatus()
	}
	http.Error(w, err.Error(), status)
}

// refused is an admin call that policy, or a policy loaded from a file, does not allow.
type refused string

func (r refused) Error() string { return string(r) }
func (refused) HTTPStatus() int { return http.StatusForbidden }

// unavailable is a dependency failure, never a client error.
type unavailable struct{ error }

func (unavailable) HTTPStatus() int { return http.StatusServiceUnavailable }

type httpError struct {
	error
	status int
}

func (e httpError) HTTPStatus() int { return e.status }

type unlockInput struct {
	Generation uint64 `json:"generation"`
	StorageKey []byte `json:"storage_key,omitempty"`
	DeviceKey  string `json:"device_key,omitempty"`
}

type sourceInput struct {
	Revision *uint64 `json:"revision,omitempty"`
	Source   string  `json:"source"`
}

type editsInput struct {
	Revision    *uint64                  `json:"revision,omitempty"`
	Changes     []perimeterformat.Change `json:"changes"`
	Credentials perimeterformat.Secrets  `json:"credentials,omitempty"`
}

// adminAPI serves the admin routes, adminRoutes among them.
func (s *state) adminAPI() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", jsonHandler(0, func(r *http.Request, _ struct{}) (any, error) {
		var health struct {
			State string `json:"state,omitempty"`
		}
		// Only owners learn whether state exists; the probe reads storage.
		if c, _ := callerFrom(r.Context()); c.Owner {
			present, err := stateExists(r.Context(), s.bucket)
			if err != nil {
				return nil, unavailable{err}
			}
			health.State = map[bool]string{false: "absent", true: "present"}[present]
		}
		return health, nil
	}))
	mux.Handle("POST /unlock", jsonHandler(maxDocumentBytes, func(r *http.Request, req unlockInput) (any, error) {
		c, err := requestCaller(r)
		key := req.StorageKey
		if err == nil && len(key) == 0 {
			key = c.Key
		}
		if err != nil {
			return nil, err
		}
		req.Generation = max(req.Generation, c.Minimum)
		defer clear(key)
		ctx := withCaller(r.Context(), c)
		initialized, err := s.unlock(ctx, key, req.Generation)
		if err == nil && req.DeviceKey != "" {
			err = s.restoreDevice(ctx, req.DeviceKey)
		}
		view, err := s.viewAfter(r, err)
		view.Initialized = initialized
		return view, err
	}))
	mux.Handle("GET /{$}", ownerTx(s, func(r *http.Request, _ struct{}) (any, error) { return s.view(r) }))
	mux.Handle("POST /enroll", s.ownerOnly(jsonHandler(maxDocumentBytes, func(r *http.Request, input map[string]identityEnrollment) (any, error) {
		return s.viewAfter(r, s.enroll(r.Context(), input))
	})))
	for pattern, handler := range adminRoutes {
		mux.Handle(pattern, s.ownerOnly(handler.ServeHTTP))
	}
	mux.Handle("POST /labels/{identity}", ownerTx(s, func(r *http.Request, l perimeterformat.Label) (any, error) {
		// A certified name can be held by several keys, and each key has its own label.
		fingerprints := s.identities.Keys(r.PathValue("identity"))
		if fingerprints == nil {
			return nil, fmt.Errorf("no identity %s", r.PathValue("identity"))
		}
		if !validLabel(l) {
			return nil, fmt.Errorf("a label needs trust in %v and audience in %v", trusts, audiences)
		}
		var err error
		for _, fingerprint := range fingerprints {
			old := s.label(fingerprint)
			l.Because = map[string]string{}
			if l.Trust != initialLabel.Trust {
				l.Because["trust"] = cmp.Or(old.Because["trust"], "the owner")
			}
			if l.Audience != initialLabel.Audience {
				l.Because["audience"] = cmp.Or(old.Because["audience"], "the owner")
			}
			if err = s.relabel(r.Context(), fingerprint, l, nil); err != nil {
				break
			}
		}
		s.recordAdmin(r.Context(), "Set the label of "+r.PathValue("identity"), l, err)
		if err != nil {
			return nil, err
		}
		return s.view(r)
	}))
	mux.Handle("POST /connections/{name}/sign-in", s.ownerOnly(jsonHandler(maxDocumentBytes, s.startSignIn)))
	mux.Handle("POST /sign-in/{state}", s.ownerOnly(jsonHandler(maxDocumentBytes, s.finishSignIn)))
	mux.Handle("/connections/{name}/{control...}", s.ownerOnly(s.connectionControl))
	mux.Handle("GET /requests", ownerTx(s, func(*http.Request, struct{}) (any, error) {
		newest := []recordSummary{}
		for _, r := range slices.Backward(slices.Collect(s.records.All())) {
			newest = append(newest, summarize(r))
		}
		return newest, nil
	}))
	mux.Handle("GET /audit", s.ownerOnly(jsonHandler(0, func(r *http.Request, _ struct{}) (any, error) {
		return s.readAuditPage(r.Context(), r.URL.Query().Get("before"))
	})))
	mux.Handle("GET /audit/{segment}/{id}", s.ownerOnly(jsonHandler(0, func(r *http.Request, _ struct{}) (any, error) {
		return s.readAuditRecord(r.Context(), r.PathValue("segment"), r.PathValue("id"))
	})))
	mux.Handle("GET /requests/{id}", ownerTx(s, func(r *http.Request, _ struct{}) (any, error) {
		if record := s.findRecord(r.PathValue("id")); record != nil {
			return *record, nil
		}
		return nil, errRecordGone
	}))
	mux.Handle("POST /requests/{id}", s.ownerOnly(jsonHandler(maxDocumentBytes, func(r *http.Request, req struct {
		Answer
		Revision uint64 `json:"revision"`
	}) (any, error) {
		return s.viewAfter(r, s.answerRequest(r.Context(), r.PathValue("id"), req.Answer, req.Revision))
	})))
	mux.Handle("GET /policy", ownerTx(s, func(r *http.Request, _ struct{}) (any, error) {
		doc := s.doc.Get()
		result := map[string]any{"source": doc.Policy, "revision": doc.Revision}
		var err error
		if r.URL.Query().Has("effective") {
			result["effective"], err = s.settings.Load().Config.Effective()
		}
		return result, err
	}))
	mux.Handle("POST /policy/preview", s.ownerOnly(jsonHandler(maxDocumentBytes, func(r *http.Request, input sourceInput) (any, error) {
		s.writes.Lock()
		defer s.writes.Unlock()
		base, before := s.snapshot()
		return s.previewPolicy(r.Context(), base, before, input.Source)
	})))
	mux.Handle("POST /policy", s.ownerOnly(jsonHandler(maxDocumentBytes, func(r *http.Request, input sourceInput) (any, error) {
		s.writes.Lock()
		defer s.writes.Unlock()
		return s.viewAfter(r, s.writeSettings(r.Context(), settingsWrite{source: &input.Source, check: s.reviewed(input.Revision)}))
	})))
	mux.Handle("POST /policy/edits", s.ownerOnly(jsonHandler(maxDocumentBytes, func(r *http.Request, input editsInput) (any, error) {
		for _, values := range input.Credentials {
			for name, raw := range values {
				if bytes.Equal(raw, []byte("null")) {
					values[name] = nil
				}
			}
		}
		s.writes.Lock()
		defer s.writes.Unlock()
		err := s.writeSettings(r.Context(), settingsWrite{changes: input.Changes, credentials: input.Credentials, check: s.reviewed(input.Revision)})
		return s.viewAfter(r, err)
	})))
	return mux
}

func (s *state) connectionControl(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	handler, setupCtx, release, ok := s.table.Control(name)
	if !ok {
		if _, installed := s.table.Connections()[name]; !installed {
			http.NotFound(w, r)
			return
		}
		http.Error(w, errChanged.Error(), http.StatusConflict)
		return
	}
	defer release()
	ctx, cancel := netx.Bind(r.Context(), setupCtx)
	defer cancel()
	r.Body = http.MaxBytesReader(w, r.Body, maxDocumentBytes)
	http.StripPrefix("/connections/"+name, handler).ServeHTTP(w, r.WithContext(ctx))
}

// viewAfter renders the owner view once an action that ran without s.mu succeeds.
func (s *state) viewAfter(r *http.Request, err error) (ownerView, error) {
	if err != nil {
		return ownerView{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.view(r)
}

// ownerTx runs each owner request as one transaction; reading the body and writing the response stay outside it.
func ownerTx[T any](s *state, fn func(*http.Request, T) (any, error)) http.HandlerFunc {
	return s.ownerOnly(jsonHandler(maxDocumentBytes, func(r *http.Request, input T) (any, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		return fn(r, input)
	}))
}

// ownerOnly serves an admitted admin caller without s.mu, for calls that wait on the network.
func (s *state) ownerOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st := s.settings.Load()
		c, err := requestCaller(r)
		if err == nil && st == nil {
			err = errLocked
		}
		ctx := withCaller(context.WithValue(r.Context(), routeKey{}, r.Pattern), c)
		if err == nil {
			err = s.admitCall(ctx, st, adminCall{})
		}
		if err != nil {
			fail(w, err)
			return
		}
		next(w, r.WithContext(ctx))
	}
}

// admitCall asks policy whether the caller in ctx may make its call; call carries the answer and record of an answer.
func (s *state) admitCall(ctx context.Context, st *settings, call adminCall) error {
	c, _ := callerFrom(ctx)
	call.Caller = policyCaller{Name: c.Name, Owner: c.Owner, Claims: c.Claims}
	call.Route, _ = ctx.Value(routeKey{}).(string)
	var deny []string
	err := st.policy.Eval(ctx, queryAdmin, call, &deny)
	if err == nil && len(deny) != 0 {
		err = refused(strings.Join(deny, "; "))
	}
	return err
}

func requestCaller(r *http.Request) (caller, error) {
	if c, ok := callerFrom(r.Context()); ok {
		return c, nil
	}
	return caller{}, errOwner
}

type agentCatalogView struct {
	CatalogID  string                  `json:"catalog_id"`
	Presets    map[string]catalogEntry `json:"presets"`
	Vocabulary map[string]obligations  `json:"vocabulary"`
}

// agentAPI serves an identity's own API inside its SSH tunnel.
func (s *state) agentAPI(key string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /connections", agentTx(s, key, func(_ *http.Request, _ struct{}, p facts.Principal) (any, error) {
		return s.listing(p), nil
	}))
	mux.HandleFunc("GET /policy", agentTx(s, key, func(_ *http.Request, _ struct{}, p facts.Principal) (any, error) {
		return s.agentPolicy(p)
	}))
	mux.HandleFunc("GET /catalog", agentTx(s, key, func(*http.Request, struct{}, facts.Principal) (any, error) {
		st := s.settings.Load()
		return agentCatalogView{CatalogID: st.catalogID, Presets: st.catalog, Vocabulary: vocabulary}, nil
	}))
	mux.HandleFunc("GET /policy/proposals/{id}", agentTx(s, key, func(r *http.Request, _ struct{}, p facts.Principal) (any, error) {
		record := s.findRecord(r.PathValue("id"))
		if record == nil || record.Changes == nil || !summarize(record).Facts.Principal.Same(p) {
			return nil, errRecordGone
		}
		return receipt(record), nil
	}))
	mux.HandleFunc("POST /policy/proposals", jsonHandler(maxAgentBytes, func(r *http.Request, input proposalInput) (any, error) {
		return s.proposePolicy(r.Context(), key, input)
	}))
	api := s.adminAPI()
	mux.Handle(adminPrefix+"/", http.StripPrefix(adminPrefix, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := s.identities.Lookup(key)
		switch {
		case !ok:
			fail(w, errNoAgent)
		case p.Name == ownerName:
			fail(w, refused("an identity named owner cannot make admin calls"))
		// A browser pointed at a forwarded port sends its own Host; unlock reads the storage key.
		case r.Host != agentHost || r.URL.Path == "/unlock":
			http.NotFound(w, r)
		default:
			c := caller{Name: p.Name, ID: key, Claims: map[string]any{"key": key, "groups": append([]string{}, p.Groups...)}}
			api.ServeHTTP(w, r.WithContext(withCaller(r.Context(), c)))
		}
	})))
	return mux
}

func agentTx[T any](s *state, key string, fn func(*http.Request, T, facts.Principal) (any, error)) http.HandlerFunc {
	return jsonHandler(maxAgentBytes, func(r *http.Request, input T) (any, error) {
		s.mu.Lock()
		defer s.mu.Unlock()
		p, ok := s.identities.Lookup(key)
		if !ok {
			return nil, errNoAgent
		}
		return fn(r, input, p)
	})
}

type fieldMetadata struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Placeholder string `json:"placeholder,omitempty"`
	Account     string `json:"account,omitempty"`
}

// ownerView exposes credential status without credential values.
type ownerView struct {
	Generation uint64                           `json:"generation"`
	Revision   uint64                           `json:"revision"`
	Config     map[string]any                   `json:"config"`
	HostKey    string                           `json:"host_key"`
	HostID     string                           `json:"host_id"`
	CA         string                           `json:"ca"`
	Fields     map[string][]fieldMetadata       `json:"fields"`
	Status     map[string]core.Status           `json:"status"`
	Labels     map[string]perimeterformat.Label `json:"labels"`
	CatalogID  string                           `json:"catalog_id"`
	Presets    map[string]catalogEntry          `json:"presets,omitempty"`
	Vocabulary map[string]obligations           `json:"vocabulary"`
	// Initialized is true only on the unlock that created this Perimeter's state.
	Initialized bool `json:"initialized"`
}

// view snapshots owner state while the caller holds s.mu. It never calls a connector.
// Presets are omitted when the request names the catalog the owner already has.
func (s *state) view(r *http.Request) (ownerView, error) {
	st, doc := s.settings.Load(), s.doc.Get()
	// The persisted CA identifies the host across restarts and SSH key rotation.
	block, _ := pem.Decode([]byte(doc.Keys.CACert))
	if block == nil {
		return ownerView{}, errors.New("Perimeter has no host certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ownerView{}, err
	}
	key, err := jwk.Import(certificate.PublicKey)
	if err != nil {
		return ownerView{}, err
	}
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return ownerView{}, err
	}
	v := ownerView{Generation: doc.Generation, Revision: doc.Revision, HostKey: string(ssh.MarshalAuthorizedKey(st.hostKey.PublicKey())), CA: doc.Keys.CACert,
		HostID: "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" + base64.RawURLEncoding.EncodeToString(thumbprint),
		Fields: map[string][]fieldMetadata{}, Status: map[string]core.Status{}, Labels: map[string]perimeterformat.Label{},
		CatalogID: st.catalogID, Presets: st.catalog, Vocabulary: vocabulary}
	if r.URL.Query().Get("catalog") == st.catalogID {
		v.Presets = nil
	}
	if v.Config, err = st.Config.View(); err != nil {
		return ownerView{}, err
	}
	for name, status := range s.table.Connections() {
		v.Status[name] = status
		for secret, placeholder := range st.connections[name].placeholders {
			kind, account := describeCredential(doc.Credentials.Get(perimeterformat.SecretID{Connection: name, Name: secret}))
			v.Fields[name] = append(v.Fields[name], fieldMetadata{Name: secret, Kind: kind, Placeholder: placeholder, Account: account})
		}
	}
	for _, fields := range v.Fields {
		slices.SortFunc(fields, func(a, b fieldMetadata) int { return strings.Compare(a.Name, b.Name) })
	}
	for key, name := range st.Principals {
		v.Labels[name] = s.label(key)
	}
	return v, nil
}

// Discovery describes reachable connections, not the owner's configuration or credentials.
// HTTP connections add public routing and placeholder data, never credentials.
type connectionListing struct {
	Name         string            `json:"name"`
	Protocol     string            `json:"kind"`
	Host         string            `json:"host"`
	State        string            `json:"state"`
	Access       Access            `json:"access"`
	Hosts        []string          `json:"hosts"`
	Slots        any               `json:"slots"`
	Placeholders map[string]string `json:"placeholders"`
	Credentials  map[string]string `json:"credentials,omitempty"`
}

// listing snapshots the connections p reaches while the caller holds s.mu.
func (s *state) listing(p facts.Principal) any {
	st, doc := s.settings.Load(), s.doc.Get()
	result := struct {
		Identity    string              `json:"identity"`
		CA          string              `json:"ca"`
		Connections []connectionListing `json:"connections"`
	}{p.Name, doc.Keys.CACert, []connectionListing{}}
	status := s.table.Connections()
	for _, name := range slices.Sorted(maps.Keys(status)) {
		c := st.connections[name]
		if !st.Reaches(p.Name, name) {
			continue
		}
		l := connectionListing{Name: name, Protocol: c.Protocol, Host: name + connectionDomain,
			State: status[name].State, Access: st.Access(p.Name, name), Hosts: c.discovery, Slots: c.slots}
		if c.listsPlaceholders {
			l.Placeholders = maps.Clone(c.placeholders)
		}
		if len(c.secrets) != 0 {
			l.Credentials = map[string]string{}
			for secret := range c.secrets {
				l.Credentials[secret], _ = describeCredential(doc.Credentials.Get(perimeterformat.SecretID{Connection: name, Name: secret}))
			}
		}
		result.Connections = append(result.Connections, l)
	}
	return result
}

func (s *state) agentPolicy(p facts.Principal) (any, error) {
	st := s.settings.Load()
	var visible map[string]any
	var err error
	if st.capable(p, capabilityConfig) {
		// Credential values live outside Config.
		visible, err = st.Config.View()
	} else {
		visible, err = st.Config.AgentView(p)
	}
	if err != nil {
		return nil, err
	}
	source, err := perimeterformat.RenderTOML(visible)
	return map[string]any{"identity": p.Name, "source": source}, err
}

// ---------------------------------------------------------------------------
// Credentials.

const (
	credentialTimeout = 30 * time.Second
	signInClient      = "Perimeter"
)

var signInLimits = credential.SignInLimits{Timeout: 30 * time.Second, Lifetime: 10 * time.Minute, MaxDeviceExpiry: 24 * time.Hour, MaxDeviceInterval: 3600,
	MaxResponseBytes: 1 << 20, MaxClientIDBytes: 512}

var errCredentialChanged = errors.New("credential changed; start again")

// bindCredential decodes a stored record into the credential a connection uses. save
// replaces the record an OAuth refresh rotates, compared against the bytes it replaces.
func bindCredential(raw json.RawMessage, client *http.Client, save func(ctx context.Context, before, after json.RawMessage) error) (*credential.Value, error) {
	if raw == nil {
		return new(credential.Value), nil
	}
	c, err := perimeterformat.DecodeCredential(raw)
	switch {
	case err != nil:
		return nil, err
	case c.OAuth != nil:
		before := raw
		return credential.OAuth(c.OAuth, credential.OAuthOptions{Client: client, Timeout: credentialTimeout,
			Save: func(ctx context.Context, grant json.RawMessage) error {
				after := perimeterformat.OAuthCredential(grant)
				if err := save(ctx, before, after); err != nil {
					return err
				}
				before = after
				return nil
			}})
	case c.File != "":
		// Read at each use, so whatever rotates the file rotates the credential.
		if secretFiles == nil {
			return nil, perimeterformat.ErrCredentialShape
		}
		return credential.File(secretFiles, c.File), nil
	case c.Text != nil:
		return credential.Static(*c.Text), nil
	}
	return new(credential.Value), nil
}

// describeCredential returns only the status the owner editor needs and the verified
// OIDC account, without exposing tokens.
func describeCredential(raw json.RawMessage) (kind, account string) {
	c, err := perimeterformat.DecodeCredential(raw)
	if err != nil || c.Text == nil && c.File == "" && c.OAuth == nil {
		return "unset", ""
	}
	if c.OAuth == nil {
		return "static", ""
	}
	ready, account, err := credential.DescribeOAuth(c.OAuth)
	switch {
	case err != nil:
		return "unset", ""
	case ready:
		return "oauth", account
	}
	return "oauth-required", account
}

// placeholder derives a credential's public reference from the persisted CA key, so restarts and
// credential refreshes keep it stable without storing another set of tokens.
// The empty element keeps the references derived from version 1 state.
func placeholder(k perimeterformat.Keys, id perimeterformat.SecretID) string {
	mac := hmac.New(sha256.New, []byte(k.CAKey))
	mac.Write([]byte("monitor credential placeholder v1\x00"))
	raw, _ := json.Marshal([]string{id.Connection, "", id.Name})
	mac.Write(raw)
	suffix := strings.ToLower(base32.StdEncoding.EncodeToString(mac.Sum(nil))[:9])
	return "tfm_" + id.Connection + "_" + suffix
}

// current reports, under s.mu, that value is still the installed credential id names and before its record.
func (s *state) current(id perimeterformat.SecretID, value *credential.Value, before json.RawMessage) bool {
	c := s.settings.Load().connections[id.Connection]
	return c != nil && c.secrets[id.Name] == value && bytes.Equal(s.doc.Get().Credentials.Get(id), before)
}

// replaceValue persists a provider's rotated record; the connector keeps running.
func (s *state) replaceValue(ctx context.Context, id perimeterformat.SecretID, value *credential.Value, before, after json.RawMessage) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.current(id, value, before) {
		return errCredentialChanged
	}
	next := s.doc.Get()
	next.Credentials = next.Credentials.Clone()
	next.Credentials.Set(id, bytes.Clone(after))
	return s.commit(ctx, next)
}

// signInCredential captures the record a sign-in replaces, so completing it cannot
// overwrite a newer edit.
func (s *state) signInCredential(connection, name string) (json.RawMessage, func(context.Context, json.RawMessage) error, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var value *credential.Value
	if c := s.settings.Load().connections[connection]; c != nil {
		value = c.secrets[name]
	}
	if value == nil {
		return nil, nil, errors.New("credential does not exist")
	}
	id := perimeterformat.SecretID{Connection: connection, Name: name}
	before := bytes.Clone(s.doc.Get().Credentials.Get(id))
	return before, func(ctx context.Context, raw json.RawMessage) error {
		s.writes.Lock()
		defer s.writes.Unlock()
		return s.writeSettings(ctx, settingsWrite{credentials: perimeterformat.Secrets{connection: {name: raw}}, check: func() error {
			if !s.current(id, value, before) {
				return errCredentialChanged
			}
			return nil
		}})
	}, nil
}

type signInInput struct {
	Redirect   string          `json:"redirect"`
	Name       string          `json:"name"`
	Credential json.RawMessage `json:"credential"`
}

func (s *state) startSignIn(r *http.Request, req signInInput) (any, error) {
	previous, save, err := s.signInCredential(r.PathValue("name"), req.Name)
	if err != nil {
		return nil, err
	}
	record := previous
	if req.Credential != nil {
		record = req.Credential
	}
	c, err := perimeterformat.DecodeCredential(record)
	if err == nil && c.OAuth == nil {
		err = errors.New("the secret is not an oauth grant")
	}
	if err != nil {
		return nil, err
	}
	session, _ := callerFrom(r.Context())
	sign, err := s.signIns.Start(r.Context(), s.settings.Load().client(), c.OAuth, req.Redirect, session.ID, func(ctx context.Context, grant json.RawMessage) error {
		return save(ctx, perimeterformat.OAuthCredential(grant))
	})
	if errors.Is(err, credential.ErrLoopback) {
		err = errors.New("this service only accepts sign-ins from a loopback address; open this Perimeter on your own computer to sign in")
	}
	if err != nil {
		return nil, err
	}
	if sign.UserCode != "" {
		return map[string]any{"url": sign.URL, "state": sign.State, "user_code": sign.UserCode, "expires": sign.Expires}, nil
	}
	return map[string]string{"url": sign.URL}, nil
}

func (s *state) finishSignIn(r *http.Request, req credential.SignInResult) (any, error) {
	session, _ := callerFrom(r.Context())
	pending, err := s.signIns.Finish(r.Context(), r.PathValue("state"), session.ID, req)
	if pending {
		return map[string]bool{"pending": true}, nil
	}
	if err == nil && req.Cancel {
		return nil, nil
	}
	return s.viewAfter(r, err)
}

// ---------------------------------------------------------------------------
// Transports: SSH for agents, routes and the owner CLI; HTTP for the owner API, as bearer
// calls in local development or Noise sessions over a WebSocket in production.

const (
	readHeaderTimeout = 30 * time.Second
	preflightMaxAge   = "600"
	bearerMode        = "bearer"
	ownerMode         = "ssh"
	ownerHost         = "owner" + connectionDomain
	rpcMode           = "rpc"
	relayMode         = "relay"

	sshChannel           = "tinfoil-owner-http-v1"
	sshGenerationRequest = "tinfoil-owner-generation-v1"
	// sessionHeader carries sshOptions.Token on each API request over the channel.
	sessionHeader = "X-Tinfoil-Session"
	// generationAckTimeout closes a stalled owner channel so an owner client cannot leave its goroutine behind.
	generationAckTimeout = 10 * time.Second

	ownerProtocol   = "monitor-owner-v1"
	ownerRPCSession = "owner-rpc"
	sessionContext  = "tinfoil owner session v1\x00"
	// sessionTimeout bounds the handshake and hello, so unauthenticated sockets do not linger.
	sessionTimeout = 10 * time.Second
	maxCalls       = 4

	relayDrain = 10 * time.Second
)

var (
	sshLimits          = sshtransport.Limits{MaxAuthTries: 3, MaxHandshakes: 64, HandshakeTimeout: 10 * time.Second}
	errMalformed       = errors.New("malformed")
	errSignature       = errors.New("invalid_signature")
	errStaleGeneration = errors.New("Perimeter state is older than the saved generation")
	errCertificate     = errors.New("an identity certificate must be an expiring user certificate with a key ID from the identity CA")
)

// owner authenticates the owner's sessions; nil lets the storage key authenticate bearer calls, for local development.
type owner struct {
	key        ed25519.PublicKey
	sessionKey noise.DHKey
	// relay opens an instance's owner socket, which the owner then runs its own session over; nil refuses relays.
	relay func(ctx context.Context, instance string) (*websocket.Conn, error)
}

// serve runs the SSH and API listeners until ctx ends or either fails, and closes both before it returns.
func (s *state) serve(ctx context.Context, sshListener, apiListener net.Listener, o *owner, ui http.Handler) error {
	defer sshListener.Close()
	defer apiListener.Close()

	if o != nil && s.hostKey() == nil {
		return errors.New("an owner requires a host key")
	}

	api, mode := s.adminAPI(), bearerMode
	if o != nil {
		mode = ownerMode
	}
	if ui != nil {
		app := http.NewServeMux()
		app.Handle("/", api)
		app.Handle("GET /app/auth.json", jsonHandler(0, func(_ *http.Request, _ struct{}) (any, error) {
			return map[string]string{"mode": mode}, nil
		}))
		app.HandleFunc("GET /app/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			ui.ServeHTTP(w, r)
		})
		api = app
	}

	handler := http.NewServeMux()
	handler.Handle("GET /healthz", api)
	var ownerSSH sshtransport.Session
	if o == nil {
		handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if key, err := base64.StdEncoding.Strict().DecodeString(token); ok && err == nil && s.isOwner(key) {
				r = r.WithContext(withCaller(r.Context(), caller{Name: ownerName, Owner: true, Key: key}))
			}
			api.ServeHTTP(w, r)
		})
	} else {
		modes := map[string]func(context.Context, *noisetransport.Session, json.RawMessage){rpcMode: func(ctx context.Context, c *noisetransport.Session, _ json.RawMessage) {
			serveRPC(ctx, c, maxCallBytes, s.ownerRPC(api))
		}}
		if o.relay != nil {
			modes[relayMode] = func(ctx context.Context, c *noisetransport.Session, hello json.RawMessage) {
				relayOwner(ctx, c, hello, o.relay)
			}
		}
		handler.HandleFunc("GET /owner/ws", func(w http.ResponseWriter, r *http.Request) {
			c, hello, err := noisetransport.Accept(w, r, noisetransport.Config{Key: o.sessionKey, Prologue: ownerProtocol, Timeout: sessionTimeout,
				// The signed Noise channel authenticates the owner, not the browser origin.
				Accept: &websocket.AcceptOptions{InsecureSkipVerify: true}}, func(binding, first []byte) error {
				var signed struct {
					Signature []byte `json:"signature"`
				}
				if json.Unmarshal(first, &signed) != nil {
					return errMalformed
				}
				if !ed25519.Verify(o.key, append([]byte(sessionContext), binding...), signed.Signature) {
					return errSignature
				}
				return nil
			})
			if err != nil {
				return
			}
			var open struct {
				Open string `json:"open"`
			}
			if json.Unmarshal(hello, &open) != nil || modes[open.Open] == nil {
				c.Conn.Close(websocket.StatusPolicyViolation, errMalformed.Error())
				return
			}
			modes[open.Open](r.Context(), c, hello)
		})
		ownerSSH = func(_ *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
			go ssh.DiscardRequests(reqs)
			for nc := range chans {
				go s.serveOwnerChannel(nc, api)
			}
		}
	}

	// Extensions take whole connections before identities: the owner CLI, then route publishers.
	authenticate := func(conn ssh.ConnMetadata, key ssh.PublicKey) (sshtransport.Session, func() error, error) {
		if ownerSSH != nil {
			if raw, ok := key.(ssh.CryptoPublicKey); ok {
				if public, ok := raw.CryptoPublicKey().(ed25519.PublicKey); ok && o.key.Equal(public) {
					return ownerSSH, nil, nil
				}
			}
		}
		if session, err := s.publisher(conn.User(), key); session != nil || err != nil {
			return session, nil, err
		}
		if cert, ok := key.(*ssh.Certificate); ok && identityCA != nil {
			// Principals carry groups, not logins, so any listed one stands in for the login.
			claims, err := certificates.VerifySSHUser(identityCA, cert, cmp.Or(cert.ValidPrincipals...))
			if err == nil && (claims.KeyID == "" || claims.ValidBefore == ssh.CertTimeInfinity) {
				err = errCertificate
			}
			if err != nil {
				return nil, nil, err
			}
			// A certificate is public, so it is registered only once its key has signed.
			fingerprint := ssh.FingerprintSHA256(cert.Key)
			return s.agentSession(fingerprint), func() error {
				end, err := s.identities.Register(fingerprint, facts.Principal{Name: claims.KeyID, Groups: claims.Principals}, false)
				if err == nil {
					time.AfterFunc(time.Until(time.Unix(int64(claims.ValidBefore), 0)), end)
				}
				return err
			}, nil
		}
		fingerprint := ssh.FingerprintSHA256(key)
		if _, known := s.identities.Lookup(fingerprint); !known {
			return nil, nil, errNoAccess
		}
		return s.agentSession(fingerprint), nil, nil
	}

	server := &http.Server{Handler: allowOrigins(ownerOrigins, handler), ReadHeaderTimeout: readHeaderTimeout}
	defer server.Close()

	serving, stop := context.WithCancelCause(ctx)
	go func() {
		stop(server.Serve(apiListener))
	}()
	context.AfterFunc(serving, func() {
		sshListener.Close()
	})
	sshtransport.Serve(sshListener, s.hostKey, sshLimits, authenticate, func(err error) { log.Printf("ssh: %v", err) })
	stop(errors.New("the SSH listener closed"))
	if ctx.Err() != nil {
		return nil
	}
	return context.Cause(serving)
}

// agentSession serves an identity's direct-tcpip streams while its key stays registered.
func (s *state) agentSession(fingerprint string) sshtransport.Session {
	return func(_ *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
		sshtransport.ServeDirect(chans, reqs, func(ctx context.Context, host string, port uint32, accept func() (net.Conn, error)) error {
			held, cancel, ok := s.identities.Hold(ctx, fingerprint)
			if !ok {
				return errNoAccess
			}
			defer cancel()
			return s.open(held, fingerprint, host, port, accept)
		})
	}
}

// open serves one agent stream. An identity that holds the routes capability reaches a reserved
// route host directly; every other stream goes to the agent API or a connection.
func (s *state) open(ctx context.Context, key, host string, port uint32, accept func() (net.Conn, error)) error {
	if reservedRoute(host) {
		// Relay under the hold, not ctx, which ends when the stream's channel closes and would cut its drain.
		if held, release, ok := s.hold(context.WithoutCancel(ctx), key, capabilityRoutes); ok {
			defer release()
			if err := netx.Dial(s.routes.DialContext, relayDrain)(held, host, port, accept); err != nil {
				return errDirectUnavailable
			}
			return nil
		}
	}
	if s.settings.Load() == nil {
		return errLocked
	}
	p, known := s.identities.Lookup(key)
	if !known {
		return errNoAccess
	}
	if host != agentHost {
		return s.table.Open(ctx, p, host, port, accept)
	}
	if port != agentPort {
		return fmt.Errorf("%s uses HTTP on port %d inside the SSH tunnel", agentHost, agentPort)
	}
	conn, err := accept()
	if err != nil {
		return err
	}
	netx.ServeConn(ctx, conn, &http.Server{Handler: s.agentAPI(key)})
	return nil
}

// selectTarget picks the connection a stream addresses: by name under connectionDomain, or else
// the single best claim among the candidates the identity reaches.
func selectTarget(host string, port uint32, candidates []core.Candidate) (string, bool, bool) {
	if name, named := strings.CutSuffix(host, connectionDomain); named {
		return name, true, slices.ContainsFunc(candidates, func(c core.Candidate) bool { return c.Name == name })
	}
	best, tied, selected := -1, false, ""
	for _, c := range candidates {
		if c.Claim == nil {
			continue
		}
		score := c.Claim(host, port)
		if score < 0 {
			continue
		}
		if score > best {
			selected, best, tied = c.Name, score, false
		} else if score == best {
			tied = true
		}
	}
	return selected, false, best >= 0 && !tied
}

func (s *state) reaches(_ context.Context, p facts.Principal, connection string) bool {
	current, known := s.identities.Lookup(p.Key)
	return known && s.settings.Load().Reaches(current.Name, connection)
}

// allowOrigins lets the listed origins call the owner API from a browser, such as a dashboard
// holding the owner key in memory. Only the bearer key authenticates; credentials are never allowed.
func allowOrigins(origins []string, next http.Handler) http.Handler {
	if len(origins) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Origin")
		origin := r.Header.Get("Origin")
		if !slices.Contains(origins, origin) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Expose-Headers", "ETag")
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, If-None-Match")
			w.Header().Set("Access-Control-Max-Age", preflightMaxAge)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// stale reports a live state older than a generation the owner has saved.
func (s *state) stale(minimum uint64) bool {
	current, unlocked := s.generation()
	return unlocked && current < minimum
}

// sshOptions is the extra data of an sshChannel, in SSH wire encoding. The authenticated owner CLI supplies it, never the browser.
type sshOptions struct {
	Host       string
	Token      string
	Generation uint64
}

// sshGeneration is the payload of an sshGenerationRequest, in SSH wire encoding.
type sshGeneration struct{ Generation uint64 }

// serveOwnerChannel serves the API to the owner CLI over one SSH channel.
func (s *state) serveOwnerChannel(nc ssh.NewChannel, api http.Handler) {
	if nc.ChannelType() != sshChannel {
		nc.Reject(ssh.Prohibited, "owner connections only serve the owner UI and API")
		return
	}
	var options sshOptions
	if err := ssh.Unmarshal(nc.ExtraData(), &options); err != nil || !validOptions(options) {
		nc.Reject(ssh.Prohibited, "invalid owner channel options")
		return
	}
	if s.stale(options.Generation) {
		nc.Reject(ssh.Prohibited, errStaleGeneration.Error())
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	conn := sshtransport.NewConn(ch, reqs)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { <-conn.Closed(); cancel() }()
	acknowledge := func() error {
		current, unlocked := s.generation()
		if !unlocked {
			return nil
		}
		// Do not report success until the CLI has persisted the generation.
		timer := time.AfterFunc(generationAckTimeout, cancel)
		defer timer.Stop()
		ok, err := ch.SendRequest(sshGenerationRequest, true, ssh.Marshal(sshGeneration{Generation: current}))
		if err != nil || !ok {
			return errors.New("owner CLI did not save the generation")
		}
		return nil
	}
	server := &http.Server{Handler: panel(api, options, acknowledge), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: time.Minute, IdleTimeout: time.Minute, MaxHeaderBytes: 8192}
	netx.ServeConn(ctx, conn, server)
}

func validOptions(o sshOptions) bool {
	token, err := base64.RawURLEncoding.DecodeString(o.Token)
	if err != nil || len(token) != 32 {
		return false
	}
	if o.Host == ownerHost {
		return true
	}
	host, port, err := net.SplitHostPort(o.Host)
	return err == nil && host == "127.0.0.1" && port != "" && !strings.ContainsAny(port, "/?#@ ")
}

// panel keeps browser protections with the measured UI. The CLI only forwards bytes.
func panel(api http.Handler, options sshOptions, acknowledge func() error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		panelPage := r.URL.Path == "/app/" || r.URL.Path == "/app/index.html"
		navigation := r.Method == http.MethodGet && panelPage && r.Header.Get("Sec-Fetch-Mode") == "navigate" && r.Header.Get("Sec-Fetch-Dest") == "document"
		if r.Host != options.Host || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != "http://"+options.Host) || (r.Header.Get("Sec-Fetch-Site") == "cross-site" && !navigation) {
			http.Error(w, "foreign browser origin refused", http.StatusForbidden)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/app/") && r.Method == http.MethodGet {
			api.ServeHTTP(w, r)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get(sessionHeader)), []byte(options.Token)) != 1 {
			http.Error(w, "local panel session required", http.StatusUnauthorized)
			return
		}
		// Only the CLI channel can send the storage key; the browser cannot unlock.
		path := strings.TrimPrefix(r.URL.Path, "/api")
		if (path == "/unlock" && options.Host != ownerHost) || !ownerPath(path) {
			http.NotFound(w, r)
			return
		}
		r = r.Clone(withCaller(r.Context(), caller{Name: ownerName, Owner: true, Minimum: options.Generation, Acknowledge: acknowledge, ID: options.Token}))
		r.URL.Path = path
		r.URL.RawPath = ""
		api.ServeHTTP(w, r)
	})
}

// ownerCall is one owner RPC request; its ownerReply carries the same ID.
type ownerCall struct {
	ID         uint64 `json:"id"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Generation uint64 `json:"generation"`
	Body       []byte `json:"body"`
}

type ownerReply struct {
	ID     uint64 `json:"id"`
	Status int    `json:"status"`
	Body   []byte `json:"body"`
}

// ownerRPC answers each call with api, as a request carrying the call's method, path and body.
func (s *state) ownerRPC(api http.Handler) func(context.Context, ownerCall) ownerReply {
	return func(ctx context.Context, call ownerCall) ownerReply {
		if !validRPCPath(call.Path) || (call.Method != http.MethodGet && call.Method != http.MethodPost) || (call.Method == http.MethodGet && len(call.Body) != 0) {
			return ownerReply{Status: http.StatusBadRequest, Body: []byte(errMalformed.Error())}
		}
		if s.stale(call.Generation) {
			return ownerReply{Status: http.StatusConflict, Body: []byte(errStaleGeneration.Error())}
		}
		// An admitted effect finishes even if its socket closes.
		if call.Method == http.MethodPost {
			ctx = context.WithoutCancel(ctx)
		}
		ctx = withCaller(ctx, caller{Name: ownerName, Owner: true, Minimum: call.Generation, ID: ownerRPCSession})
		r, err := http.NewRequestWithContext(ctx, call.Method, call.Path, bytes.NewReader(call.Body))
		if err != nil {
			return ownerReply{Status: http.StatusBadRequest, Body: []byte(errMalformed.Error())}
		}
		if call.Method == http.MethodPost {
			r.Header.Set("Content-Type", "application/json")
		}
		recorder := httptest.NewRecorder()
		api.ServeHTTP(recorder, r)
		return ownerReply{Status: recorder.Code, Body: recorder.Body.Bytes()}
	}
}

// validRPCPath accepts an origin-relative owner API path; it checks ownerPath after percent-decoding.
func validRPCPath(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") && !strings.Contains(raw, "\\") &&
		u.Scheme == "" && u.Host == "" && u.User == nil && u.Opaque == "" && u.Fragment == "" &&
		path.Clean(u.Path) == u.Path && ownerPath(u.Path)
}

// ownerPath refuses the app, a nested owner session, and paths an upstream could resolve differently.
func ownerPath(p string) bool {
	return !strings.Contains(p, "..") && !strings.Contains(p, "\\") && !slices.ContainsFunc([]string{"/app", "/owner"}, func(reserved string) bool {
		return p == reserved || strings.HasPrefix(p, reserved+"/")
	})
}

// serveRPC answers calls of at most limit bytes, a few at once and in any order, until the socket ends.
func serveRPC(ctx context.Context, c *noisetransport.Session, limit int, serve func(context.Context, ownerCall) ownerReply) {
	running := make(chan struct{}, maxCalls)
	for {
		var call ownerCall
		message, err := c.Read(ctx, limit)
		if err == nil {
			err = json.Unmarshal(message, &call)
		}
		if err != nil {
			c.Conn.Close(websocket.StatusPolicyViolation, errMalformed.Error())
			return
		}
		running <- struct{}{}
		go func() {
			defer func() { <-running }()
			reply := serve(ctx, call)
			reply.ID = call.ID
			out, _ := json.Marshal(reply)
			c.Write(ctx, out)
		}()
	}
}

// relayOwner opens the owner socket of the hello's instance, which the owner then runs its own session over.
func relayOwner(ctx context.Context, c *noisetransport.Session, hello json.RawMessage, dial func(ctx context.Context, instance string) (*websocket.Conn, error)) {
	var open struct {
		InstanceID string `json:"instance_id"`
	}
	if json.Unmarshal(hello, &open) != nil {
		c.Conn.Close(websocket.StatusPolicyViolation, errMalformed.Error())
		return
	}
	upstream, err := dial(ctx, open.InstanceID)
	if err != nil {
		// The innermost cause fits the close frame's 123-byte reason; dial wrappers add the URL.
		for errors.Unwrap(err) != nil {
			err = errors.Unwrap(err)
		}
		c.Conn.Close(websocket.StatusInternalError, "relay unavailable: "+err.Error())
		return
	}
	upstream.SetReadLimit(noise.MaxMsgLen)
	defer c.Conn.CloseNow()
	go func() {
		copyMessages(ctx, upstream, c.Conn)
		upstream.CloseNow()
	}()
	copyMessages(ctx, c.Conn, upstream)
}

// copyMessages copies whole messages until either side ends, passing on its close.
func copyMessages(ctx context.Context, dst, src *websocket.Conn) {
	for {
		kind, message, err := src.Read(ctx)
		var closed websocket.CloseError
		if errors.As(err, &closed) {
			dst.Close(closed.Code, closed.Reason)
		}
		if err != nil || dst.Write(ctx, kind, message) != nil {
			return
		}
	}
}

// parseOwnerKey reads a measured owner key. A small-order point would verify forged
// signatures for any message, so only canonical keys outside the torsion subgroup pass.
func parseOwnerKey(value string) (ed25519.PublicKey, error) {
	encoded, ok := strings.CutPrefix(value, "ed25519:")
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if ok && err == nil && len(key) == ed25519.PublicKeySize && "ed25519:"+base64.StdEncoding.EncodeToString(key) == value {
		point, err := new(edwards25519.Point).SetBytes(key)
		if err == nil && bytes.Equal(point.Bytes(), key) && new(edwards25519.Point).MultByCofactor(point).Equal(edwards25519.NewIdentityPoint()) == 0 {
			return key, nil
		}
	}
	return nil, errors.New("owner public key must be ed25519: followed by the base64 of a valid Ed25519 public key")
}

// ---------------------------------------------------------------------------
// Tinfoil sandboxes: route publishers, reserved route hosts and the bootstrap relay.

const (
	maxUntrustedPublishers = 128
	maxForwardAddresses    = 128
	forwardOpenTimeout     = 10 * time.Second
	// An identity publishes an OpenSSH SOCKS RemoteForward on this loopback port.
	socksPort = "1080"
	aliasPort = 443
	// Listeners on 127.0.0.1 do not accept this loopback alias; wildcard listeners do.
	wildcardHost = "127.0.0.2"
	forwardHost  = "127.0.0.1"
	// A negative claim refuses a target.
	unclaimed = -1

	routeSuffix = ".sandbox.invalid"
	// An identity reaches another enrolled identity, NAME, as NAME.sandbox.
	identitySuffix = ".sandbox"
	// bootstrapUser prefixes the SSH user a publisher announces its bootstrap route as.
	bootstrapUser = "sandbox-v2:"
	// fingerprintPrefix starts the SHA-256 key fingerprints that are the identity registry's key IDs.
	fingerprintPrefix = "SHA256:"
	sandboxAttribute  = "sandbox"
)

var (
	errRouteUnavailable  = errors.New("not connected to the Perimeter")
	errDirectUnavailable = fmt.Errorf("route %w", sshtransport.ErrUnavailable)
	pinnedSource         = regexp.MustCompile(`@sha256:[0-9a-f]{64}$`)
)

// routeName names a key's route by its fingerprint; a malformed fingerprint names no publisher.
func routeName(fingerprint string) string {
	digest, _ := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(fingerprint, fingerprintPrefix))
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest)) + routeSuffix
}

// bootstrapRoute names an unverified publisher by the instance it claims. Only its port
// 443 is reachable this way; callers verify what it serves, and the route grants no agent access.
func bootstrapRoute(instance string) string {
	digest := sha256.Sum256([]byte(bootstrapUser + instance))
	return "bootstrap-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])) + routeSuffix
}

func reservedRoute(host string) bool {
	host = "." + strings.TrimSuffix(strings.ToLower(host), ".")
	return strings.HasSuffix(host, identitySuffix) || strings.HasSuffix(host, routeSuffix)
}

// routeAllowed reports whether a route pattern among hosts matches host, so * never reaches a route.
func routeAllowed(hosts []string, host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return slices.ContainsFunc(hosts, func(pattern string) bool {
		ok, _ := path.Match(strings.ToLower(pattern), host)
		return ok && reservedRoute(pattern)
	})
}

// publisher names an authenticated peer and an optional discovery alias.
// Trusted publishers are exempt from the limit on untrusted connections.
type publisher struct {
	Name, Alias string
	Trusted     bool
}

type forwardPeer struct {
	publisher
	conn     *ssh.ServerConn
	forwards *sshtransport.Forwards
}

// forwarder serves virtual TCP forwards without binding sockets on the server.
// Each authenticated name owns one connection; aliases must resolve uniquely.
type forwarder struct {
	mu    sync.Mutex
	peers map[string]*forwardPeer
}

// servePublisher replaces a peer's previous connection immediately and owns its
// registrations until disconnect. Callers supply names from authentication.
// Only explicit ports (1-65535) are accepted; no local sockets are bound.
func (f *forwarder) servePublisher(conn *ssh.ServerConn, channels <-chan ssh.NewChannel, requests <-chan *ssh.Request, identity publisher) {
	defer conn.Close()
	if identity.Name == "" {
		return
	}
	f.mu.Lock()
	unknown := 0
	for name, peer := range f.peers {
		if name != identity.Name && !peer.Trusted {
			unknown++
		}
	}
	if !identity.Trusted && unknown >= maxUntrustedPublishers {
		f.mu.Unlock()
		return
	}
	previous := f.peers[identity.Name]
	peer := &forwardPeer{publisher: identity, conn: conn, forwards: sshtransport.NewForwards(conn, maxForwardAddresses, forwardOpenTimeout)}
	if f.peers == nil {
		f.peers = map[string]*forwardPeer{}
	}
	f.peers[identity.Name] = peer
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.peers[identity.Name] == peer {
			delete(f.peers, identity.Name)
		}
	}()
	if previous != nil {
		previous.conn.Close()
	}
	go func() {
		for channel := range channels {
			channel.Reject(ssh.Prohibited, "publisher connections cannot open client channels")
		}
	}()
	peer.forwards.Serve(requests)
}

// DialContext opens a publisher's virtual loopback forward at address, a peer name or
// unambiguous alias with a port. Addresses are scoped to the publisher, so peers can publish the
// same ports. Aliases expose only port 443; key-derived names may use any port.
func (f *forwarder) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	host, service, err := net.SplitHostPort(address)
	port, invalid := strconv.ParseUint(service, 10, 16)
	if err != nil || invalid != nil || port == 0 {
		return nil, errRouteUnavailable
	}
	name := strings.TrimSuffix(strings.ToLower(host), ".")
	f.mu.Lock()
	peer := f.peers[name]
	if peer == nil && name != "" && port == aliasPort {
		for _, candidate := range f.peers {
			if candidate.Alias == name && candidate.forwards.Has(forwardHost, uint32(port)) {
				if peer != nil {
					f.mu.Unlock()
					return nil, errRouteUnavailable
				}
				peer = candidate
			}
		}
	}
	f.mu.Unlock()
	if peer == nil {
		return nil, errRouteUnavailable
	}
	conn, err := peer.forwards.Dial(forwardHost, uint32(port))
	if err != nil {
		return nil, errRouteUnavailable
	}
	return conn, nil
}

// routeDial dials reserved route hosts that hosts name through the route forwarder, and every other address through next.
func (s *state) routeDial(hosts []string, next dialFunc) dialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || !reservedRoute(host) {
			return next(ctx, network, address)
		}
		name, named := strings.CutSuffix(strings.TrimSuffix(strings.ToLower(host), "."), identitySuffix)
		keys := s.identities.Keys(name)
		if !routeAllowed(hosts, host) || !named || len(keys) != 1 {
			return nil, errRouteUnavailable
		}
		// The SOCKS server is the publisher's own ssh client, reached over an SSH channel, not a socket.
		server := net.JoinHostPort(routeName(keys[0]), socksPort)
		socks, err := proxy.SOCKS5(network, server, nil, nil)
		if err != nil {
			return nil, err
		}
		conn, err := s.routes.DialContext(ctx, network, server)
		if err != nil {
			return nil, err
		}
		// The handshake runs on the channel itself, so callers keep its half-close and closure.
		if _, err := socks.(interface {
			DialWithConn(context.Context, net.Conn, string, string) (net.Addr, error)
		}).DialWithConn(ctx, conn, network, net.JoinHostPort(wildcardHost, port)); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}
}

// routeClaim keeps a connection from being chosen for a reserved route host its hosts do not name.
func routeClaim(hosts []string, claim func(string, uint32) int) func(string, uint32) int {
	if claim == nil {
		return nil
	}
	return func(host string, port uint32) int {
		if reservedRoute(host) && !routeAllowed(hosts, host) {
			return unclaimed
		}
		return claim(host, port)
	}
}

// publisher returns the reverse-tunnel publisher session that user announces with key, or nil
// for any other user. Key probes never enroll or restore an identity.
func (s *state) publisher(user string, key ssh.PublicKey) (sshtransport.Session, error) {
	instance, announced := strings.CutPrefix(user, bootstrapUser)
	if !announced {
		return nil, nil
	}
	if instance == "" {
		return nil, errors.New("a publisher instance is required")
	}
	if _, unlocked := s.generation(); !unlocked {
		return nil, errLocked
	}
	fingerprint := ssh.FingerprintSHA256(key)
	p := publisher{Name: routeName(fingerprint), Alias: bootstrapRoute(instance)}
	_, p.Trusted = s.identities.Lookup(fingerprint)
	return func(conn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
		s.routes.servePublisher(conn, chans, reqs, p)
	}, nil
}

// Boot is the sandbox boot an identity belongs to. Its persisted JSON matches the
// existing identity.sandbox source and owner API representation.
type Boot struct {
	Source     string `json:"source"`
	InstanceID string `json:"instance_id"`
}

// validateBoot checks the integration-owned portion of an identity before
// the host commits it. An absent boot is valid for ordinary agent identities.
func validateBoot(raw json.RawMessage) error {
	var b Boot
	if len(raw) == 0 {
		return nil
	}
	if err := facts.DecodeNumbers(raw, &b); err != nil || b == (Boot{}) {
		return err
	}
	if !pinnedSource.MatchString(b.Source) {
		return errors.New("source must be a digest-pinned release reference")
	}
	if b.InstanceID == "" {
		return errors.New("instance_id is required")
	}
	return nil
}

const (
	sandboxRelayRoute = "POST /sandboxes/relay"
	maxRelayBytes     = 1 << 20

	maxRelayAttestationBytes = 32 << 20
	relayHopTimeout          = 30 * time.Second
	relayIdleTimeout         = time.Minute
	relayIdleConns           = 4
	// attestationPath serves attestation evidence for a ?nonce=, on enclaves and bunkers alike.
	attestationPath       = "/.well-known/tinfoil-attestation"
	sandboxAttestationURL = "http://sandbox" + attestationPath + "?nonce="
	sandboxOwnerPath      = "/owner/ws"
	bootstrapPort         = "443"
)

var (
	instancePattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hex32Pattern    = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	errRelayInput   = errors.New("a relay needs a bunker instance_id and an attestation nonce")
)

// relayInput selects a bunker boot by its measured instance.
type relayInput struct {
	InstanceID string `json:"instance_id"`
	Nonce      string `json:"nonce"`
}

type relayReply struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
}

// relaySandbox fetches one attestation over a bunker's bootstrap route and returns the response
// bytes unchanged. That route is unverified and grants no agent access.
func relaySandbox(ctx context.Context, relays http.RoundTripper, in relayInput) (relayReply, error) {
	if !instancePattern.MatchString(in.InstanceID) || !hex32Pattern.MatchString(in.Nonce) {
		return relayReply{}, errRelayInput
	}
	request, err := http.NewRequest(http.MethodGet, sandboxAttestationURL+in.Nonce, nil)
	if err != nil {
		return relayReply{}, err
	}
	// An empty User-Agent is omitted, so the bunker receives no client headers.
	request.Header = http.Header{"User-Agent": {""}}
	// Connections are pooled per route; the bunker still sees its own Host.
	request.URL.Host = net.JoinHostPort(bootstrapRoute(in.InstanceID), bootstrapPort)
	ctx, cancel := context.WithTimeout(ctx, relayHopTimeout)
	defer cancel()
	response, err := relays.RoundTrip(request.WithContext(ctx))
	if err != nil {
		return relayReply{}, httpError{errors.New("bunker relay: " + err.Error()), http.StatusBadGateway}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxRelayAttestationBytes+1))
	if err == nil && len(body) > maxRelayAttestationBytes {
		err = errors.New("the response is too large")
	}
	if err != nil {
		return relayReply{}, httpError{errors.New("bunker relay: " + err.Error()), http.StatusBadGateway}
	}
	return relayReply{Status: response.StatusCode, Body: base64.RawURLEncoding.EncodeToString(body)}, nil
}

// dialSandboxOwner opens a bunker boot's owner socket over its bootstrap route.
func dialSandboxOwner(ctx context.Context, relays http.RoundTripper, instance string) (*websocket.Conn, error) {
	if !instancePattern.MatchString(instance) {
		return nil, errRelayInput
	}
	client := &http.Client{Transport: relays, Timeout: relayHopTimeout}
	conn, _, err := websocket.Dial(ctx, "ws://"+net.JoinHostPort(bootstrapRoute(instance), bootstrapPort)+sandboxOwnerPath, &websocket.DialOptions{HTTPClient: client})
	return conn, err
}

// ---------------------------------------------------------------------------
// Tinfoil inference: HTTP and MCP connectors to an attested enclave.

const (
	tinfoilKey             = "TINFOIL_API_KEY"
	attestationTimeout     = 30 * time.Second
	maxAttestationBytes    = 32 << 20
	tinfoilAPIPath         = "/v1"
	countTokensUnsupported = "Tinfoil does not expose token counting"
)

// messageLimits bound the inference responses converted for Messages clients.
var messageLimits = messages.Limits{ErrorBytes: 1 << 20, ResultBytes: 16 << 20, EventBytes: 8 << 20}

type tinfoilSetup struct {
	Enclave string `json:"enclave"`
	Repo    string `json:"repo"`
}

func validateEnclave(enclave, repo string) error {
	if !slots.ValidOrigin("https://"+enclave) || strings.Trim(enclave, web.HostChars) != "" || strings.Contains(enclave, ":") {
		return errors.New("Tinfoil enclave must be a lowercase HTTPS hostname without a port")
	}
	_, _, _, err := verify.ParseReference(repo)
	return err
}

func tinfoilKeySlot(enclave string) slots.Slot {
	return slots.Slot{Value: tinfoilKey, Origin: "https://" + enclave, Path: tinfoilAPIPath, Header: "Authorization", Prefix: "Bearer "}
}

// parseTinfoil reads an inference setup: the enclave's HTTP API, with its key in one fixed slot.
func parseTinfoil(spec ConnectionSpec) (*tinfoilSetup, *web.Setup, slots.Set, error) {
	t := new(tinfoilSetup)
	if err := facts.DecodeNumbers(spec.Config, t); err != nil {
		return nil, nil, slots.Set{}, err
	}
	if err := validateEnclave(t.Enclave, t.Repo); err != nil {
		return nil, nil, slots.Set{}, err
	}
	set, err := slots.New([]slots.Slot{tinfoilKeySlot(t.Enclave)}, httpSlots)
	if err != nil {
		return nil, nil, slots.Set{}, err
	}
	setup, err := web.New(spec.Definition, spec.Options, nil, web.Slots{Claim: set.Claim, Covers: set.Covers, Bind: set.Bind})
	return t, setup, set, err
}

// parseTinfoilMCP reads an MCP setup whose HTTPS server is an attested enclave, and its repository.
func parseTinfoilMCP(spec ConnectionSpec) (*mcp.Setup, string, error) {
	var config struct {
		mcp.Setup
		Repo string `json:"repo"`
	}
	if err := mcp.Decode(spec.Config, spec.Definition, &config, &config.Setup); err != nil {
		return nil, "", err
	}
	u, _ := url.Parse(config.URL)
	if u.Scheme != "https" || u.User != nil {
		return nil, "", errors.New("Tinfoil MCP requires an HTTPS URL without user information")
	}
	return &config.Setup, config.Repo, validateEnclave(u.Host, config.Repo)
}

// attest verifies the enclave before callers can send credentials or MCP discovery.
// Inference and MCP share the same attestation, renewal and TLS key binding.
func attest(ctx context.Context, h worker.Host, key, enclave, repo string, base *http.Transport) (*attestation.Transport, error) {
	if !h.Configured(key) {
		return nil, errors.New("Tinfoil API key is not configured")
	}
	verifier, err := verify.NewVerifier()
	if err != nil {
		return nil, err
	}
	return attestation.New(ctx, attestation.Config{Host: enclave, Path: attestationPath, Nonce: tinfoildoc.RandomNonce, Base: base,
		Timeout: attestationTimeout, MaxBytes: maxAttestationBytes,
		Verify: func(evidence, nonce []byte) (string, time.Time, error) {
			verified, err := verifier.VerifyV3(evidence, nonce, repo)
			if err != nil {
				return "", time.Time{}, fmt.Errorf("verify Tinfoil attestation: %w", err)
			}
			pin, ok := verified.TLSPublicKeyFP()
			if !ok {
				return "", time.Time{}, errors.New("invalid attested Tinfoil TLS key")
			}
			return pin, verified.FreshnessExpiresAt, nil
		}})
}

// open attests the enclave once per setup; its pool serves every stream and owner chat.
func (t *tinfoilSetup) open(ctx context.Context, setup *web.Setup, h worker.Host) (worker.Instance, error) {
	base := upstreamTransport(h.Dial)
	transport, err := attest(ctx, h, tinfoilKey, t.Enclave, t.Repo, base)
	if err != nil {
		base.CloseIdleConnections()
		return worker.Instance{}, err
	}
	control := http.NewServeMux()
	control.Handle("POST /chat/completions", &httputil.ReverseProxy{Transport: transport, Rewrite: func(r *httputil.ProxyRequest) {
		key, _ := h.Secret(r.In.Context(), tinfoilKey)
		r.Out.URL, r.Out.Host = &url.URL{Scheme: "https", Host: t.Enclave, Path: "/v1/chat/completions"}, ""
		r.Out.Header = http.Header{"Authorization": {"Bearer " + key}, "Content-Type": {"application/json"}}
	}})
	serve := func(ctx context.Context, conn net.Conn, name, host string, port uint32, gate core.Gate) {
		handler := web.Handler{Setup: setup, Transport: transport, CheckRedirect: refuseRedirects, TLS: h.TLS, Placeholder: h.Placeholder, Secret: h.Secret, MaxBody: maxBodyBytes,
			ServeHTTP: func(ctx context.Context, c net.Conn, server *http.Server) error {
				return netx.ServeConn(ctx, c, server)
			}}
		privateHost := ""
		if host == "" {
			privateHost = name + connectionDomain
			named := *setup
			named.Hosts = []string{privateHost}
			handler.Setup = &named
		}
		handler.Prepare = func(r *http.Request, original *web.HTTPFacts) (http.RoundTripper, error) {
			if privateHost != "" && r.URL.Host == privateHost {
				slot := tinfoilKeySlot(t.Enclave)
				if r.URL.Path != slot.Path && !strings.HasPrefix(r.URL.Path, slot.Path+"/") {
					return nil, errors.New("Tinfoil API requests must use a " + slot.Path + " path")
				}
				// Put a public placeholder in the normal slot. The shared HTTP path
				// captures the enclave target and resolves the key only after the gate.
				placeholder := h.Placeholder(tinfoilKey)
				if placeholder == "" {
					return nil, errors.New("Tinfoil credential is unavailable")
				}
				r.URL.Scheme, r.URL.Host, r.Host = "https", t.Enclave, t.Enclave
				r.Header.Del("X-Api-Key")
				r.Header.Set(slot.Header, slot.Prefix+placeholder)
			}
			return prepareAPIRequest(r, original, transport)
		}
		handler.Serve(ctx, conn, name, host, port, gate)
	}
	return worker.Instance{Serve: serve, Control: control, Close: func() error {
		transport.CloseIdleConnections()
		base.CloseIdleConnections()
		return nil
	}}, nil
}

// apiTransport only adapts responses. Request normalization is complete before
// the gate, and every upstream request uses the original attested transport.
type apiTransport struct {
	http.RoundTripper
	messages    bool
	streaming   bool
	model       any
	countTokens bool
}

func (t apiTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	// The deployed router has no token-count endpoint. Let Claude use its local
	// estimate instead of making a billed completion disguised as token counting.
	if t.countTokens {
		return messages.Error(r, http.StatusNotImplemented, "not_supported_error", countTokensUnsupported), nil
	}
	resp, err := t.RoundTripper.RoundTrip(r)
	if err != nil || !t.messages {
		return resp, err
	}
	return messages.Response(r, resp, t.model, t.streaming, messageLimits)
}

// prepareAPIRequest consumes the web parser's unambiguous JSON, normalizes the
// deployed coding clients and leaves response conversion for after execution.
func prepareAPIRequest(r *http.Request, original *web.HTTPFacts, transport http.RoundTripper) (http.RoundTripper, error) {
	if r.Method != http.MethodPost {
		return nil, nil
	}
	switch r.URL.Path {
	case "/v1/messages", "/v1/messages/count_tokens", "/v1/responses":
	default:
		return nil, nil
	}
	body, ok := original.Body.(map[string]any)
	if original.BodyKind != web.BodyJSON || !ok {
		return nil, fmt.Errorf("inference requests require an unambiguous JSON object of at most %d MiB", maxBodyBytes>>20)
	}
	response := apiTransport{RoundTripper: transport}
	if r.URL.Path == "/v1/responses" {
		// Codex 0.153.4 emits developer messages. Tinfoil's Responses backend
		// accepts these instructions under the system role instead.
		input, _ := body["input"].([]any)
		for _, item := range input {
			if message, ok := item.(map[string]any); ok && message["role"] == "developer" {
				message["role"] = "system"
			}
		}
	} else {
		response.messages, response.model = true, body["model"]
		response.streaming, _ = body["stream"].(bool)
		var err error
		body, err = messages.Request(body)
		if err != nil {
			return nil, err
		}
		if r.URL.Path == "/v1/messages/count_tokens" {
			response.countTokens = true
			return response, nil
		}
		r.URL.Path, r.URL.RawPath, r.URL.RawQuery = "/v1/chat/completions", "", ""
		r.Header.Del("Anthropic-Version")
		r.Header.Del("Anthropic-Beta")
		// Response conversion reads uncompressed bytes, including streamed events.
		r.Header.Set("Accept-Encoding", "identity")
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil }
	r.ContentLength = int64(len(raw))
	r.TransferEncoding = nil
	r.Header.Del("Content-Length")
	return response, nil
}

// ---------------------------------------------------------------------------
// Protocols: each connection's kind selects its parser, its host capabilities and its policy hints.
// The same selection opens a connector in process and in an isolated worker.

const (
	connectionDomain  = ".perimeter"
	placeholderPrefix = "tfm_"
	// HTTP bodies and WebSocket messages larger than this are opaque to policy.
	maxBodyBytes = 8 << 20
	// SigV4 signs bodies of at most this size.
	maxSignedBodyBytes   = 16 << 20
	connectorOpenTimeout = time.Minute
	dialTimeout          = 30 * time.Second
	upstreamTimeout      = 30 * time.Second
	maxWorkers           = 32
	maxMailBytes         = 25 << 20
	maxMQTTPacket        = 1 << 20
	// maxMQTTPending bounds the QoS 2 publishes awaiting release.
	maxMQTTPending   = 16
	workerBroker     = "/broker.sock"
	workerListenerFD = 3
)

// Deployed protocol and worker limits.
var (
	sftpLimits   = session.SFTPLimits{Packet: 1 << 20, Handles: 1024}
	cliLimits    = session.Limits{Stdin: 1 << 20, WaitDelay: time.Second}
	natsLimits   = nats.Limits{Payload: 1 << 20, Line: 8192, Subscriptions: 1024, PendingMessages: 128, PendingBytes: 4 << 20, Timeout: upstreamTimeout}
	workerLimits = worker.Limits{Streams: 128, Upstreams: 32, Handshake: dialTimeout, Credential: credentialTimeout, Sign: 10 * time.Second,
		Connections: 32, Idle: 8, PoolIdle: 30 * time.Second, Read: 10 * time.Second, ServeIdle: time.Minute}
)

// protocols are the connection kinds, which policies also see as protocols. hostProtocols reach
// host resources outside their grants, so only local development registers them.
var (
	protocols     = []string{"tcp", "http", "mcp", "ssh", "sftp", "cli", "mqtt", "nats", "imap", "smtp", "redis", "postgres", "ssh-agent", "gpg-agent", "tinfoil", "tinfoil-mcp"}
	hostProtocols = []string{"cli", "gpg-agent"}
)

type dialFunc = func(ctx context.Context, network, address string) (net.Conn, error)

// operationSummary is protocol-neutral catalog metadata, never an authorization input.
type operationSummary struct {
	Action  string   `json:"action"`
	Effects []string `json:"effects,omitempty"`
}

// parsed is one connection's setup as its protocol parsed it: what the table stages, what
// discovery and the catalog show, how policy reads its observations and how it opens.
type parsed struct {
	ConnectionSpec
	claim             func(string, uint32) int
	hosts             []string // upstream hosts and host patterns the setup names
	discovery         []string
	slots             any
	operations        map[string]operationSummary // nil: no operation listing
	secretNames       []string
	perMessage        bool // each operation is gated against captured input, so streams outlive label changes
	listsPlaceholders bool // agents send credential placeholders in place of secrets
	hostKey           bool // the connector authenticates as the Perimeter's SSH host
	// hint fills the sends and observes hints policy resolves for an observation and any effects
	// its protocol implies, or refuses an observation the product does not admit.
	hint func(o *facts.Observation, c *requestContext) error
	open func(ctx context.Context, h worker.Host) (worker.Instance, error)
}

// parseConnection selects spec's protocol. It validates and compiles the setup without I/O.
func parseConnection(spec ConnectionSpec) (*parsed, error) {
	p := &parsed{ConnectionSpec: spec, hint: func(*facts.Observation, *requestContext) error { return nil }}
	serveHTTP := func(ctx context.Context, c net.Conn, server *http.Server) error {
		return netx.ServeConn(ctx, c, server)
	}
	relay := func(ctx context.Context, a, b net.Conn) { netx.Relay(ctx, a, b, relayDrain) }
	switch spec.Protocol {
	case "tcp":
		t, err := tcp.Parse(spec.Config)
		if err != nil {
			return nil, err
		}
		p.claim, p.hosts = t.Claim, t.Hosts
		p.hint = func(_ *facts.Observation, c *requestContext) error {
			c.Sends, c.Observes = "anyone", perimeterformat.Label{Audience: "me", Trust: "untrusted"}
			return nil
		}
		p.open = func(_ context.Context, h worker.Host) (worker.Instance, error) {
			return worker.Instance{Serve: t.Handler(h.Dial, relay)}, nil
		}
	case "http", "tinfoil":
		var set slots.Set
		parseSlots := func(raw json.RawMessage) (web.Slots, error) {
			var err error
			set, err = slots.Parse(raw, httpSlots)
			return web.Slots{Claim: set.Claim, Covers: set.Covers, Bind: set.Bind}, err
		}
		var setup *web.Setup
		var enclave *tinfoilSetup
		var err error
		if spec.Protocol == "http" {
			setup, err = web.Parse(spec.Config, spec.Definition, spec.Options, parseSlots)
		} else {
			enclave, setup, set, err = parseTinfoil(spec)
		}
		if err != nil {
			return nil, err
		}
		if enclave == nil {
			p.discovery = setup.Hosts
		}
		p.claim, p.hosts, p.slots, p.secretNames, p.perMessage, p.listsPlaceholders = setup.Claim, setup.Hosts, set, set.Names(), true, true
		sends := map[string]string{}
		if setup.Preset != nil {
			p.operations = map[string]operationSummary{}
			for id, op := range setup.Preset.Operations {
				// The product requires every reviewed operation to declare its effects.
				if len(op.Effects) == 0 {
					return nil, fmt.Errorf("invalid operation %q", id)
				}
				var audience string
				if op.Sends != nil && json.Unmarshal(op.Sends, &audience) != nil || !validEffects(op.Effects) || !validSends(audience) {
					return nil, fmt.Errorf("invalid effects or audience for operation %s", id)
				}
				p.operations[id], sends[id] = operationSummary{Action: op.Action, Effects: op.Effects}, audience
			}
		}
		p.hint = func(o *facts.Observation, c *requestContext) error {
			var details struct {
				HTTP struct {
					WebSocket bool   `json:"websocket"`
					Method    string `json:"method"`
				} `json:"http"`
			}
			raw, _ := json.Marshal(o.Details)
			json.Unmarshal(raw, &details)
			switch {
			case details.HTTP.WebSocket && details.HTTP.Method == "":
				// A received WebSocket message neither repeats the request's effects nor sends upstream;
				// the connection labels its entire opaque payload.
				c.Sends = "me"
				if o.Operation != nil {
					o.Operation.Effects = []string{"read"}
				}
			case details.HTTP.WebSocket && o.Operation == nil:
				return errors.New("WebSocket requests require a reviewed operation")
			case o.Operation != nil:
				c.Sends = sends[o.Operation.ID]
			}
			return nil
		}
		p.open = func(ctx context.Context, h worker.Host) (worker.Instance, error) {
			if enclave != nil {
				return enclave.open(ctx, setup, h)
			}
			return worker.Instance{Serve: func(ctx context.Context, conn net.Conn, name, host string, port uint32, gate core.Gate) {
				transport := upstreamTransport(h.Dial)
				defer transport.CloseIdleConnections()
				web.Handler{Setup: setup, Transport: transport, CheckRedirect: refuseRedirects, TLS: h.TLS, ServeHTTP: serveHTTP, Placeholder: h.Placeholder, Secret: h.Secret, MaxBody: maxBodyBytes}.Serve(ctx, conn, name, host, port, gate)
			}}, nil
		}
	case "mcp", "tinfoil-mcp":
		var setup *mcp.Setup
		var repo string
		var err error
		if spec.Protocol == "mcp" {
			setup, err = mcp.Parse(spec.Config, spec.Definition)
		} else {
			setup, repo, err = parseTinfoilMCP(spec)
		}
		if err != nil {
			return nil, err
		}
		// A preset's data flow applies to every tool call.
		var sends string
		var observes *perimeterformat.Label
		if pr := setup.Preset; pr != nil {
			if len(pr.Sends) != 0 && facts.DecodeNumbers(pr.Sends, &sends) != nil || len(pr.Observes) != 0 && facts.DecodeNumbers(pr.Observes, &observes) != nil ||
				!validSends(sends) || observes != nil && !validLabel(*observes) {
				return nil, errors.New("invalid MCP data-flow settings")
			}
		}
		p.hosts, p.secretNames = setup.Hosts(), []string{"token"}
		p.hint = func(_ *facts.Observation, c *requestContext) error {
			c.Sends = sends
			if observes != nil {
				c.Observes = *observes
			}
			return nil
		}
		p.open = func(ctx context.Context, h worker.Host) (worker.Instance, error) {
			transport := upstreamTransport(h.Dial)
			var base http.RoundTripper = transport
			closeTransport := transport.CloseIdleConnections
			if repo != "" {
				attested, err := attest(ctx, h, "token", setup.Hosts()[0], repo, transport)
				if err != nil {
					transport.CloseIdleConnections()
					return worker.Instance{}, err
				}
				base, closeTransport = attested, func() { attested.CloseIdleConnections(); transport.CloseIdleConnections() }
			}
			client := mcp.Client{HTTP: &http.Client{Transport: base, CheckRedirect: refuseRedirects}, Timeout: upstreamTimeout, TLS: h.TLS, ServeHTTP: serveHTTP,
				// Only tools and instructions the owner pinned are exposed.
				Expose: func(current *mcp.Snapshot) ([]*mcpsdk.Tool, string) {
					ok, _ := setup.Pin.Approved(current)
					if len(ok) > 0 {
						return ok, current.Instructions
					}
					return ok, ""
				}}
			if h.Configured("token") {
				client.Token = func(ctx context.Context) (string, error) { return h.Secret(ctx, "token") }
			}
			session, err := mcp.Open(ctx, setup, client)
			if err != nil {
				closeTransport()
				return worker.Instance{}, err
			}
			current := session.Snapshot()
			ok, _ := setup.Pin.Approved(current)
			status := map[string]any{"blocked": len(current.Tools) - len(ok)}
			if len(ok) < len(current.Tools) {
				status["changes"], status["pin"] = setup.Pin.Diff(current), current
			}
			details, _ := json.Marshal(status)
			return worker.Instance{Serve: session.Serve, Details: details, Close: func() error {
				err := session.Close()
				closeTransport()
				return err
			}}, nil
		}
	case "ssh", "sftp":
		var hosts []string
		var handler func(dialFunc, ssh.Signer, func(context.Context) (string, error)) core.Serve
		if spec.Protocol == "ssh" {
			c, err := session.ParseSSH(spec.Config)
			if err != nil {
				return nil, err
			}
			hosts, handler = c.Hosts(), c.Handler
		} else {
			c, err := session.ParseSFTP(spec.Config)
			if err != nil {
				return nil, err
			}
			hosts = c.Hosts()
			handler = func(dial dialFunc, host ssh.Signer, key func(context.Context) (string, error)) core.Serve {
				return c.Handler(dial, host, key, sftpLimits)
			}
		}
		p.hosts, p.secretNames, p.hostKey = hosts, []string{"key"}, true
		p.open = func(_ context.Context, h worker.Host) (worker.Instance, error) {
			return worker.Instance{Serve: handler(h.Dial, h.HostKey, func(ctx context.Context) (string, error) { return h.Secret(ctx, "key") })}, nil
		}
	case "cli":
		c, err := session.ParseCLI(spec.Config)
		if err != nil {
			return nil, err
		}
		p.secretNames, p.hostKey = c.Credentials, true
		p.open = func(_ context.Context, h worker.Host) (worker.Instance, error) {
			return worker.Instance{Serve: c.Handler(h.HostKey, h.Secret, cliLimits)}, nil
		}
	case "ssh-agent":
		c, err := signer.ParseSSHAgent(spec.Config)
		if err != nil {
			return nil, err
		}
		p.secretNames = c.Credentials
		p.open = func(_ context.Context, h worker.Host) (worker.Instance, error) {
			return worker.Instance{Serve: c.Handler(h.Secret)}, nil
		}
	case "gpg-agent":
		c, err := signer.ParseGPGAgent(spec.Config)
		if err != nil {
			return nil, err
		}
		p.open = func(context.Context, worker.Host) (worker.Instance, error) {
			// The agent socket is a host resource, dialed directly.
			return worker.Instance{Serve: c.Handler((&net.Dialer{Timeout: dialTimeout}).DialContext)}, nil
		}
	case "imap", "smtp", "redis", "mqtt", "nats", "postgres":
		return parseEndpoint(p, spec)
	default:
		return nil, fmt.Errorf("unknown kind %s", spec.Protocol)
	}
	p.claim = routeClaim(p.hosts, p.claim)
	return p, nil
}

// parseEndpoint selects the protocols that dial one upstream URL with a password.
func parseEndpoint(p *parsed, spec ConnectionSpec) (*parsed, error) {
	var hosts []string
	var handler func(h worker.Host) core.Serve
	password := func(h worker.Host) func(context.Context) (string, error) {
		return func(ctx context.Context) (string, error) { return h.Secret(ctx, "password") }
	}
	p.secretNames = []string{"password"}
	var err error
	switch spec.Protocol {
	case "imap":
		var c *email.IMAP
		if c, err = email.ParseIMAP(spec.Config); err == nil {
			hosts = c.Hosts()
			handler = func(h worker.Host) core.Serve { return c.Handler(h.Dial, password(h)) }
		}
	case "smtp":
		var c *email.SMTP
		if c, err = email.ParseSMTP(spec.Config); err == nil {
			hosts = c.Hosts()
			handler = func(h worker.Host) core.Serve {
				return c.Handler(h.Dial, password(h), h.TLS, func(ctx context.Context, conn net.Conn) net.Listener { return netx.Listen(ctx, conn) }, maxMailBytes)
			}
		}
		var options PolicyOptions
		json.Unmarshal(spec.Options, &options)
		p.hint = func(o *facts.Observation, c *requestContext) error {
			var details struct {
				SMTP struct {
					To []string `json:"to"`
				} `json:"smtp"`
			}
			raw, _ := json.Marshal(o.Details)
			json.Unmarshal(raw, &details)
			// Mail to the connection's own address stays within its audience.
			c.Sends = sendsConnection
			for _, to := range details.SMTP.To {
				if !strings.EqualFold(to, options.Address) {
					c.Sends = "anyone"
				}
			}
			return nil
		}
	case "redis":
		var c *redis.Redis
		if c, err = redis.Parse(spec.Config); err == nil {
			hosts = c.Hosts()
			handler = func(h worker.Host) core.Serve { return c.Handler(h.Dial, password(h)) }
		}
	case "mqtt":
		var c *mqtt.MQTT
		if c, err = mqtt.Parse(spec.Config); err == nil {
			hosts = c.Hosts()
			handler = func(h worker.Host) core.Serve { return c.Handler(h.Dial, password(h), maxMQTTPacket, maxMQTTPending) }
		}
		p.perMessage = true
		p.hint = connectionAudience
	case "nats":
		var c *nats.NATS
		if c, err = nats.Parse(spec.Config); err == nil {
			hosts = c.Hosts()
			handler = func(h worker.Host) core.Serve { return c.Handler(h.Dial, h.Secret, natsLimits) }
		}
		p.secretNames, p.perMessage = []string{"password", "token"}, true
		p.hint = connectionAudience
	case "postgres":
		var c *postgres.Postgres
		if c, err = postgres.Parse(spec.Config); err == nil {
			hosts = c.Hosts()
			handler = func(h worker.Host) core.Serve { return c.Handler(h.Dial, password(h), h.TLS, upstreamTimeout) }
		}
	}
	if err != nil {
		return nil, err
	}
	p.hosts = hosts
	p.open = func(_ context.Context, h worker.Host) (worker.Instance, error) {
		return worker.Instance{Serve: handler(h)}, nil
	}
	p.claim = routeClaim(p.hosts, p.claim)
	return p, nil
}

// connectionAudience sends a pub/sub message to the connection's configured audience.
func connectionAudience(_ *facts.Observation, c *requestContext) error {
	c.Sends = sendsConnection
	return nil
}

func validSends(sends string) bool {
	return sends == "" || sends == sendsConnection || slices.Contains(audiences, sends)
}

// observe binds a connection's captured event to the facts policy and audit read: its
// protocol's hints, and its operation's lineage and effects from the preset's actions.
func (st *settings) observe(connection string, event facts.Event) (requestFacts, error) {
	o, err := event.Decode()
	f := requestFacts{Parameters: o.Parameters, Scope: o.Scope, Title: o.Title, Details: o.Details}
	c := st.connections[connection]
	if c == nil {
		return f, errChanged
	}
	if refused := c.hint(&o, &f.Context); err == nil {
		err = refused
	}
	if o.Operation != nil {
		f.Operation = resolveOperation(o.Operation.ID, o.Operation.Action, o.Operation.Effects, presets[st.Connections[connection].Preset].Catalog.Actions)
	}
	return f, err
}

// upstreamTransport sends a connector's requests through dial.
func upstreamTransport(dial dialFunc) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = dial
	return transport
}

// guardedDialer checks the resolved address, so DNS cannot steer an upstream into a refused range.
func guardedDialer(allowed []netip.Prefix) *net.Dialer {
	var v4, v6 []netip.Prefix
	for _, p := range allowed {
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	guard := ssrf.New(ssrf.WithAnyPort(), ssrf.WithAllowedV4Prefixes(v4...), ssrf.WithAllowedV6Prefixes(v6...))
	return &net.Dialer{Timeout: dialTimeout, Control: guard.Safe}
}

// client is for requests the Perimeter makes itself, such as OAuth.
func (st *settings) client() *http.Client {
	return &http.Client{Transport: upstreamTransport(guardedDialer(st.AllowNetworks).DialContext), CheckRedirect: refuseRedirects}
}

// refuseRedirects fails a redirect, which could carry a credential elsewhere.
func refuseRedirects(*http.Request, []*http.Request) error {
	return errors.New("redirects are refused")
}

// opener opens c's connector with st's capabilities, in this process or an isolated worker.
// Its dial reaches reserved route hosts only as its setup names them.
func (s *state) opener(st *settings, c *installed) core.Open {
	dial := s.routeDial(c.hosts, guardedDialer(st.AllowNetworks).DialContext)
	var hostKey ssh.Signer
	if c.hostKey {
		hostKey = st.hostKey
	}
	return func(ctx context.Context) (core.Connector, error) {
		if workers == nil {
			instance, err := c.open(ctx, worker.Host{Dial: dial, HostKey: hostKey, TLS: st.streamTLS,
				Secret:      func(ctx context.Context, name string) (string, error) { return c.secrets[name].Value(ctx) },
				Configured:  func(name string) bool { return c.secrets[name].Configured() },
				Placeholder: func(name string) string { return c.placeholders[name] },
			})
			return core.Connector{Serve: instance.Serve, Close: instance.Close, Details: instance.Details, Control: instance.Control}, err
		}
		data, err := json.Marshal(c.ConnectionSpec)
		if err != nil {
			return core.Connector{}, err
		}
		grants := worker.Grants{Connect: netx.Connect(netx.Dial(dial, relayDrain)), Secrets: map[string]worker.Secret{}, HostKey: hostKey,
			Certificate: func(name string) (*tls.Certificate, error) {
				return st.tls.GetCertificate(&tls.ClientHelloInfo{ServerName: name})
			}}
		for name, value := range c.secrets {
			grants.Secrets[name] = worker.Secret{Configured: value.Configured(), Placeholder: c.placeholders[name], Value: value.Value}
		}
		p, err := worker.Launch(ctx, workers.Start, data, grants, workerNet, workerLimits)
		if err != nil {
			return core.Connector{}, err
		}
		return core.Connector{Serve: p.Serve, Close: p.Close, Ready: p.Ready, Details: p.Details(), Control: p.Control()}, nil
	}
}

// streamTLS is the server configuration for one stream; a client without SNI is issued the stream's host.
func (st *settings) streamTLS(_ context.Context, host string) *tls.Config {
	config := st.tls.Clone()
	issue := config.GetCertificate
	config.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName == "" {
			named := *hello
			named.ServerName = host
			hello = &named
		}
		return issue(hello)
	}
	return config
}

// httpSlots place credentials in HTTP requests, never in form fields.
var httpSlots = slots.Options{Prefix: placeholderPrefix, MaxSignedBody: maxSignedBodyBytes}

var workerNet = worker.Net{
	Relay:    func(ctx context.Context, a, b net.Conn) { netx.Relay(ctx, a, b, relayDrain) },
	Serve:    netx.ServeListener,
	Hijack:   netx.Hijack,
	Buffered: netx.Buffered,
}

// serveWorkerChild serves the one connection a Perimeter host launched this process for.
func serveWorkerChild() error {
	file := os.NewFile(workerListenerFD, "connector-listener")
	ln, err := net.FileListener(file)
	file.Close()
	if err != nil {
		return err
	}
	broker := func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", workerBroker)
	}
	return worker.Serve(context.Background(), func(ctx context.Context, data json.RawMessage, h worker.Host) (worker.Instance, error) {
		var spec ConnectionSpec
		if err := json.Unmarshal(data, &spec); err != nil {
			return worker.Instance{}, err
		}
		p, err := parseConnection(spec)
		if err != nil {
			return worker.Instance{}, err
		}
		return p.open(ctx, h)
	}, os.Stdin, ln, broker, workerNet, workerLimits)
}

// ---------------------------------------------------------------------------
// Startup.

func main() {
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("unexpected server arguments; use the separately installed perimeter client")
	}
	// A worker runs one connector over inherited descriptors. Its host owns configuration,
	// authenticated streams, policy decisions and credentials.
	if *serveWorker {
		if err := serveWorkerChild(); err != nil {
			log.Fatal(err)
		}
		return
	}
	var err error
	development = !*production && strings.HasPrefix(*bucketURL, "file://")
	if presets, presetDefaults, err = loadPresets(extraPresets); err != nil {
		log.Fatal(err)
	}
	if basePolicy != "" {
		if _, err := preparePolicy(context.Background(), new(Config)); err != nil {
			log.Fatal(err)
		}
	}
	if *connectorWorkers {
		workers = bubblewrap(*workerRoot)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	bucket, err := blob.OpenBucket(ctx, *bucketURL)
	if err != nil {
		log.Fatal(err)
	}
	defer bucket.Close()
	s := newState(ctx, bucket)

	// Each bunker's bootstrap connections stay open between relayed requests, so a request
	// does not wait for a new forwarded channel.
	relays := &http.Transport{DisableCompression: true, MaxIdleConnsPerHost: relayIdleConns, IdleConnTimeout: relayIdleTimeout, DialContext: s.routes.DialContext}
	adminRoutes = map[string]http.Handler{sandboxRelayRoute: jsonHandler(maxRelayBytes, func(r *http.Request, in relayInput) (any, error) {
		return relaySandbox(r.Context(), relays, in)
	})}
	app := http.StripPrefix("/app/", http.FileServerFS(ui.Files))
	if *uiDevURL != "" {
		if !development {
			log.Fatal("-ui-dev-url requires a development file:// bucket without -production")
		}
		if app, err = uiDevProxy(*uiDevURL); err != nil {
			log.Fatal(err)
		}
	}
	// Production owners authenticate through SSH or Noise sessions and unlock the
	// encrypted state. Only local development permits bearer authentication.
	var o *owner
	if *ownerPublicKey != "" || !development {
		if unlockKey != nil {
			log.Fatal("-owner-key-file requires a development file:// bucket without -owner-public-key")
		}
		o = &owner{relay: func(ctx context.Context, instance string) (*websocket.Conn, error) {
			return dialSandboxOwner(ctx, relays, instance)
		}}
		if o.key, err = parseOwnerKey(*ownerPublicKey); err != nil {
			log.Fatal(err)
		}
		if o.sessionKey, err = noisetransport.LoadKey(*ownerSessionKey); err != nil {
			log.Fatal(err)
		}
	}
	passphraseKeys = o == nil
	if unlockKey != nil {
		if _, err := s.unlock(ctx, unlockKey, 0); err != nil {
			log.Fatal(err)
		}
	}
	sshListener, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	apiListener, err := net.Listen("tcp", *api)
	if err != nil {
		log.Fatal(err)
	}
	err = s.serve(ctx, sshListener, apiListener, o, app)
	stop()
	s.close()
	if err != nil {
		log.Fatal(err)
	}
}

// bubblewrap launches each connector worker from this executable in the prepared read-only root.
func bubblewrap(rootDir string) *worker.Local {
	return &worker.Local{Limit: maxWorkers, Net: workerNet, Limits: workerLimits, Command: func(broker string) (*exec.Cmd, error) {
		root, err := filepath.Abs(rootDir)
		if err != nil || rootDir == "" || root == "/" {
			return nil, errors.New("worker root must be a prepared filesystem directory")
		}
		root, err = filepath.EvalSymlinks(root)
		if err != nil || root == "/" {
			return nil, errors.New("worker root must be a prepared filesystem directory")
		}
		if info, err := os.Stat(root); err != nil || !info.IsDir() {
			return nil, errors.New("worker root directory does not exist")
		}
		executable, err := os.Executable()
		if err == nil {
			executable, err = filepath.Abs(executable)
		}
		if err != nil {
			return nil, err
		}
		launcher, err := exec.LookPath("bwrap")
		if err != nil {
			return nil, errors.New("bubblewrap is required for connector workers")
		}
		userns := "--disable-userns"
		if value, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil && strings.TrimSpace(string(value)) == "0" {
			// The CVM already forbids nested user namespaces. Verify that restriction;
			// --disable-userns would try to create a forbidden second namespace.
			userns = "--assert-userns-disabled"
		}
		cmd := exec.Command(launcher, "--unshare-all", "--unshare-user", "--die-with-parent", "--new-session", userns, "--cap-drop", "ALL", "--clearenv",
			"--ro-bind", root, "/", "--ro-bind", executable, "/worker",
			"--ro-bind", broker, workerBroker, "--proc", "/proc", "--dev", "/dev",
			"--size", "67108864", "--tmpfs", "/tmp", "--chdir", "/tmp",
			"--remount-ro", "/dev", "--remount-ro", "/",
			"--setenv", "HOME", "/tmp", "--setenv", "TMPDIR", "/tmp", "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
			"--setenv", "GOMEMLIMIT", "256MiB", "--setenv", "GOMAXPROCS", "2", "--", "/worker", "--"+serveWorkerFlag)
		cmd.Env = []string{}
		return cmd, nil
	}}
}

func uiDevProxy(address string) (http.Handler, error) {
	target, err := url.Parse(address)
	if err != nil || target.Scheme != "http" || target.Host == "" || target.User != nil ||
		(target.Path != "" && target.Path != "/") || target.RawQuery != "" || target.Fragment != "" ||
		(target.Hostname() != "localhost" && !net.ParseIP(target.Hostname()).IsLoopback()) {
		return nil, errors.New("-ui-dev-url must be a loopback HTTP origin, such as http://127.0.0.1:5173")
	}
	target.Path = ""
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "UI development server unavailable; start it with bun dev/run.ts", http.StatusBadGateway)
	}
	return proxy, nil
}
