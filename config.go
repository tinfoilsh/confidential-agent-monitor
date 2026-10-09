package main

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"maps"
	"net/netip"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/gobwas/glob"
	toml "github.com/pelletier/go-toml/v2"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/connector/mcp"
	"github.com/tinfoilsh/monitor/connector/web"
	"github.com/tinfoilsh/monitor/facts"
)

const (
	mcpNameChars   = "abcdefghijklmnopqrstuvwxyz0123456789-"
	maxPolicyBytes = 2 << 20
)

var levels = []string{"off", "read", "ask", "allow"}

type identity struct {
	Key      string            `json:"key"`
	Accounts map[string]access `json:"accounts"`
	Rules    map[string]rule   `json:"rules,omitempty"`
	// Profile admits every request unchanged and unlabeled, recording it, to learn what a client sends.
	Profile bool `json:"profile,omitempty"`
}

type access struct {
	Level   string            `json:"level"`
	Actions map[string]string `json:"actions,omitempty"`
}

// A rule waives requirements for one operation under the definition the owner approved.
type rule struct {
	Enabled      *bool          `json:"enabled,omitempty"`
	Account      string         `json:"account"`
	Action       string         `json:"action"`
	Operation    string         `json:"operation,omitempty"`
	Definition   string         `json:"definition,omitempty"`
	Scope        map[string]any `json:"scope"`
	Requirements requirements   `json:"requirements"`
}

type account struct {
	Preset        string                    `json:"preset"`
	PolicyOptions connector.PolicyOptions   `json:"policy_options"`
	Contents      string                    `json:"contents"`
	Strangers     bool                      `json:"strangers"`
	Sends         string                    `json:"sends"`
	Connections   map[string]map[string]any `json:"connections,omitempty"`
}

// Lattice switches control enforcement. Labels keep recording both axes.
type latticeOptions struct {
	Confidentiality bool `json:"confidentiality"`
	Integrity       bool `json:"integrity"`
}

type config struct {
	Monitor struct {
		Version int               `json:"version"`
		Presets map[string]string `json:"presets,omitempty"`
	} `json:"monitor"`
	Lattices      latticeOptions      `json:"lattices"`
	AllowNetworks []netip.Prefix      `json:"allow_networks"`
	Accounts      map[string]account  `json:"accounts"`
	Identities    map[string]identity `json:"identities"`
	Policies      map[string]string   `json:"policies"`
	Data          map[string]any      `json:"data"`

	// Presets contains the source overrides; resolved holds the compiled definitions.
	Presets  map[string]map[string]any `json:"presets,omitempty"`
	resolved map[string]*presetRecord
	pins     []tomlChange
}

func readSource(source string) (map[string]any, error) {
	if len(source) > maxPolicyBytes {
		return nil, errors.New("policy source is too large")
	}
	var v map[string]any
	if err := toml.Unmarshal([]byte(source), &v); err != nil {
		return nil, fmt.Errorf("policy TOML: %w", err)
	}
	if v == nil {
		v = map[string]any{}
	}
	return v, nil
}

func jsonValue(v any) (any, error) {
	switch x := v.(type) {
	case map[string]any:
		if literal, ok := x["$json"]; ok {
			s, ok := literal.(string)
			if !ok || len(x) != 1 {
				return nil, errors.New("$json must be the only field of a JSON literal")
			}
			var val any
			err := facts.DecodeNumbers([]byte(s), &val)
			return val, err
		}
		out := map[string]any{}
		for k, val := range x {
			var err error
			if out[k], err = jsonValue(val); err != nil {
				return nil, err
			}
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			var err error
			if out[i], err = jsonValue(val); err != nil {
				return nil, err
			}
		}
		return out, nil
	case time.Time, toml.LocalDate, toml.LocalTime, toml.LocalDateTime:
		return nil, errors.New("policy dates and times must be quoted strings")
	default:
		return v, nil
	}
}

// policyPresets evaluates only captured preset contents. No environment lookup
// or new shipped version can change the meaning of an already-applied source.
// It captures pinned shipped definitions in p.Bases and records new pins in cfg.pins.
func policyPresets(cfg *config, p *policyDocument) (map[string]*presetRecord, error) {
	shipped, err := presets()
	if err != nil {
		return nil, err
	}
	out := maps.Clone(shipped)
	pins, owned := cfg.Monitor.Presets, cfg.Presets
	if pins == nil {
		pins = map[string]string{}
		cfg.Monitor.Presets = pins
	}
	names := map[string]bool{}
	for _, a := range cfg.Accounts {
		names[a.Preset] = true
	}
	for name := range pins {
		names[name] = true
	}
	for name := range owned {
		names[name] = true
	}
	for _, name := range slices.Sorted(maps.Keys(names)) {
		if _, pinned := pins[name]; !pinned && shipped[name] != nil {
			pins[name] = shipped[name].hash
			cfg.pins = append(cfg.pins, tomlChange{path: []string{"monitor", "presets", name}, value: pins[name]})
		}
		raw := json.RawMessage(`{}`)
		if hash, pinned := pins[name]; pinned {
			if p.Bases[hash] == nil && shipped[name] != nil && shipped[name].hash == hash {
				p.Bases[hash] = shipped[name].source
			}
			if raw = p.Bases[hash]; raw == nil {
				return nil, fmt.Errorf("preset %s has an unavailable content hash", name)
			}
		}
		if shipped[name] != nil && owned[name] == nil && pins[name] == shipped[name].hash {
			continue
		}
		if owned[name] != nil {
			patch, err := json.Marshal(owned[name])
			if err == nil {
				raw, err = jsonpatch.MergePatch(raw, patch)
			}
			if err != nil {
				return nil, err
			}
		}
		if out[name], err = decodePreset(raw); err != nil {
			return nil, fmt.Errorf("preset %s: %w", name, err)
		}
	}
	return out, nil
}

// compileSource decodes configuration, binds credentials by name and drops orphaned ones.
// Only runtime handles receive secret values.
func compileSource(p *policyDocument, secrets secretStore) (*config, map[string]*connection, error) {
	source, err := readSource(p.Source)
	if err != nil {
		return nil, nil, err
	}
	decoded, err := jsonValue(source)
	if err != nil {
		return nil, nil, err
	}
	cfg := &config{Lattices: latticeOptions{Confidentiality: true}}
	cfg.Monitor.Version = 1
	raw, err := json.Marshal(decoded)
	if err == nil {
		err = facts.DecodeNumbers(raw, cfg)
	}
	if err != nil {
		return nil, nil, err
	}
	if cfg.Monitor.Version != 1 {
		return nil, nil, errors.New("unsupported policy format version")
	}
	if cfg.resolved, err = policyPresets(cfg, p); err != nil {
		return nil, nil, err
	}
	connections := map[string]*connection{}
	for acct, a := range cfg.Accounts {
		for _, pattern := range a.PolicyOptions.Private {
			if _, err := glob.Compile(pattern, '/'); err != nil {
				return nil, nil, fmt.Errorf("account %s: invalid private pattern %q: %w", acct, pattern, err)
			}
		}
		if _, ok := cfg.resolved[a.Preset]; !ok {
			return nil, nil, fmt.Errorf("account %s has unknown preset %s", acct, a.Preset)
		}
		if !slices.Contains(facts.Audiences, a.Contents) || !slices.Contains(facts.Audiences, a.Sends) {
			return nil, nil, fmt.Errorf("account %s: contents and sends must be one of %v", acct, facts.Audiences)
		}
		for key, kinds := range a.Connections {
			name := connectionName(acct, key)
			if name+".monitor" == agentHost || name+".monitor" == mcpHost {
				return nil, nil, fmt.Errorf("connection name %s is reserved for the monitor", name)
			}
			if connections[name] != nil {
				return nil, nil, fmt.Errorf("connection name %s is taken", name)
			}
			if len(kinds) != 1 {
				return nil, nil, fmt.Errorf("connection %s must have one kind", name)
			}
			for kind, spec := range kinds {
				// The gateway names tools name__tool, so the first separator must end the connection name.
				if kind == "mcp" && strings.Trim(strings.ToLower(name), mcpNameChars) != "" {
					return nil, nil, fmt.Errorf("MCP connection name %s may use only letters, digits and -", name)
				}
				newConnector, ok := connectorKinds[kind]
				if !ok {
					return nil, nil, fmt.Errorf("connection %s has unknown kind %s", name, kind)
				}
				raw, _ := json.Marshal(spec)
				instance := newConnector()
				if err := facts.DecodeNumbers(raw, instance); err != nil {
					return nil, nil, fmt.Errorf("connection %s: %w", name, err)
				}
				c := &connection{name: name, protocol: kind, account: acct, key: key, config: raw, connector: instance}
				if credentials, ok := instance.(interface {
					SecretValues() map[string]*credential.Value
				}); ok {
					c.Secrets = credentials.SecretValues()
					names := catalogSecrets(cfg.resolved[a.Preset], key, kind)
					if len(names) == 0 {
						// Custom connections inherit unset editors from catalogs for their protocol.
						for _, preset := range cfg.resolved {
							names = append(names, catalogSecrets(preset, "*", kind)...)
						}
					}
					for _, name := range append(names, slices.Collect(maps.Keys(c.Secrets))...) {
						if c.Secrets[name] == nil {
							c.Secrets[name] = new(credential.Value)
						} else if c.Secrets[name].Raw() != nil {
							return nil, nil, errors.New("set credentials through account settings")
						}
					}
				}
				connections[name] = c
			}
		}
	}
	for name, id := range cfg.Identities {
		for acct, a := range id.Accounts {
			if _, ok := cfg.Accounts[acct]; !ok || !slices.Contains(levels, a.Level) {
				return nil, nil, fmt.Errorf("identity %s: account %s must exist and have a level in %v", name, acct, levels)
			}
			for action, level := range a.Actions {
				if level == "read" || !slices.Contains(levels, level) {
					return nil, nil, fmt.Errorf("identity %s: action %s must be off, ask or allow", name, action)
				}
			}
		}
	}
	for id, secret := range secrets.all() {
		c := connections[connectionName(id[0], id[1])]
		if c == nil || c.account != id[0] || c.key != id[1] || c.Secrets == nil {
			secrets.set(id, nil)
			continue
		}
		value := new(credential.Value)
		if err := value.UnmarshalJSON(secret); err != nil {
			return nil, nil, fmt.Errorf("credential %v: %w", id, err)
		}
		c.Secrets[id[2]] = value
	}
	return cfg, connections, nil
}

// A presetRecord contains reviewed protocol definitions and account setup metadata.
type presetRecord struct {
	Title       string         `json:"title"`
	Catalog     *presetCatalog `json:"catalog"`
	HTTP        *web.Preset    `json:"http,omitempty"`
	MCP         *mcp.Preset    `json:"mcp,omitempty"`
	PublicScope []string       `json:"public_scope,omitempty"`
	source      json.RawMessage
	hash        string
	http        *web.CompiledPreset
	mcp         *mcp.CompiledPreset
}
type presetCatalog struct {
	Group       string                     `json:"group,omitempty"`
	Actions     map[string]presetAction    `json:"actions,omitempty"`
	Connections map[string]json.RawMessage `json:"connections,omitempty"`
	Defaults    json.RawMessage            `json:"defaults,omitempty"`
	Fields      []json.RawMessage          `json:"fields,omitempty"`
}

type presetAction struct {
	Title   string   `json:"title"`
	Effects []string `json:"effects,omitempty"`
}

func decodePreset(raw []byte) (*presetRecord, error) {
	sum := sha256.Sum256(raw)
	p := presetRecord{source: raw, hash: hex.EncodeToString(sum[:])}
	if err := facts.DecodeNumbers(raw, &p); err != nil {
		return nil, err
	}
	if p.Catalog == nil {
		return nil, fmt.Errorf("catalog must be an object")
	}
	for name, a := range p.Catalog.Actions {
		if a.Effects != nil && !facts.ValidEffects(a.Effects) {
			return nil, fmt.Errorf("invalid effects for action %s", name)
		}
	}
	if p.HTTP != nil {
		var err error
		if p.http, err = p.HTTP.Compile(); err != nil {
			return nil, err
		}
	}
	if p.MCP != nil {
		var err error
		if p.mcp, err = p.MCP.Compile(); err != nil {
			return nil, err
		}
	}
	return &p, nil
}
func actionLineage(action string) []string {
	var lineage []string
	for action != "" {
		lineage = append(lineage, action)
		i := strings.LastIndexByte(action, '.')
		if i < 0 {
			break
		}
		action = action[:i]
	}
	return lineage
}

//go:embed presets/*.json
var presetFiles embed.FS

// A preset reads {MONITOR_X} only if MONITOR_X_PRESETS lists its name.
var envRef = regexp.MustCompile(`\{(MONITOR_\w+)\}`)

// draftFiles holds unreviewed presets a dev monitor loads from disk with -drafts; they are never embedded.
var draftFiles fs.FS

var presets = sync.OnceValues(func() (map[string]*presetRecord, error) {
	files, _ := fs.Glob(presetFiles, "presets/*.json")
	out := map[string]*presetRecord{}
	for _, file := range files {
		name, p, err := presetFile(presetFiles, file)
		if err != nil {
			return nil, err
		}
		out[name] = p
	}
	if draftFiles == nil {
		return out, nil
	}
	// Each draft is checked alone, so a malformed one is skipped rather than stopping the monitor.
	drafts, _ := fs.Glob(draftFiles, "*.json")
	for _, file := range drafts {
		name, p, err := presetFile(draftFiles, file)
		if _, ok := out[name]; ok && err == nil {
			err = errors.New("a shipped preset has this name")
		}
		if err == nil {
			out[name] = p
			continue
		}
		log.Printf("draft %s: %v", file, err)
	}
	return out, nil
})

func presetFile(fsys fs.FS, file string) (string, *presetRecord, error) {
	name := strings.TrimSuffix(path.Base(file), ".json")
	src, err := fs.ReadFile(fsys, file)
	if err != nil {
		return "", nil, err
	}
	src = withEnv(name, src)
	p, err := decodePreset(src)
	if err != nil {
		return "", nil, fmt.Errorf("%s: %w", file, err)
	}
	return name, p, nil
}

func withEnv(name string, src []byte) []byte {
	return envRef.ReplaceAllFunc(src, func(ref []byte) []byte {
		key := string(ref[1 : len(ref)-1])
		if !slices.Contains(strings.Split(os.Getenv(key+"_PRESETS"), ","), name) {
			return nil
		}
		quoted, _ := jsontext.AppendQuote(nil, os.Getenv(key))
		return quoted[1 : len(quoted)-1]
	})
}

type catalogEntry struct {
	*presetCatalog
	Title      string                       `json:"title"`
	Operations *map[string]web.Operation    `json:"operations,omitempty"`
	Vocabulary map[string]facts.Obligations `json:"vocabulary"`
}

// catalog exposes setup metadata and operations from the resolved records.
func catalog(all map[string]*presetRecord) map[string]catalogEntry {
	entries := map[string]catalogEntry{}
	for name, p := range all {
		entry := catalogEntry{presetCatalog: p.Catalog, Title: p.Title, Vocabulary: facts.Effects}
		if p.HTTP != nil {
			entry.Operations = &p.HTTP.Operations
		}
		entries[name] = entry
	}
	return entries
}

func catalogSecrets(p *presetRecord, key, kind string) (names []string) {
	for _, raw := range p.Catalog.Fields {
		var field struct {
			Path []string `json:"path"`
		}
		if json.Unmarshal(raw, &field) != nil {
			continue
		}
		path := field.Path
		if len(path) == 5 && path[0] == "connections" && (key == "*" || path[1] == key) && path[2] == kind && path[3] == "secrets" {
			names = append(names, path[4])
		}
	}
	return
}
