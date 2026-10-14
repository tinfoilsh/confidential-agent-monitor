package main

import (
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	jsonpatch "github.com/evanphx/json-patch/v5"
	toml "github.com/pelletier/go-toml/v2"
	"github.com/pelletier/go-toml/v2/unstable/edit"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/connector/mcp"
	"github.com/tinfoilsh/monitor/connector/web"
	"github.com/tinfoilsh/monitor/facts"
)

const maxPolicyBytes = 2 << 20

var levels = []string{"off", "read", "ask", "allow"}

type identity struct {
	Routes   bool              `json:"routes,omitempty"`
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
	Requirements []requirement  `json:"requirements"`
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
	Lattices      latticeOptions      `json:"lattices"`
	AllowNetworks []netip.Prefix      `json:"allow_networks"`
	Accounts      map[string]account  `json:"accounts"`
	Identities    map[string]identity `json:"identities"`
	Policies      map[string]string   `json:"policies"`
	Data          map[string]any      `json:"data"`

	// Presets contains the source overrides; resolved holds the compiled definitions.
	Presets  map[string]map[string]any `json:"presets,omitempty"`
	resolved map[string]*presetRecord
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

// sourceChange replaces or deletes one source value. Tables and rules retain
// their names; edits never reconstruct source from a derived configuration.
type sourceChange struct {
	Path   []string `json:"path"`
	Value  any      `json:"value,omitempty"`
	Delete bool     `json:"delete,omitempty"`
}

// TOML has no null and cannot represent every JSON number exactly. A tagged JSON
// literal preserves those values. An object containing the reserved tag is itself
// escaped, so arbitrary request scopes and MCP schemas round-trip without loss.
func tomlValue(v any) (any, error) {
	switch x := v.(type) {
	case nil:
		return map[string]any{"$json": "null"}, nil
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return n, nil
		}
		return map[string]any{"$json": x.String()}, nil
	case map[string]any:
		if _, reserved := x["$json"]; reserved {
			raw, err := json.Marshal(x)
			return map[string]any{"$json": string(raw)}, err
		}
		out := map[string]any{}
		for k, val := range x {
			var err error
			if out[k], err = tomlValue(val); err != nil {
				return nil, err
			}
		}
		return out, nil
	case []any:
		out := make([]any, len(x))
		for i, val := range x {
			var err error
			if out[i], err = tomlValue(val); err != nil {
				return nil, err
			}
		}
		return out, nil
	default:
		return v, nil
	}
}

func renderTOML(v map[string]any) (string, error) {
	encoded, err := tomlValue(v)
	if err != nil {
		return "", err
	}
	text, err := toml.Marshal(encoded)
	return string(text), err
}

// editSource changes only the requested paths, preserving unrelated source text.
func editSource(source string, changes []sourceChange) (string, error) {
	doc, err := edit.Parse([]byte(source))
	if err != nil {
		return "", err
	}
	for _, change := range changes {
		if change.Delete {
			doc.Delete(change.Path)
			continue
		}
		if err := doc.Set(change.Path, change.Value); err != nil {
			doc.Delete(change.Path)
			if err := doc.Set(change.Path, change.Value); err != nil {
				return "", err
			}
		}
	}
	if len(doc.Bytes()) > maxPolicyBytes {
		return "", errors.New("policy source is too large")
	}
	return doc.String(), nil
}

// compileSource decodes configuration, binds credentials by name and drops orphaned ones.
// Only runtime handles receive secret values.
func compileSource(policy string, secrets secretStore) (*config, map[string]*connection, error) {
	source, err := readSource(policy)
	if err != nil {
		return nil, nil, err
	}
	decoded, err := jsonValue(source)
	if err != nil {
		return nil, nil, err
	}
	cfg := &config{Lattices: latticeOptions{Confidentiality: true}}
	raw, err := json.Marshal(decoded)
	if err == nil {
		err = facts.DecodeNumbers(raw, cfg)
	}
	if err != nil {
		return nil, nil, err
	}
	shipped, err := presets()
	if err != nil {
		return nil, nil, err
	}
	cfg.resolved = maps.Clone(shipped)
	for name, override := range cfg.Presets {
		raw := json.RawMessage(`{}`)
		if shipped[name] != nil {
			raw = shipped[name].source
		}
		patch, err := json.Marshal(override)
		if err == nil {
			raw, err = jsonpatch.MergePatch(raw, patch)
		}
		if err == nil {
			cfg.resolved[name], err = decodePreset(raw)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("preset %s: %w", name, err)
		}
	}
	connections := map[string]*connection{}
	for acct, a := range cfg.Accounts {
		if _, ok := cfg.resolved[a.Preset]; !ok {
			return nil, nil, fmt.Errorf("account %s has unknown preset %s", acct, a.Preset)
		}
		base, _ := json.Marshal(presetCatalog{Connections: cfg.resolved[a.Preset].Catalog.Connections})
		patch, _ := json.Marshal(a)
		raw, err := jsonpatch.MergePatch(base, patch)
		a = account{}
		if err == nil {
			err = facts.DecodeNumbers(raw, &a)
		}
		if err != nil {
			return nil, nil, fmt.Errorf("account %s: %w", acct, err)
		}
		cfg.Accounts[acct] = a
		if !slices.Contains(facts.Audiences, a.Contents) || !slices.Contains(facts.Audiences, a.Sends) {
			return nil, nil, fmt.Errorf("account %s: contents and sends must be one of %v", acct, facts.Audiences)
		}
		for key, kinds := range a.Connections {
			name := connectionName(acct, key)
			if name+".monitor" == agentHost {
				return nil, nil, fmt.Errorf("connection name %s is reserved for the monitor", name)
			}
			if connections[name] != nil {
				return nil, nil, fmt.Errorf("connection name %s is taken", name)
			}
			if len(kinds) != 1 {
				return nil, nil, fmt.Errorf("connection %s must have one kind", name)
			}
			for kind, spec := range kinds {
				newConnector, ok := connectorKinds[kind]
				if !ok {
					return nil, nil, fmt.Errorf("connection %s has unknown kind %s", name, kind)
				}
				raw, _ := json.Marshal(spec)
				instance := newConnector.NewConfig()
				if err := facts.DecodeNumbers(raw, instance); err != nil {
					return nil, nil, fmt.Errorf("connection %s: %w", name, err)
				}
				c := &connection{name: name, protocol: kind, account: acct, key: key, config: raw, connector: instance}
				if credentials, ok := instance.(interface {
					SecretValues() map[string]*credential.Value
				}); ok {
					c.Secrets = credentials.SecretValues()
					names := slices.Collect(maps.Keys(c.Secrets))
					for _, raw := range cfg.resolved[a.Preset].Catalog.Fields {
						var field struct {
							Path  []string   `json:"path"`
							Paths [][]string `json:"paths"`
						}
						if json.Unmarshal(raw, &field) != nil {
							continue
						}
						for _, path := range append(field.Paths, field.Path) {
							if len(path) == 5 && slices.Equal(path[:4], []string{"connections", key, kind, "secrets"}) {
								names = append(names, path[4])
							}
						}
					}
					for _, name := range names {
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
	p := presetRecord{source: raw}
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

// draftFiles holds unreviewed presets a dev monitor loads from disk with -drafts; they are never embedded and never replace a shipped preset.
var draftFiles fs.FS

var presets = sync.OnceValues(func() (map[string]*presetRecord, error) {
	shipped, _ := fs.Sub(presetFiles, "presets")
	out := map[string]*presetRecord{}
	for _, fsys := range []fs.FS{shipped, draftFiles} {
		if fsys == nil {
			continue
		}
		files, _ := fs.Glob(fsys, "*.json")
		for _, file := range files {
			name := strings.TrimSuffix(file, ".json")
			if out[name] != nil {
				continue
			}
			src, err := fs.ReadFile(fsys, file)
			if err == nil {
				out[name], err = decodePreset(src)
			}
			if err != nil {
				return nil, fmt.Errorf("preset %s: %w", file, err)
			}
		}
	}
	return out, nil
})
