package main

import (
	"embed"
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
	"reflect"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/mcp"
	"github.com/tinfoilsh/monitor/connector/web"
	"github.com/tinfoilsh/monitor/facts"
)

const mcpNameChars = "abcdefghijklmnopqrstuvwxyz0123456789-"

var levels = []string{"off", "read", "ask", "allow"}

type identity struct {
	Key      string            `json:"key"`
	Accounts map[string]access `json:"accounts"`
	Rules    []rule            `json:"rules,omitempty"`
	Messages *messageAccess    `json:"messages,omitempty"`
	// Profile admits every request unchanged and unlabeled, recording it, to learn what a client sends.
	Profile bool `json:"profile,omitempty"`
}

type access struct {
	Level   string            `json:"level"`
	Actions map[string]string `json:"actions,omitempty"`
}

// A rule waives gaps for one matched operation under the definition the owner approved.
type rule struct {
	Account    string         `json:"account"`
	Action     string         `json:"action"`
	Operation  string         `json:"operation,omitempty"`
	Definition string         `json:"definition,omitempty"`
	Scope      map[string]any `json:"scope"`
	Waives     []string       `json:"waives"`
}

// policyOptions contains settings used only by policy, never connection setup.
type policyOptions struct {
	Private  []string `json:"private,omitempty"`
	Address  string   `json:"address,omitempty"`
	Origin   string   `json:"origin,omitempty"`
	compiled *compiledOptions
}

type account struct {
	Preset        string                    `json:"preset"`
	PolicyOptions policyOptions             `json:"policy_options"`
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

	// Presets are the owner's, in the shipped file format; each replaces the shipped preset of its name.
	Presets  map[string]map[string]any `json:"presets,omitempty"`
	resolved map[string]*presetRecord
}

// parse decodes the owner's config without starting anything.
func parse(raw []byte) (*config, map[string]*connection, error) {
	cfg := config{Lattices: latticeOptions{Confidentiality: true}}
	if err := connector.DecodeNumbers(raw, &cfg); err != nil {
		return nil, nil, err
	}
	for _, reserved := range []string{"definitions", "presets", "lattices"} {
		if _, ok := cfg.Data[reserved]; ok {
			return nil, nil, fmt.Errorf("data.%s is reserved for the monitor", reserved)
		}
	}
	resolved, err := withOwned(cfg.Presets)
	if err != nil {
		return nil, nil, err
	}
	cfg.resolved = resolved
	connections := map[string]*connection{}
	for acct, a := range cfg.Accounts {
		if _, ok := resolved[a.Preset]; !ok {
			return nil, nil, fmt.Errorf("account %s has unknown preset %s", acct, a.Preset)
		}
		if !slices.Contains(facts.Audiences, a.Contents) || !slices.Contains(facts.Audiences, a.Sends) {
			return nil, nil, fmt.Errorf("account %s: contents and sends must be one of %v", acct, facts.Audiences)
		}
		for key, kinds := range a.Connections {
			name := connectionName(acct, key)
			if name == "messages" || name == "mcp" || name == "agent" {
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
				if err := connector.Decode(raw, instance); err != nil {
					return nil, nil, fmt.Errorf("connection %s: %w", name, err)
				}
				connections[name] = &connection{name: name, protocol: kind, account: acct, key: key,
					config: raw, connector: instance}
				connections[name].publicConfig = redactedConnection(connections[name])
			}
		}
	}
	for name, id := range cfg.Identities {
		if err := validateMessageAccess(name, id.Messages, cfg.Identities); err != nil {
			return nil, nil, err
		}
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
	return &cfg, connections, nil
}

// migratePresets rewrites legacy account selectors before validation. It preserves
// connections and owner records; saved approvals expire with the policy digest.
func migratePresets(raw json.RawMessage) (json.RawMessage, bool, error) {
	var cfg map[string]any
	if err := connector.DecodeNumbers(raw, &cfg); err != nil {
		return nil, false, err
	}
	object := func(v any) map[string]any { m, _ := v.(map[string]any); return m }
	changed := false
	github := map[string]bool{}
	owned := object(cfg["presets"])
	for name, value := range object(cfg["accounts"]) {
		a := object(value)
		options := object(a["policy_options"])
		if template, ok := a["template"].(string); ok {
			preset := template
			if template == "api" {
				preset, _ = options["preset"].(string)
				if preset == "" {
					return nil, false, fmt.Errorf("account %s: legacy api account has no preset", name)
				}
			} else if options["preset"] != nil {
				return nil, false, fmt.Errorf("account %s: a legacy preset requires template api", name)
			}
			if current, exists := a["preset"]; exists && current != preset {
				return nil, false, fmt.Errorf("account %s: preset conflicts with legacy template", name)
			}
			a["preset"] = preset
			delete(a, "template")
			delete(options, "preset")
			changed = true
		}
		// An owner-defined github_api remains an independent, data-only preset.
		if a["preset"] == "github_api" && owned["github_api"] == nil {
			if owned["github"] != nil {
				return nil, false, fmt.Errorf("account %s: owner github preset conflicts with legacy github_api", name)
			}
			a["preset"] = "github"
			github[name], changed = true, true
		}
	}
	for _, value := range object(cfg["identities"]) {
		for name, value := range object(object(value)["accounts"]) {
			if !github[name] {
				continue
			}
			access := object(value)
			actions := object(access["actions"])
			next := maps.Clone(actions)
			for _, old := range []string{"write", "write.issues", "write.pulls", "write.contents", "admin", "admin.merge"} {
				delete(next, old)
			}
			for old, replacements := range map[string][]string{
				"write.issues": {"open.issues", "comment"}, "write.pulls": {"open.pulls"},
				"write.contents": {"push"}, "admin.merge": {"merge"},
			} {
				mode, ok := actions[old]
				if !ok {
					mode, ok = actions[strings.Split(old, ".")[0]]
				}
				if !ok {
					continue
				}
				for _, action := range replacements {
					if current, exists := next[action]; exists && !reflect.DeepEqual(current, mode) {
						return nil, false, fmt.Errorf("account %s: conflicting permissions for %s", name, action)
					}
					next[action] = mode
				}
			}
			if actions != nil {
				access["actions"] = next
			}
		}
	}
	if !changed {
		return raw, false, nil
	}
	raw, err := json.Marshal(cfg)
	return raw, true, err
}

// A presetRecord contains reviewed protocol definitions and account setup metadata.
type presetRecord struct {
	Title       string         `json:"title"`
	Catalog     *presetCatalog `json:"catalog"`
	HTTP        *web.Preset    `json:"http,omitempty"`
	MCP         *mcp.Preset    `json:"mcp,omitempty"`
	PublicScope []string       `json:"public_scope,omitempty"`
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
	var p presetRecord
	if err := connector.DecodeNumbers(raw, &p); err != nil {
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
		if err := p.HTTP.Validate(); err != nil {
			return nil, err
		}
	}
	if p.MCP != nil {
		if err := p.MCP.Validate(); err != nil {
			return nil, err
		}
	}
	return &p, nil
}
func (r *presetRecord) EffectsFor(action string) []string {
	for action != "" && r.Catalog != nil {
		if effects := r.Catalog.Actions[action].Effects; effects != nil {
			return slices.Clone(effects)
		}
		i := strings.LastIndexByte(action, '.')
		if i < 0 {
			break
		}
		action = action[:i]
	}
	return nil
}

//go:embed presets/*.json
var presetFiles embed.FS

// A preset reads {MONITOR_X} only if MONITOR_X_PRESETS lists its name.
var envRef = regexp.MustCompile(`\{(MONITOR_\w+)\}`)

// draftFiles holds unreviewed presets a dev monitor loads from disk with -drafts; they are never embedded.
var draftFiles fs.FS

var presets = sync.OnceValues(func() (map[string]*presetRecord, error) {
	files, _ := fs.Glob(presetFiles, "presets/*.json")
	shipped := map[string]map[string]any{}
	for _, file := range files {
		name, p, err := presetFile(presetFiles, file)
		if err != nil {
			return nil, err
		}
		shipped[name] = p
	}
	out, err := checked(map[string]*presetRecord{}, shipped)
	if err != nil || draftFiles == nil {
		return out, err
	}
	// Each draft is checked alone, so a malformed one is skipped rather than stopping the monitor.
	drafts, _ := fs.Glob(draftFiles, "*.json")
	for _, file := range drafts {
		name, p, err := presetFile(draftFiles, file)
		if _, ok := out[name]; ok && err == nil {
			err = errors.New("a shipped preset has this name")
		}
		if err == nil {
			var next map[string]*presetRecord
			if next, err = checked(maps.Clone(out), map[string]map[string]any{name: p}); err == nil {
				out = next
				continue
			}
		}
		log.Printf("draft %s: %v", file, err)
	}
	return out, nil
})

func presetFile(fsys fs.FS, file string) (string, map[string]any, error) {
	name := strings.TrimSuffix(path.Base(file), ".json")
	src, err := fs.ReadFile(fsys, file)
	if err != nil {
		return "", nil, err
	}
	src = withEnv(name, src)
	// encoding/json keeps the last of repeated names, which could silently drop a condition.
	if !jsontext.Value(src).IsValid() {
		return "", nil, fmt.Errorf("%s is not valid JSON or repeats a name", file)
	}
	var p map[string]any
	if err := connector.DecodeNumbers(src, &p); err != nil {
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

// withOwned returns the shipped presets with the owner's in place of any of the same name.
// An owner's preset reads the environment as a shipped one of its name would.
func withOwned(owned map[string]map[string]any) (map[string]*presetRecord, error) {
	shipped, err := presets()
	if err != nil || len(owned) == 0 {
		return shipped, err
	}
	files := map[string]map[string]any{}
	for name, file := range owned {
		raw, _ := json.Marshal(file)
		var p map[string]any
		if err := connector.DecodeNumbers(withEnv(name, raw), &p); err != nil {
			return nil, fmt.Errorf("preset %s: %w", name, err)
		}
		files[name] = p
	}
	return checked(maps.Clone(shipped), files)
}

// checked validates the data used to build facts. Policy compilation is separate.
func checked(out map[string]*presetRecord, files map[string]map[string]any) (map[string]*presetRecord, error) {
	for name, file := range files {
		if name == "" {
			return nil, fmt.Errorf("preset needs a name")
		}
		raw, err := json.Marshal(file)
		if err != nil {
			return nil, err
		}
		record, err := decodePreset(raw)
		if err != nil {
			return nil, fmt.Errorf("preset %s: %w", name, err)
		}
		out[name] = record
	}
	return out, nil
}

type catalogEntry struct {
	*presetCatalog
	Title      string                       `json:"title"`
	Operations *[]web.Operation             `json:"operations,omitempty"`
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
