package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	jsonpatch "github.com/evanphx/json-patch/v5"
	toml "github.com/pelletier/go-toml/v2"
	"github.com/pelletier/go-toml/v2/unstable/edit"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/facts"
)

const maxPolicyBytes = 2 << 20

// Source and the preset contents named by its hashes define the policy.
type policyDocument struct {
	Source    string                     `json:"source"`
	Bases     map[string]json.RawMessage `json:"bases"`
	Proposals []policyProposal           `json:"proposals,omitempty"`
}

func contentHash(source string) string {
	sum := sha256.Sum256([]byte(source))
	return hex.EncodeToString(sum[:])
}

func jsonObject(raw []byte) (map[string]any, error) {
	var v map[string]any
	if err := facts.DecodeNumbers(raw, &v); err != nil {
		return nil, err
	}
	if v == nil {
		return nil, errors.New("configuration must be an object")
	}
	return v, nil
}

func pointer(path []string) string {
	parts := make([]string, len(path))
	for i, part := range path {
		parts[i] = strings.ReplaceAll(strings.ReplaceAll(part, "~", "~0"), "/", "~1")
	}
	return "/" + strings.Join(parts, "/")
}

func mapValue(v map[string]any, path []string) (any, bool) {
	for i, key := range path {
		x, ok := v[key]
		if !ok {
			return nil, false
		}
		if i == len(path)-1 {
			return x, true
		}
		v, ok = x.(map[string]any)
		if !ok {
			return nil, false
		}
	}
	return v, true
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

type tomlChange struct {
	path   []string
	value  any
	delete bool
}

// editSource changes only the requested paths, preserving unrelated source text.
func editSource(source string, changes []tomlChange) (string, error) {
	doc, err := edit.Parse([]byte(source))
	if err != nil {
		return "", err
	}
	for _, change := range changes {
		if change.delete {
			doc.Delete(change.path)
			continue
		}
		if err := doc.Set(change.path, change.value); err != nil {
			doc.Delete(change.path)
			if err := doc.Set(change.path, change.value); err != nil {
				return "", err
			}
		}
	}
	if len(doc.Bytes()) > maxPolicyBytes {
		return "", errors.New("policy source is too large")
	}
	return doc.String(), nil
}

func clonePolicy(p *policyDocument) *policyDocument {
	copy := *p
	copy.Bases = maps.Clone(p.Bases)
	copy.Proposals = slices.Clone(p.Proposals)
	return &copy
}

// pinPresets captures definitions on the write path, after validation.
func pinPresets(cfg *config, p *policyDocument) error {
	shipped, err := presets()
	if err != nil {
		return err
	}
	for _, name := range slices.Sorted(maps.Keys(cfg.Monitor.Presets)) {
		hash := cfg.Monitor.Presets[name]
		base := shipped[name]
		if p.Bases[hash] == nil {
			p.Bases[hash] = base.source
		}
	}
	p.Source, err = editSource(p.Source, cfg.pins)
	return err
}

// policyPresets evaluates only captured preset contents. No environment lookup
// or new shipped version can change the meaning of an already-applied source.
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
		if shipped[name] != nil && owned[name] == nil && pins[name] == shipped[name].hash {
			continue
		}
		base := map[string]any{}
		if hash, pinned := pins[name]; pinned {
			raw := p.Bases[hash]
			if raw == nil && shipped[name] != nil && shipped[name].hash == hash {
				raw = shipped[name].source
			}
			if raw == nil {
				return nil, fmt.Errorf("preset %s has an unavailable content hash", name)
			}
			base, err = jsonObject(raw)
			if err != nil {
				return nil, err
			}
		}
		raw, err := json.Marshal(base)
		if err == nil && owned[name] != nil {
			var patch []byte
			patch, err = json.Marshal(owned[name])
			if err == nil {
				raw, err = jsonpatch.MergePatch(raw, patch)
			}
		}
		if err != nil {
			return nil, err
		}
		out[name], err = decodePreset(raw)
		if err != nil {
			return nil, fmt.Errorf("preset %s: %w", name, err)
		}
	}
	return out, nil
}

// compileSource decodes configuration and binds credentials by name.
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
	v := decoded.(map[string]any)
	cfg := &config{Lattices: latticeOptions{Confidentiality: true}}
	cfg.Monitor.Version = 1
	raw, err := json.Marshal(v)
	if err == nil {
		err = facts.DecodeNumbers(raw, cfg)
	}
	if err != nil {
		return nil, nil, err
	}
	if cfg.Monitor.Version != 1 {
		return nil, nil, errors.New("unsupported policy format version")
	}
	resolved, err := policyPresets(cfg, p)
	if err != nil {
		return nil, nil, err
	}
	cfg, connections, err := cfg.compile(resolved)
	if err != nil {
		return nil, nil, err
	}
	for _, c := range connections {
		for name, value := range c.Secrets {
			if value != nil && value.Raw() != nil {
				return nil, nil, errors.New("set credentials through account settings")
			}
			if value == nil {
				c.Secrets[name] = new(credential.Value)
			}
		}
	}
	for id, secret := range secrets.all() {
		c := connections[connectionName(id[0], id[1])]
		if c == nil || c.account != id[0] || c.key != id[1] || c.Secrets == nil {
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

func isCredentialPath(path []string) bool {
	return len(path) == 7 && path[0] == "accounts" && path[2] == "connections" && path[5] == "secrets"
}
func credentialID(path []string) secretID { return secretID{path[1], path[3], path[6]} }
