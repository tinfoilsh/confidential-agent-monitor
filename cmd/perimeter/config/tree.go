package config

import (
	"cmp"
	"encoding/json"
	"maps"
	"slices"
	"strings"

	"github.com/tinfoilsh/confidential-agent-monitor/connector/catalog"
)

type ResolvedNode struct {
	Key     string   `json:"key"`
	Title   string   `json:"title"`
	Effects []string `json:"effects"`
	Setting
	Children []ResolvedNode `json:"children,omitempty"`
}

type pinnedTool struct {
	Name        string `json:"name"`
	Title       string `json:"title"`
	Annotations struct {
		ReadOnlyHint bool `json:"readOnlyHint"`
	} `json:"annotations"`
}

func (c *Config) pinned(connection string) []pinnedTool {
	var pinned struct {
		Pin struct {
			Tools []pinnedTool `json:"tools"`
		} `json:"pin"`
	}
	if spec, err := c.Spec(connection); err == nil {
		_ = json.Unmarshal(spec.Config, &pinned)
	}
	return pinned.Pin.Tools
}

// A pinned MCP tool sits under read or use by the hint the owner approved with the pin.
func (t pinnedTool) action() string {
	if t.Annotations.ReadOnlyHint {
		return "read." + t.Name
	}
	return "use." + t.Name
}

func (c *Config) titled(connection string) map[string]string {
	preset := c.Presets[c.Connections[connection].Preset]
	titles := map[string]string{}
	if preset == nil {
		return titles
	}
	for _, op := range c.Operations[c.Connections[connection].Preset] {
		titles[op.Action] = op.Action
	}
	for key, action := range preset.Catalog.Actions {
		titles[key] = action.Title
	}
	for _, tool := range c.pinned(connection) {
		titles[tool.action()] = cmp.Or(tool.Title, tool.Name)
	}
	return titles
}

func segmentTitle(segment string) string {
	return strings.ToUpper(segment[:min(1, len(segment))]) + strings.NewReplacer("_", " ", "-", " ").Replace(segment[min(1, len(segment)):])
}

func (c *Config) tree(connection string, t tiers) []ResolvedNode {
	preset := c.Presets[c.Connections[connection].Preset]
	if preset == nil {
		return nil
	}
	titles := c.titled(connection)
	effects := map[string]map[string]bool{}
	add := func(key string, list []string) {
		for _, a := range catalog.Lineage(key) {
			if effects[a] == nil {
				effects[a] = map[string]bool{}
			}
			for _, e := range list {
				effects[a][e] = true
			}
		}
	}
	for key := range titles {
		add(key, nil)
	}
	for _, op := range c.Operations[c.Connections[connection].Preset] {
		add(op.Action, op.Effects)
	}
	for _, key := range slices.Collect(maps.Keys(effects)) {
		if op := preset.Catalog.Resolve("", key, nil); op != nil {
			add(key, op.Effects)
		}
	}
	children := map[string][]string{}
	for key := range effects {
		parent := ""
		if i := strings.LastIndexByte(key, '.'); i >= 0 {
			parent = key[:i]
		}
		children[parent] = append(children[parent], key)
	}
	var build func(parent string) []ResolvedNode
	build = func(parent string) []ResolvedNode {
		var nodes []ResolvedNode
		for _, key := range slices.Sorted(slices.Values(children[parent])) {
			title, named := titles[key]
			if !named {
				title = segmentTitle(key[strings.LastIndexByte(key, '.')+1:])
			}
			n := ResolvedNode{Key: key, Title: cmp.Or(title, key), Effects: slices.Sorted(maps.Keys(effects[key])), Children: build(key)}
			n.Setting = strictest(t.modes(catalog.Lineage(key), n.Effects))
			nodes = append(nodes, n)
		}
		return nodes
	}
	return build("")
}
