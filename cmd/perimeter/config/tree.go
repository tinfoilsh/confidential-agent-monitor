package config

import (
	"cmp"
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

func (c *Config) titled(connection string) map[string]string {
	preset := c.Preset(connection)
	titles := map[string]string{}
	if preset == nil {
		return titles
	}
	for key, action := range preset.Catalog.Actions {
		titles[key] = action.Title
	}
	for _, o := range c.operations[connection] {
		titles[o.Operation.Action] = cmp.Or(o.Title, titles[o.Operation.Action], o.Operation.Action)
	}
	return titles
}

func segmentTitle(segment string) string {
	return strings.ToUpper(segment[:min(1, len(segment))]) + strings.NewReplacer("_", " ", "-", " ").Replace(segment[min(1, len(segment)):])
}

func (c *Config) tree(connection string, t tiers) []ResolvedNode {
	preset := c.Preset(connection)
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
	for _, o := range c.operations[connection] {
		add(o.Operation.Action, o.Operation.Effects)
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
