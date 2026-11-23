package migrate

import (
	"encoding/json"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/tinfoilsh/confidential-agent-monitor/core/tomledit"
)

const (
	version2        = 2
	version3        = 3
	ownerPackage    = "sentinel"
	ownerPolicy     = "network-default"
	denyUnknown     = "package sentinel\n\ndeny contains \"This request has no recognized policy operation.\" if input.facts.operation == null\n"
	allowKnown      = "package sentinel\n\nallow if input.facts.operation != null\n\nallow if input.facts.kind == \"admission\"\n"
	allowEverything = "package sentinel\n\nallow := true\n"
)

// Before version 3 a request passed unless owner policy denied it. A policy that may be the owner's is left alone
// unless it is the rule onboarding wrote, so one that only denies now refuses everything until the owner rewrites it.
func upgradeV2(plain []byte) ([]byte, error) {
	var v2 struct {
		Version int    `json:"version"`
		Policy  string `json:"policy"`
	}
	if err := json.Unmarshal(plain, &v2); err != nil {
		return nil, err
	}
	if v2.Version >= version3 {
		return plain, nil
	}
	if v2.Version < version2 {
		return nil, fmt.Errorf("version %d is no longer supported", v2.Version)
	}
	source, err := tomledit.Read(v2.Policy)
	if err != nil {
		return nil, err
	}
	policies, _ := source["policies"].(map[string]any)
	data, _ := source["data"].(map[string]any)
	owned := data[ownerPackage] != nil
	var changes []tomledit.Change
	for _, name := range slices.Sorted(maps.Keys(policies)) {
		text, _ := policies[name].(string)
		owned = owned || strings.Contains(text, ownerPackage)
		if text == denyUnknown {
			changes = append(changes, tomledit.Change{Path: []string{"policies", name}, Value: allowKnown})
		}
	}
	if !owned {
		name := ownerPolicy
		for i := 2; policies[name] != nil; i++ {
			name = fmt.Sprintf("%s-%d", ownerPolicy, i)
		}
		changes = append(changes, tomledit.Change{Path: []string{"policies", name}, Value: allowEverything})
	}
	if len(changes) != 0 {
		if v2.Policy, err = tomledit.Edit(v2.Policy, changes); err != nil {
			return nil, err
		}
	}
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(plain, &doc); err != nil {
		return nil, err
	}
	doc["version"], _ = json.Marshal(version3)
	doc["policy"], _ = json.Marshal(v2.Policy)
	return json.Marshal(doc)
}
