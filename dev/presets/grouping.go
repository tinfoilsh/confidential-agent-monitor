package main

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

var groupWord = regexp.MustCompile(`[^a-z0-9_]+`)
var groupPath = regexp.MustCompile(`^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]*)*$`)
var groupVersion = regexp.MustCompile(`^(v?[0-9]+([.][0-9]+)*[a-z]*|[0-9]{4}-[0-9]{2}-[0-9]{2})$`)

// These are exact words, not prefixes: settings, subscriptions and releases
// are resources even though their names start with verbs.
var groupVerbs = strings.Fields("get list read search query find create add update edit set put patch post delete remove cancel confirm approve reject archive unarchive close reopen merge lock unlock move copy rename restore enable disable send publish unpublish start stop restart retry resume pause abort run rerun execute trigger invoke dispatch deploy test verify validate check import export upload download accept transfer duplicate clone sync subscribe unsubscribe follow unfollow star unstar pin unpin mute unmute block unblock join leave invite share revoke grant reset regenerate rotate attach detach batch")

func groupName(s string) string {
	return strings.Trim(groupWord.ReplaceAllString(snake(s), "_"), "_")
}

func resourceWords(s string) string {
	parts := strings.Split(groupName(s), "_")
	for len(parts) > 1 && slices.Contains(groupVerbs, parts[0]) {
		parts = parts[1:]
	}
	for len(parts) > 1 && slices.Contains(groupVerbs, parts[len(parts)-1]) {
		parts = parts[:len(parts)-1]
	}
	return strings.Join(parts, "_")
}

// actionResource keeps the enclosing resources, so repo/org hooks and
// deployment/commit statuses cannot acquire the same permission by accident.
// RPC fields and source categories cover APIs without a resource-shaped URL.
func actionResource(o specOp) string {
	if o.Resource != "" {
		return o.Resource
	}
	if len(o.GraphQL) == 2 {
		return resourceWords(o.GraphQL[1])
	}
	var parts []string
	segments := strings.Split(strings.Trim(o.Path, "/"), "/")
	for i, raw := range segments {
		if raw == "" || strings.Contains(raw, "{") || groupVersion.MatchString(raw) || slices.Contains([]string{"api", "rest", "rpc", "graphql", "upload", "download"}, raw) {
			continue
		}
		raw = strings.TrimSuffix(strings.TrimSuffix(raw, ".json"), ".xml")
		raw, _, _ = strings.Cut(raw, ":")
		for _, segment := range strings.Split(raw, ".") {
			part := groupName(segment)
			if part == "" {
				continue
			}
			if i == len(segments)-1 {
				if slices.Contains(groupVerbs, part) && len(parts) > 0 {
					continue
				}
				part = resourceWords(part)
			}
			parts = append(parts, part)
		}
	}
	if len(parts) == 0 {
		for _, tag := range o.Tags {
			if name := groupName(tag); name != "" && !slices.Contains([]string{"query", "mutation", "do_not_render"}, name) {
				return name
			}
		}
		return "general"
	}
	return strings.Join(parts, ".")
}

func groupedAction(o specOp, verb string) string {
	return actionResource(o) + "." + verb
}

// Several APIs use the same parameterized route for unrelated resource types.
// Prefer the source operation's identity, then the first matching route. Use
// the same selection for shipped grouping and candidate generation.
func groupHints(ops []map[string]any, p parsed, provider string) map[string]specOp {
	hints := map[string]specOp{}
	for _, op := range ops {
		id := op["id"].(string)
		for _, raw := range p.Ops {
			o := normalizeProvider(provider, raw)
			if !sameRoute(operationSpec(op), o) {
				continue
			}
			if _, exists := hints[id]; !exists {
				hints[id] = o
			}
			if id == o.ID || id == o.SourceID || o.ID != "" && strings.HasPrefix(id, o.ID+"."+o.Body+".") {
				hints[id] = o
				break
			}
		}
	}
	return hints
}

func actionTitle(s string) string {
	if title := map[string]string{"repos": "Repositories", "orgs": "Organizations", "user": "Account", "gpg_keys": "GPG keys", "ssh_signing_keys": "SSH signing keys", "read": "Read", "write": "Create and edit", "admin": "Manage", "execute": "Run", "pay": "Make payments", "open": "Open and edit", "push": "Push commits", "merge": "Merge", "use": "Use tools"}[s]; title != "" {
		return title
	}
	s = strings.ReplaceAll(s, "_", " ")
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func addActionParents(actions map[string]any, action string) {
	parts := strings.Split(action, ".")
	for i, part := range parts {
		key := strings.Join(parts[:i+1], ".")
		if _, ok := actions[key]; !ok {
			actions[key] = map[string]any{"title": actionTitle(part)}
		}
	}
}

// groupRecord changes only action names and their catalog. Effects, request
// constraints and approval scopes remain on the individual operations.
func groupRecord(record map[string]any, hints map[string]specOp) int {
	catalog := record["catalog"].(map[string]any)
	oldActions, _ := catalog["actions"].(map[string]any)
	var ops []map[string]any
	switch values := record["operations"].(type) {
	case []map[string]any:
		ops = values
	case []any:
		for _, value := range values {
			ops = append(ops, value.(map[string]any))
		}
	}
	if len(ops) == 0 {
		return 0
	}
	// Actions supplied by a recognizer have effects in the catalog. Keep those
	// roots and their descendants, including GitHub's Git/GraphQL/MCP controls.
	actions := map[string]any{}
	for name, meta := range oldActions {
		for parent, value := range oldActions {
			m, _ := value.(map[string]any)
			if m["effects"] != nil && (name == parent || strings.HasPrefix(name, parent+".")) {
				actions[name] = meta
				break
			}
		}
	}
	changed := 0
	for _, op := range ops {
		id, old := op["id"].(string), op["action"].(string)
		o := operationSpec(op)
		if hint, ok := hints[id]; ok {
			o.Tags, o.Resource = hint.Tags, hint.Resource
		}
		var verb string
		switch effects := op["effects"].(type) {
		case []any:
			verb, _ = effects[0].(string)
		case []string:
			verb = effects[0]
		}
		// Reviewed GitHub actions distinguish pushing/merging/commenting even
		// though each has a write effect. Retain those meaningful verbs.
		parts := strings.Split(old, ".")
		verbs := append(slices.Clone(effectOrder), "session", "open", "comment", "merge", "push", "use")
		if strings.HasPrefix(old, actionResource(o)+".") && slices.Contains(verbs, parts[len(parts)-1]) {
			verb = parts[len(parts)-1]
		} else if slices.Contains(verbs, parts[0]) {
			verb = parts[0]
		} else if slices.Contains(verbs, parts[len(parts)-1]) {
			verb = parts[len(parts)-1]
		}
		next := groupedAction(o, verb)
		if next != old {
			op["action"] = next
			changed++
		} else if meta, ok := oldActions[next]; ok {
			actions[next] = meta
		}
		addActionParents(actions, next)
	}
	catalog["actions"] = actions
	record["operations"] = ops
	return changed
}

// groupShipped regroups only existing operations. It never promotes source
// additions or depends on a network refresh. Unavailable specs use the shipped
// route and field names; native/MCP presets retain their small action catalogs.
func groupShipped(only []string) error {
	sources, err := load[map[string]source](sourcesPath)
	if err != nil {
		return err
	}
	lock, err := load[lockFile](lockPath)
	if err != nil {
		return err
	}
	files, err := filepath.Glob(filepath.Join(shippedDir, "*.json"))
	if err != nil {
		return err
	}
	selected := map[string]bool{}
	for _, name := range only {
		if src, ok := sources[name]; ok && src.Preset != "" {
			for _, preset := range strings.Split(src.Preset, ",") {
				selected[preset] = true
			}
		} else {
			selected[name] = true
		}
	}
	for name := range selected {
		if !slices.Contains(files, filepath.Join(shippedDir, name+".json")) {
			return fmt.Errorf("unknown shipped preset %q", name)
		}
	}
	for _, file := range files {
		name := strings.TrimSuffix(filepath.Base(file), ".json")
		if len(only) > 0 && !selected[name] {
			continue
		}
		record, err := load[map[string]any](file)
		if err != nil {
			return err
		}
		ops, _ := record["operations"].([]any)
		if len(ops) == 0 {
			continue
		}
		hints := map[string]specOp{}
		for _, key := range sortedKeys(sources) {
			src := sources[key]
			if !slices.Contains(strings.Split(src.Preset, ","), name) || len(src.Specs) == 0 {
				continue
			}
			p, err := specOps(key, src, lock)
			if err != nil {
				if len(src.Groups) > 0 {
					return err
				}
				fmt.Printf("%s: using shipped routes for grouping: %v\n", name, err)
				continue
			}
			var records []map[string]any
			for _, value := range ops {
				records = append(records, value.(map[string]any))
			}
			for id, hint := range groupHints(records, p, key) {
				hints[id] = hint
			}
		}
		before, _ := json.Marshal(record)
		count := groupRecord(record, hints)
		after, _ := json.Marshal(record)
		if string(before) != string(after) {
			if err := writeJSON(file, record); err != nil {
				return err
			}
		}
		fmt.Printf("%s: grouped %d existing operations\n", name, count)
	}
	return nil
}
