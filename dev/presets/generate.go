package main

import (
	"bytes"
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
)

const candidatesDir = "candidates"
const coverageDir = "coverage"

type inventoryOperation struct {
	ID            string         `json:"source_id"`
	Source        documentStamp  `json:"source"`
	Method        string         `json:"method,omitempty"`
	Origin        string         `json:"origin,omitempty"`
	Path          string         `json:"path,omitempty"`
	Body          string         `json:"body,omitempty"`
	Query         map[string]any `json:"query,omitempty"`
	Descriptors   []string       `json:"descriptors"`
	Status        string         `json:"status"`
	Reason        string         `json:"reason,omitempty"`
	MissingParams []string       `json:"missing_params,omitempty"`
}

type generationReport struct {
	Service         string               `json:"service"`
	Presets         []string             `json:"presets"`
	Sources         []lockEntry          `json:"sources"`
	Note            string               `json:"source_scope,omitempty"`
	Definition      source               `json:"source_definition"`
	Error           string               `json:"error,omitempty"`
	Warnings        []string             `json:"warnings,omitempty"`
	Operations      []inventoryOperation `json:"operations"`
	Conflicts       [][2]string          `json:"conflicts"`
	UnmappedShipped []string             `json:"unmapped_shipped"`
	Counts          map[string]int       `json:"counts"`
	CandidateSHA256 string               `json:"candidate_sha256,omitempty"`
	GeneratorSHA256 string               `json:"generator_sha256"`
	ShippedSHA256   string               `json:"shipped_sha256,omitempty"`
}

func generatorDigest() (string, error) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		return "", err
	}
	files = append(files, "go.mod", "go.sum")
	slices.Sort(files)
	h := sha256.New()
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		b, err := os.ReadFile(file)
		if err != nil {
			return "", err
		}
		h.Write([]byte(file + "\x00"))
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func shippedDigest(names []string) (string, error) {
	h := sha256.New()
	for _, name := range names {
		b, err := os.ReadFile(filepath.Join(shippedDir, name+".json"))
		if err != nil {
			return "", err
		}
		h.Write([]byte(name + "\x00"))
		h.Write(b)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func writeJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if filepath.Dir(path) == candidatesDir || filepath.Dir(path) == shippedDir {
		if record, ok := value.(map[string]any); ok && record["http"] != nil {
			header := maps.Clone(record)
			delete(header, "http")
			prefix, err := json.MarshalIndent(header, "", "  ")
			if err != nil {
				return err
			}
			var out bytes.Buffer
			out.Write(bytes.TrimSuffix(prefix, []byte("\n}")))
			out.WriteString(",\n  \"http\": {\n")
			spec := maps.Clone(httpSection(record))
			delete(spec, "operations")
			for _, key := range slices.Sorted(maps.Keys(spec)) {
				keyJSON, _ := json.Marshal(key)
				valueJSON, err := json.Marshal(spec[key])
				if err != nil {
					return err
				}
				fmt.Fprintf(&out, "    %s: %s,\n", keyJSON, valueJSON)
			}
			out.WriteString("    \"operations\": {\n")
			ops, _ := httpSection(record)["operations"].(map[string]any)
			for i, id := range sortedKeys(ops) {
				if i > 0 {
					out.WriteString(",\n")
				}
				key, _ := json.Marshal(id)
				operation := maps.Clone(ops[id].(map[string]any))
				delete(operation, "id")
				line, err := json.Marshal(operation)
				if err != nil {
					return err
				}
				fmt.Fprintf(&out, "      %s: %s", key, line)
			}
			out.WriteString("\n    }\n  }\n}")
			data = out.Bytes()
		}
	}
	if err = os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".generate-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(append(data, '\n')); err != nil {
		f.Close()
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}

func operationSpec(op map[string]any) specOp {
	str := func(key string) string { v, _ := op[key].(string); return v }
	o := specOp{ID: str("id"), Method: str("method"), Origin: str("origin"), Path: str("path"), Body: str("body")}
	if o.Body == "" {
		o.Body = "none"
	}
	o.Query, _ = op["query"].(map[string]any)
	if patterns, ok := op["path_patterns"].(map[string]any); ok {
		o.PathPatterns = map[string]string{}
		for name, pattern := range patterns {
			o.PathPatterns[name], _ = pattern.(string)
		}
	}
	if g, ok := op["graphql"].(map[string]any); ok {
		kind, _ := g["operation"].(string)
		field, _ := g["field"].(string)
		o.GraphQL = []string{kind, field}
		if fields, ok := g["fields"].([]any); ok {
			o.GraphQL = []string{kind}
			for _, f := range fields {
				name, _ := f.(string)
				o.GraphQL = append(o.GraphQL, name)
			}
		}
	}
	return o
}

// A descriptor accepting any body covers every body variant of its route; others never cover an uninspectable one.
func sameRoute(a, b specOp) bool {
	if a.Method != b.Method || a.Origin != b.Origin || a.Body != "any" && (a.Body != b.Body || b.Unsupported != "") {
		return false
	}
	if a.GraphQL != nil && b.GraphQL != nil {
		return graphqlOverlap(a.GraphQL, b.GraphQL)
	}
	return routeShape(a.Method, a.Path) == routeShape(b.Method, b.Path)
}

func sameEffects(a, b any) bool {
	x, _ := a.([]any)
	y, _ := b.([]any)
	x, y = slices.Clone(x), slices.Clone(y)
	byName := func(p, q any) int { return strings.Compare(p.(string), q.(string)) }
	slices.SortFunc(x, byName)
	slices.SortFunc(y, byName)
	return slices.Equal(x, y)
}

// acceptAnyBody drops the body conditions and selectors a descriptor cannot apply once it accepts any body.
func acceptAnyBody(op map[string]any) {
	op["body"] = "any"
	delete(op, "fields")
	delete(op, "present")
	scope := op["scope"].(map[string]any)
	for name, selector := range scope {
		if s, _ := selector.(map[string]any); s["from"] == "body" || s["from"] == "form" {
			delete(scope, name)
		}
	}
	if grant, ok := op["grant"].([]any); ok {
		op["grant"] = slices.DeleteFunc(grant, func(name any) bool { return scope[name.(string)] == nil })
	}
}

// Each matcher is an operation kind followed by the root fields it accepts; "*" accepts any.
func graphqlOverlap(a, b []string) bool {
	if len(a) < 2 || len(b) < 2 || a[0] != b[0] {
		return false
	}
	return a[1] == "*" || b[1] == "*" || slices.ContainsFunc(a[1:], func(f string) bool { return slices.Contains(b[1:], f) })
}

// conditionsOverlap reports whether one request can meet both sets of conditions; with presence, true accepts any single value.
func conditionsOverlap(a, b map[string]any, presence bool) bool {
	for key, value := range a {
		other, ok := b[key]
		_, text := value.(string)
		_, otherText := other.(string)
		if ok && !reflect.DeepEqual(value, other) && !(presence && (value == true && otherText || other == true && text)) {
			return false
		}
	}
	return true
}

func headerConditions(op map[string]any) map[string]any {
	headers, _ := op["headers"].(map[string]any)
	lower := map[string]any{}
	for key, value := range headers {
		lower[strings.ToLower(key)] = value
	}
	return lower
}

// mediaBody returns the body kind the matcher infers from a Content-Type header value.
func contentTypeAllows(condition any, body string) bool {
	switch body {
	case "any", "none":
		return true
	case "graphql":
		body = "json"
	}
	contentType, literal := condition.(string)
	return condition == true || literal && mediaBody(contentType) == body
}

func recordOverlap(a, b map[string]any) bool {
	x, y := operationSpec(a), operationSpec(b)
	if x.Method != y.Method || x.Origin != y.Origin || !bodiesOverlap(x.Body, y.Body) || !segmentsOverlap(x, y) {
		return false
	}
	if x.GraphQL != nil && y.GraphQL != nil {
		return graphqlOverlap(x.GraphQL, y.GraphQL)
	}
	for _, key := range []string{"query", "headers", "fields"} {
		am, _ := a[key].(map[string]any)
		bm, _ := b[key].(map[string]any)
		if key == "headers" {
			am, bm = headerConditions(a), headerConditions(b)
		}
		if !conditionsOverlap(am, bm, key != "fields" || x.Body == "form" || y.Body == "form") {
			return false
		}
	}
	for _, pair := range [][2]map[string]any{{a, b}, {b, a}} {
		if contentType, ok := headerConditions(pair[0])["content-type"]; ok && !contentTypeAllows(contentType, operationSpec(pair[1]).Body) {
			return false
		}
		present, _ := pair[0]["present"].([]any)
		fields, _ := pair[1]["fields"].(map[string]any)
		for _, at := range present {
			pointer, _ := at.(string)
			if value, ok := fields[pointer]; ok && value == nil {
				return false
			}
		}
		q, _ := pair[0]["query"].(map[string]any)
		allowed := map[string]bool{}
		if params, ok := pair[1]["params"].([]any); ok {
			for _, p := range params {
				if s, ok := p.(string); ok {
					allowed[s] = true
				}
			}
		}
		conditions, _ := pair[1]["query"].(map[string]any)
		for k := range conditions {
			allowed[k] = true
		}
		for k, v := range q {
			if v != nil && !allowed[k] && pair[1]["open_params"] != true {
				return false
			}
		}
	}
	return true
}

// An exclusion rejects a literal value, or with prefix the values starting with text, or with infix the values containing it.
type exclusion struct {
	text          string
	prefix, infix bool
}

const customMethodSeparator = ":"

// separateRoutes excludes another operation's more specific segment from a capture when that operation accepts every other segment of the capture's operation, or else applies source patterns that separate the segments; a source pattern replaces exclusions it also rejects.
func separateRoutes(operations []map[string]any, precise map[string]map[string]string) (overlaps [][2]int) {
	type capture struct {
		op   int
		name string
	}
	excluded := map[capture][]exclusion{}
	specs, segments, documented := make([]specOp, len(operations)), make([][]string, len(operations)), make([]map[string]string, len(operations))
	for i, op := range operations {
		specs[i] = operationSpec(op)
		segments[i] = strings.Split(specs[i].Path, "/")
		documented[i] = precise[specs[i].Origin+" "+specs[i].Path]
	}
	for i, a := range operations {
	pairs:
		for j := i + 1; j < len(operations); j++ {
			if !recordOverlap(a, operations[j]) {
				continue
			}
			overlaps = append(overlaps, [2]int{i, j})
			x, y, as, bs := specs[i], specs[j], segments[i], segments[j]
			if len(as) != len(bs) || strings.Contains(x.Path+y.Path, "*}") {
				continue
			}
			sides := []struct {
				op, peer       int
				spec, other    specOp
				segs, siblings []string
			}{{i, j, x, y, as, bs}, {j, i, y, x, bs, as}}
			assignable := func(spec specOp, name string) bool {
				return spec.PathPatterns[name] == "" && strings.Count(spec.Path, "{"+name+"}") == 1
			}
			for k := range as {
				for _, side := range sides {
					s, t := side.segs[k], side.siblings[k]
					prefix, name, suffix, ok := paramParts(s)
					tPrefix, tName, tSuffix, sibling := paramParts(t)
					patternPrefix := literalPrefix(cmp.Or(side.other.PathPatterns[tName], documented[side.peer][tName]))
					tPrefix += patternPrefix
					// A bare capture cannot hold a value of a sibling's custom method, such as {id} beside {id}:verb.
					verb := sibling && prefix+suffix == "" && strings.HasPrefix(tSuffix, customMethodSeparator)
					if !ok || s == t || !assignable(side.spec, name) || sibling && !verb && (len(tPrefix) <= len(prefix+literalPrefix(documented[side.op][name])) || !strings.HasPrefix(tPrefix, prefix)) {
						continue
					}
					lossless := true
					for m := range side.segs {
						lossless = lossless && (m == k || within(side.segs[m], side.siblings[m], side.spec.PathPatterns, side.other.PathPatterns))
					}
					if !lossless {
						continue
					}
					e := exclusion{text: t[len(prefix) : len(t)-len(suffix)]}
					switch {
					case verb:
						e = exclusion{text: customMethodSeparator, infix: true}
					case sibling:
						e = exclusion{text: tPrefix[len(prefix):], prefix: true}
						if _, ok := excluded[capture{side.peer, tName}]; !ok && patternPrefix != "" && assignable(side.other, tName) {
							excluded[capture{side.peer, tName}] = nil
						}
					}
					c := capture{side.op, name}
					excluded[c] = append(excluded[c], e)
					continue pairs
				}
			}
			for k := range as {
				var exprs []string
				var sourced []capture
				for _, side := range sides {
					patterns := side.spec.PathPatterns
					if _, name, _, ok := paramParts(side.segs[k]); ok && documented[side.op][name] != "" && assignable(side.spec, name) {
						patterns = map[string]string{name: documented[side.op][name]}
						sourced = append(sourced, capture{side.op, name})
					}
					exprs = append(exprs, segmentExpr(side.segs[k], patterns))
				}
				if len(sourced) > 0 && !intersect(exprs[0], exprs[1]) {
					for _, c := range sourced {
						if _, ok := excluded[c]; !ok {
							excluded[c] = nil
						}
					}
					continue pairs
				}
			}
			// A peer narrower only by a namespace and a final literal, such as settings/layouts beside {module}/{id}, claims the namespace.
			for _, side := range sides {
				var literals []int
				for m := range side.segs {
					_, _, _, param := paramParts(side.segs[m])
					if _, _, _, sibling := paramParts(side.siblings[m]); param && !sibling {
						literals = append(literals, m)
					} else if !within(side.segs[m], side.siblings[m], side.spec.PathPatterns, side.other.PathPatterns) {
						literals = nil
						break
					}
				}
				if len(literals) != 2 || literals[1] != len(side.segs)-1 {
					continue
				}
				prefix, name, suffix, _ := paramParts(side.segs[literals[0]])
				if !assignable(side.spec, name) {
					continue
				}
				t, c := side.siblings[literals[0]], capture{side.op, name}
				excluded[c] = append(excluded[c], exclusion{text: t[len(prefix) : len(t)-len(suffix)]})
				continue pairs
			}
		}
	}
	for c, values := range excluded {
		var exprs []string
		for _, e := range values {
			expr := regexp.QuoteMeta(e.text)
			if e.prefix || e.infix {
				expr += ".*"
			}
			if e.infix {
				expr = ".*" + expr
			}
			exprs = append(exprs, expr)
		}
		pattern := documented[c.op][c.name]
		if pattern == "" || len(exprs) > 0 && intersect(pattern, strings.Join(exprs, "|")) {
			pattern = complement(values)
		}
		patterns, _ := operations[c.op]["path_patterns"].(map[string]any)
		if patterns == nil {
			patterns = map[string]any{}
			operations[c.op]["path_patterns"] = patterns
		}
		patterns[c.name] = pattern
	}
	return overlaps
}

// complement returns an expression for the nonempty values that are neither an excluded literal nor start with an excluded prefix nor contain an excluded infix.
func complement(excluded []exclusion) string {
	type node struct {
		next     map[rune]*node
		end, cut bool
	}
	class := func(runes string) string { return strings.ReplaceAll(regexp.QuoteMeta(runes), "-", `\-`) }
	var banned string
	for _, e := range excluded {
		if e.infix && !strings.Contains(banned, e.text) {
			banned += e.text
		}
	}
	anyRune := "."
	if banned != "" {
		anyRune = "[^" + class(banned) + "]"
	}
	root := &node{next: map[rune]*node{}}
	for _, e := range excluded {
		if e.infix || strings.ContainsAny(e.text, banned) {
			continue
		}
		n := root
		for _, r := range e.text {
			if n.next[r] == nil {
				n.next[r] = &node{next: map[rune]*node{}}
			}
			n = n.next[r]
		}
		n.end, n.cut = true, n.cut || e.prefix
	}
	var render func(n *node) string
	render = func(n *node) string {
		var alternatives []string
		if !n.end && n != root {
			alternatives = append(alternatives, "")
		}
		keys := slices.Sorted(maps.Keys(n.next))
		if len(keys) == 0 {
			alternatives = append(alternatives, anyRune+"+")
		} else {
			alternatives = append(alternatives, "[^"+class(banned+string(keys))+"]"+anyRune+"*")
		}
		for _, r := range keys {
			if child := n.next[r]; !child.cut {
				alternatives = append(alternatives, regexp.QuoteMeta(string(r))+render(child))
			}
		}
		if n != root && len(alternatives) > 1 {
			return "(?:" + strings.Join(alternatives, "|") + ")"
		}
		return strings.Join(alternatives, "|")
	}
	return render(root)
}

func normalizeProvider(name string, o specOp) specOp {
	if name == "airtable" {
		o.Path = strings.NewReplacer("{baseId}", "app{base}", "{tableIdOrName}", "{table}", "{recordId}", "{record}").Replace(o.Path)
	}
	if name == "anthropic" {
		if o.Path == "/v1/messages" || o.Path == "/v1/complete" || o.Path == "/v1/messages/batches" && o.Method == "POST" {
			o.Effects = []string{"generate", "pay", "send"}
		}
		if o.Path == "/v1/messages/count_tokens" {
			o.Effects = []string{"send"}
		}
	}
	if name == "superlinked" {
		o.Path = strings.Replace(o.Path, "{model}", "{model*}", 1)
		if slices.Contains(o.Tags, "inference") {
			o.Effects = []string{"generate", "pay", "send"}
		}
		if o.Method != "GET" && (strings.HasPrefix(o.Path, "/v1/config") || strings.HasPrefix(o.Path, "/v1/pools")) {
			o.Effects = []string{"admin"}
			if o.Method == "DELETE" {
				o.Effects = append(o.Effects, "delete")
			}
		}
	}
	if name == "open_router" {
		if o.ID == "listVideosModels" {
			o.ID, o.Path = "getVideos", "/api/v1/videos/{jobId}"
		}
		if o.Method != "GET" {
			for _, prefix := range []string{"auth/", "oauth/", "keys", "byok", "guardrails", "observability/", "organization/", "private-endpoints", "scim/", "vault/", "workspaces"} {
				if strings.HasPrefix(o.Path, "/api/v1/"+prefix) {
					o.Effects = []string{"admin"}
					if o.Method == "DELETE" {
						o.Effects = append(o.Effects, "delete")
					}
					break
				}
			}
		}
		switch o.ID {
		case "sendChatCompletionRequest", "createResponses", "createMessages", "createEmbeddings", "createRerank",
			"createImages", "createVideos", "createAudioSpeech", "createAudioTranscriptions", "createBatches",
			"createSystemone", "createApiAlphaDecisions":
			o.Effects = []string{"generate", "pay", "send"}
		case "createPresetsChatCompletions", "createPresetsMessages", "createPresetsResponses":
			o.Effects = []string{"write"}
		case "createInternChatCompletion", "invokeIntern":
			o.Effects = []string{"execute", "generate", "pay", "send"}
		case "createIntern", "provisionIntern":
			o.Effects = []string{"admin", "execute", "pay"}
		case "updateIntern", "suspendIntern":
			o.Effects = []string{"admin"}
		case "deleteIntern":
			o.Effects = []string{"admin", "delete"}
		case "signInternDaemonRequest", "signInternDaemonAccessRequest", "copyVaultSecretsToIntern",
			"bulkAddWorkspaceMembers", "createScimGroupMapping", "updateScimGroupMapping", "createScimSyncJob",
			"createObservabilityDestination", "updateObservabilityDestination", "createWorkspace", "updateWorkspace":
			o.Effects = []string{"admin", "share"}
		case "storeVaultSecret", "storeInternVaultSecret", "createBYOKKey", "updateBYOKKey":
			o.Effects = []string{"admin", "send", "share"}
		case "validatePrivateEndpoint":
			o.Effects = []string{"admin", "generate", "pay", "send"}
		}
	}
	return o
}

func generateService(name string, sources map[string]source, lock lockFile) (generationReport, error) {
	src := sources[name]
	r := generationReport{Service: name, Presets: strings.Split(src.Preset, ","), Sources: lock[name], Note: src.Note, Counts: map[string]int{}, Operations: []inventoryOperation{}, Conflicts: [][2]string{}}
	r.Definition = src
	if src.Preset == "" {
		return r, fmt.Errorf("%s has no shipped preset mapping", name)
	}
	var candidate map[string]any
	var err error
	var baseline []map[string]any
	for _, preset := range r.Presets {
		p, err := load[map[string]any](filepath.Join(shippedDir, preset+".json"))
		if err != nil {
			return r, err
		}
		if candidate == nil {
			candidate = maps.Clone(p)
		}
		if ops, ok := httpSection(p)["operations"].(map[string]any); ok {
			for _, id := range sortedKeys(ops) {
				op := maps.Clone(ops[id].(map[string]any))
				op["id"] = id
				baseline = append(baseline, op)
			}
		}
	}
	r.ShippedSHA256, err = shippedDigest(r.Presets)
	if err != nil {
		return r, err
	}
	if len(src.Specs) == 0 {
		return r, fmt.Errorf("no specification configured: %s", src.Note)
	}
	origins, _ := httpSection(candidate)["origins"].(map[string]any)
	p, err := specOps(name, src, lock, origins)
	if err != nil {
		return r, err
	}
	r.Warnings = append(r.Warnings, p.Warnings...)
	if len(r.Presets) > 1 {
		r.Warnings = append(r.Warnings, "source spans multiple presets; candidate catalog needs provider-specific connection review")
	}
	operations := slices.Clone(baseline)
	ids := map[string]bool{}
	for _, o := range operations {
		ids[o["id"].(string)] = true
	}
	generated := map[string]string{}
	precise := map[string]map[string]string{}
	reviewer := map[string]string{}
	ai := name == "anthropic" || name == "open_ai" || name == "google_gemini"
	for _, raw := range p.Ops {
		o := normalizeProvider(name, raw)
		if raw.Reviewed {
			o.Effects = raw.Effects
		}
		route := o.Origin + " " + o.Path
		if precise[route] == nil {
			precise[route] = map[string]string{}
		}
		for capture, pattern := range o.PathPatterns {
			if known, ok := precise[route][capture]; ok && known != pattern {
				pattern = ""
			}
			precise[route][capture] = pattern
		}
		entry := inventoryOperation{ID: o.SourceID, Source: documentStamp{o.SourceURL, o.SourceHash}, Method: o.Method, Origin: o.Origin, Path: o.Path, Body: o.Body, Query: o.Query, Descriptors: []string{}}
		if o.Method == "" || o.Path == "" {
			entry.Status = "unsupported"
			entry.Reason = o.Unsupported
			if entry.Reason == "" {
				entry.Reason = "source does not describe a method and path"
			}
		} else {
			base := cmp.Or(o.ID, o.Method+" "+o.Path)
			drafted := operationObj(draftOps(parsed{Ops: []specOp{o}}, ai)[0], "")
			patterns := map[string]any{}
			for capture, pattern := range o.PathPatterns {
				patterns[capture] = pattern
			}
			documented := maps.Clone(drafted)
			documented["path_patterns"] = patterns
			opaque := o.Opaque
			var matched, targets []map[string]any
			for _, override := range baseline {
				shipped, id := operationSpec(override), override["id"].(string)
				// Separation may narrow a descriptor below its own operation's source path patterns, so those only rule out other descriptors.
				named := id == base || strings.HasPrefix(id, base+"."+shipped.Body+".")
				if (sameRoute(shipped, o) || opaque && shipped.GraphQL == nil && sameRoute(o, shipped)) && (named && recordOverlap(override, drafted) || recordOverlap(override, documented)) {
					if opaque && shipped.Body != "any" {
						acceptAnyBody(override)
					}
					entry.Descriptors = append(entry.Descriptors, id)
					matched = append(matched, override)
					if named {
						targets = append(targets, override)
					}
				}
			}
			// Reviewed effects apply to the descriptors named after the operation, or else to every descriptor serving it.
			if !o.Reviewed {
				targets = nil
			} else if len(targets) == 0 {
				targets = matched
			}
			for _, override := range targets {
				id, changed := override["id"].(string), !sameEffects(override["effects"], documented["effects"])
				if other, ok := reviewer[id]; ok && changed {
					return r, fmt.Errorf("reviewed effects of %s and %s disagree for %s", other, o.SourceID, id)
				}
				reviewer[id] = o.SourceID
				if changed {
					override["effects"], override["action"] = documented["effects"], documented["action"]
				}
			}
			if len(entry.Descriptors) > 0 {
				entry.Status = "shipped_override"
				params := slices.Clone(o.Params)
				for key, value := range o.Query {
					if value != nil && !slices.Contains(params, key) {
						params = append(params, key)
					}
				}
				slices.Sort(params)
				accepts := func(override map[string]any, param string) bool {
					q, _ := override["query"].(map[string]any)
					if constraint, exists := q[param]; exists {
						literal, fixed := o.Query[param]
						return constraint != nil && (!fixed || reflect.DeepEqual(literal, constraint))
					}
					ps, _ := override["params"].([]any)
					return override["open_params"] == true || slices.Contains(ps, any(param))
				}
				for _, param := range params {
					if slices.ContainsFunc(matched, func(override map[string]any) bool { return accepts(override, param) }) {
						continue
					}
					for _, override := range matched {
						q, _ := override["query"].(map[string]any)
						if _, conditioned := q[param]; conditioned {
							continue
						}
						ps, _ := override["params"].([]any)
						override["params"] = append(ps, param)
						if scope := override["scope"].(map[string]any); !slices.ContainsFunc(slices.Collect(maps.Values(scope)), func(s any) bool {
							m, _ := s.(map[string]any)
							return m["from"] == "query" && m["at"] == ""
						}) {
							bind(scope, "query", map[string]any{"from": "query", "at": "", "type": "object"})
						}
					}
				}
				for _, param := range params {
					if !slices.ContainsFunc(matched, func(override map[string]any) bool { return accepts(override, param) }) {
						entry.MissingParams = append(entry.MissingParams, param)
					}
				}
				if len(entry.MissingParams) > 0 {
					r.Counts["parameter_gaps"]++
				}
			} else {
				if o.Unsupported != "" || (o.Body == "any" || o.Body == "opaque") && !o.Opaque {
					entry.Status = "unsupported"
					entry.Reason = cmp.Or(o.Unsupported, "payload is not inspectable; a generated approval cannot bind it")
					r.Counts[entry.Status]++
					r.Operations = append(r.Operations, entry)
					continue
				}
				d := draftOps(parsed{Ops: []specOp{o}}, ai)[0]
				definition := operationObj(d, "")
				fingerprint, _ := json.Marshal(definition)
				if id, ok := generated[string(fingerprint)]; ok {
					entry.Descriptors = []string{id}
				} else {
					// A taken ID gets a suffix from the request the descriptor matches, not its inferred or reviewed semantics.
					route := maps.Clone(definition)
					for _, key := range []string{"action", "effects", "params", "scope"} {
						delete(route, key)
					}
					identity, _ := json.Marshal(route)
					id := base
					for attempt := 0; ids[id]; attempt++ {
						sum := sha256.Sum256(fmt.Appendf(nil, "%s\x00%d", identity, attempt))
						id = base + "." + o.Body + "." + hex.EncodeToString(sum[:6])
					}
					ids[id] = true
					definition["id"] = id
					operations = append(operations, definition)
					generated[string(fingerprint)] = id
					entry.Descriptors = []string{id}
				}
				entry.Status = "needs_review"
			}
		}
		r.Counts[entry.Status]++
		r.Operations = append(r.Operations, entry)
	}
	served := map[string]bool{}
	for _, entry := range r.Operations {
		served[entry.ID] = served[entry.ID] || len(entry.Descriptors) > 0
	}
	for _, o := range p.Ops {
		if o.Reviewed && !served[o.SourceID] {
			return r, fmt.Errorf("reviewed effects for %s apply to no descriptor", o.SourceID)
		}
	}
	for _, o := range p.Excluded {
		key, _ := sourceKey(src.Exclusions, o)
		r.Operations = append(r.Operations, inventoryOperation{ID: o.SourceID, Source: documentStamp{o.SourceURL, o.SourceHash}, Method: o.Method, Origin: o.Origin, Path: o.Path, Body: o.Body, Query: o.Query, Descriptors: []string{}, Status: "excluded", Reason: src.Exclusions[key]})
		r.Counts["excluded"]++
	}
	for _, pair := range separateRoutes(operations, precise) {
		if a, b := operations[pair[0]], operations[pair[1]]; recordOverlap(a, b) {
			r.Conflicts = append(r.Conflicts, [2]string{a["id"].(string), b["id"].(string)})
		}
	}
	for i := range r.Operations {
		entry := &r.Operations[i]
		if entry.Status != "unsupported" || entry.Method != "" {
			continue
		}
		for _, op := range operations {
			if op["path"] == entry.Path && op["origin"] == entry.Origin {
				entry.Descriptors = append(entry.Descriptors, op["id"].(string))
			}
		}
		if len(entry.Descriptors) > 0 {
			r.Counts["unsupported"]--
			entry.Status = "archived_schema"
			r.Counts[entry.Status]++
			entry.Reason = "Current method indexed; descriptor uses a shipped definition or archived schema. Current documentation still needs verification."
		}
	}
	mapped := map[string]bool{}
	for _, entry := range r.Operations {
		for _, id := range entry.Descriptors {
			mapped[id] = true
		}
	}
	for _, op := range baseline {
		if id := op["id"].(string); !mapped[id] {
			r.UnmappedShipped = append(r.UnmappedShipped, id)
		}
	}
	slices.Sort(r.UnmappedShipped)
	r.Counts["unmapped_shipped"] = len(r.UnmappedShipped)
	named := map[string]any{}
	for _, op := range operations {
		definition := maps.Clone(op)
		delete(definition, "id")
		named[op["id"].(string)] = definition
	}
	httpSection(candidate)["operations"] = named
	for set, hosts := range p.Origins {
		if origins == nil {
			origins = map[string]any{}
			httpSection(candidate)["origins"] = origins
		}
		shipped, _ := origins[set].([]any)
		for _, host := range shipped {
			if host, ok := host.(string); ok {
				hosts = append(hosts, host)
			}
		}
		slices.Sort(hosts)
		origins[set] = jsonStrings(slices.Compact(hosts))
	}
	hints, err := presetHints(operations, r.Presets, sources, lock, origins, map[string]parsed{name: p})
	if err != nil {
		return r, err
	}
	r.Counts["regrouped"] = groupRecord(candidate, hints)
	r.Counts["source_variants"] = len(r.Operations)
	r.Counts["descriptors"] = len(operations)
	r.Counts["conflicts"] = len(r.Conflicts)
	b, _ := json.Marshal(candidate)
	sum := sha256.Sum256(b)
	r.CandidateSHA256 = hex.EncodeToString(sum[:])
	if err := writeJSON(filepath.Join(candidatesDir, name+".json"), candidate); err != nil {
		return r, err
	}
	return r, nil
}

func generate(only []string) error {
	sources, err := load[map[string]source](sourcesPath)
	if err != nil {
		return err
	}
	lock, err := load[lockFile](lockPath)
	if err != nil {
		return err
	}
	digest, err := generatorDigest()
	if err != nil {
		return err
	}
	selected := map[string]bool{}
	for _, name := range only {
		if _, ok := sources[name]; ok {
			selected[name] = true
			continue
		}
		for key, src := range sources {
			if slices.Contains(strings.Split(src.Preset, ","), name) {
				selected[key] = true
			}
		}
	}
	for _, name := range only {
		found := false
		for key := range selected {
			if key == name || slices.Contains(strings.Split(sources[key].Preset, ","), name) {
				found = true
			}
		}
		if !found {
			return fmt.Errorf("unknown service %q", name)
		}
	}
	var failed []error
	for _, name := range sortedKeys(sources) {
		if len(only) > 0 && !selected[name] || len(only) == 0 && sources[name].Preset == "" {
			continue
		}
		r, err := generateService(name, sources, lock)
		r.GeneratorSHA256 = digest
		if err != nil {
			r.Error = err.Error()
			failed = append(failed, fmt.Errorf("%s: %w", name, err))
		}
		if err := writeJSON(filepath.Join(coverageDir, name+".json"), r); err != nil {
			return err
		}
		fmt.Printf("%s: %d source variants, %d descriptors, %d need review, %d unsupported, %d conflicts", name, len(r.Operations), r.Counts["descriptors"], r.Counts["needs_review"], r.Counts["unsupported"], len(r.Conflicts))
		if r.Error != "" {
			fmt.Printf("; %s", r.Error)
		}
		fmt.Println()
	}
	if err := writeCoverageIndex(sources); err != nil {
		failed = append(failed, err)
	}
	return errors.Join(failed...)
}

func accept(only []string) error {
	sources, err := load[map[string]source](sourcesPath)
	if err != nil {
		return err
	}
	for _, name := range only {
		if preset := sources[name].Preset; preset == "" || strings.Contains(preset, ",") {
			return fmt.Errorf("%s is not a source with exactly one shipped preset", name)
		}
	}
	if err := check(only, false, 0); err != nil {
		return err
	}
	for _, name := range only {
		candidate, err := load[map[string]any](filepath.Join(candidatesDir, name+".json"))
		if err == nil {
			err = writeJSON(filepath.Join(shippedDir, sources[name].Preset+".json"), candidate)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func httpSection(record map[string]any) map[string]any {
	if spec, ok := record["http"].(map[string]any); ok {
		return spec
	}
	spec := map[string]any{}
	record["http"] = spec
	return spec
}
