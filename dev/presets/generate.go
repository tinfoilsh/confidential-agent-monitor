package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
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
	// Keep generated operation records on individual lines, like shipped presets.
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
	if g, ok := op["graphql"].(map[string]any); ok {
		kind, _ := g["operation"].(string)
		field, _ := g["field"].(string)
		o.GraphQL = []string{kind, field}
	}
	return o
}

func sameRoute(a, b specOp) bool {
	if a.Method != b.Method || a.Origin != b.Origin || a.Body != b.Body {
		return false
	}
	if a.GraphQL != nil || b.GraphQL != nil {
		return slices.Equal(a.GraphQL, b.GraphQL)
	}
	return routeShape(a.Method, a.Path) == routeShape(b.Method, b.Path)
}

// Conditions conflict only if both records constrain a key differently.
func conditionsOverlap(a, b map[string]any) bool {
	for key, value := range a {
		if other, ok := b[key]; ok && !reflect.DeepEqual(value, other) {
			return false
		}
	}
	return true
}

func recordOverlap(a, b map[string]any) bool {
	x, y := operationSpec(a), operationSpec(b)
	if x.Method != y.Method || x.Origin != y.Origin || !bodiesOverlap(x.Body, y.Body) || !segmentsOverlap(x.Path, y.Path) {
		return false
	}
	if x.GraphQL != nil || y.GraphQL != nil {
		return slices.Equal(x.GraphQL, y.GraphQL)
	}
	for _, key := range []string{"query", "headers", "fields"} {
		am, _ := a[key].(map[string]any)
		bm, _ := b[key].(map[string]any)
		if !conditionsOverlap(am, bm) {
			return false
		}
	}
	// Literal query conditions must also be accepted by the other record.
	for _, pair := range [][2]map[string]any{{a, b}, {b, a}} {
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
	if name == "open_router" {
		// The model catalog and job status routes are both reads. Use one
		// descriptor for their union, binding the requested segment in scope,
		// so /videos/models cannot also match /videos/{jobId}.
		if o.ID == "listVideosModels" {
			o.ID, o.Path = "getVideos", "/api/v1/videos/{jobId}"
		}
		if o.Method != "GET" {
			// These resources control credentials, access, routing or budgets.
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
			// These save inference configuration; they do not run inference.
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
			// Validation sends a live inference request using the workspace key.
			o.Effects = []string{"admin", "generate", "pay", "send"}
		}
	}
	return o
}

func generateService(name string, src source, lock lockFile) (generationReport, error) {
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
	p, err := specOps(name, src, lock)
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
	for _, raw := range p.Ops {
		o := normalizeProvider(name, raw)
		entry := inventoryOperation{ID: o.SourceID, Source: documentStamp{o.SourceURL, o.SourceHash}, Method: o.Method, Origin: o.Origin, Path: o.Path, Body: o.Body, Query: o.Query, Descriptors: []string{}}
		if o.Unsupported != "" || o.Method == "" || o.Path == "" {
			entry.Status = "unsupported"
			entry.Reason = o.Unsupported
			if entry.Reason == "" {
				entry.Reason = "source does not describe a method and path"
			}
		} else {
			for _, override := range baseline {
				if sameRoute(operationSpec(override), o) {
					entry.Descriptors = append(entry.Descriptors, override["id"].(string))
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
				for _, param := range params {
					allowed := false
					for _, override := range baseline {
						if !slices.Contains(entry.Descriptors, override["id"].(string)) {
							continue
						}
						accepts := false
						if override["open_params"] == true {
							accepts = true
						}
						if ps, ok := override["params"].([]any); ok && slices.Contains(ps, any(param)) {
							accepts = true
						}
						if q, ok := override["query"].(map[string]any); ok {
							if constraint, exists := q[param]; exists {
								literal, fixed := o.Query[param]
								accepts = constraint != nil && (!fixed || reflect.DeepEqual(literal, constraint))
							}
						}
						allowed = allowed || accepts
					}
					if !allowed {
						entry.MissingParams = append(entry.MissingParams, param)
					}
				}
				if len(entry.MissingParams) > 0 {
					r.Counts["parameter_gaps"]++
				}
			} else {
				if o.Body == "any" || o.Body == "opaque" {
					entry.Status = "unsupported"
					entry.Reason = "payload is not inspectable; a generated approval cannot bind it"
					r.Counts[entry.Status]++
					r.Operations = append(r.Operations, entry)
					continue
				}
				d := draftOps(parsed{Ops: []specOp{o}}, name == "anthropic" || name == "open_ai" || name == "google_gemini")[0]
				definition := operationObj(d, "")
				fingerprint, _ := json.Marshal(definition)
				if id, ok := generated[string(fingerprint)]; ok {
					entry.Descriptors = []string{id}
				} else {
					id := o.ID
					if id == "" {
						id = o.Method + " " + o.Path
					}
					sum := sha256.Sum256(fingerprint)
					if ids[id] {
						id += "." + o.Body + "." + hex.EncodeToString(sum[:6])
					}
					if ids[id] {
						return r, fmt.Errorf("duplicate generated operation id %q", id)
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
	for i, a := range operations {
		for _, b := range operations[i+1:] {
			if recordOverlap(a, b) {
				r.Conflicts = append(r.Conflicts, [2]string{a["id"].(string), b["id"].(string)})
			}
		}
	}
	// A current index can identify methods whose only available request schema
	// is archived. Keep that distinction visible even when a candidate exists.
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
	r.Counts["regrouped"] = groupRecord(candidate, groupHints(operations, p, name))
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
		r, err := generateService(name, sources[name], lock)
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

func httpSection(record map[string]any) map[string]any {
	if spec, ok := record["http"].(map[string]any); ok {
		return spec
	}
	spec := map[string]any{}
	record["http"] = spec
	return spec
}
