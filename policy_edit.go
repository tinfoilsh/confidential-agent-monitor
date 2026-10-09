package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"strings"

	toml "github.com/pelletier/go-toml/v2"
	"github.com/pelletier/go-toml/v2/unstable/edit"
	"github.com/pmezard/go-difflib/difflib"
	"github.com/tinfoilsh/monitor/facts"
)

const (
	maxProposalBytes   = 64 << 10
	maxProposalReason  = 4096
	maxProposalDeletes = 64
)

var errPolicyConflict = errors.New("policy changed; reload it and review a new diff before applying")

type sourceInput struct {
	Source string `json:"source"`
}
type editsInput struct {
	Changes []sourceChange `json:"changes"`
}
type proposalInput struct {
	Source string     `json:"source"`
	Reason string     `json:"reason"`
	Delete [][]string `json:"delete,omitempty"`
}

// sourceChange replaces or deletes one source value. Tables and rules retain
// their names; edits never reconstruct source from a derived configuration.
type sourceChange struct {
	Path   []string        `json:"path"`
	Value  json.RawMessage `json:"value,omitempty"`
	Delete bool            `json:"delete,omitempty"`
}

type tomlChange struct {
	path   []string
	value  any
	delete bool
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

// prepareCandidate validates source and pins its presets without publishing anything.
func (m *monitor) prepareCandidate(ctx context.Context, source string, secrets secretStore) (sealed, *state, error) {
	next := m.doc
	policy := policyDocument{Source: source, Bases: maps.Clone(m.doc.Policy.Bases)}
	next.Policy = &policy
	next.Secrets = secrets
	if secrets == nil {
		next.Secrets = m.doc.Secrets.clone()
	}
	st, err := m.build(ctx, next, m.live.Load().Env, m.live.Load())
	if err != nil {
		return next, nil, err
	}
	policy.Source, err = editSource(source, st.cfg.pins)
	return next, st, err
}

func (m *monitor) editPolicy(ctx context.Context, changes []sourceChange) error {
	if len(changes) == 0 {
		return nil
	}
	secrets := m.doc.Secrets.clone()
	edits := make([]tomlChange, 0, len(changes))
	for _, change := range changes {
		if len(change.Path) == 0 {
			return errors.New("an edit requires a source path")
		}
		var value any
		if change.Delete {
			if len(change.Value) != 0 {
				return errors.New("a deletion cannot have a value")
			}
		} else if err := facts.DecodeNumbers(change.Value, &value); err != nil {
			return err
		}
		// Credentials live in the sealed store; removing a connection drops its own.
		if isCredentialPath(change.Path) {
			var raw json.RawMessage
			if value != nil {
				raw, _ = json.Marshal(value)
			}
			secrets.set(credentialID(change.Path), raw)
			continue
		}
		if change.Delete {
			edits = append(edits, tomlChange{path: change.Path, delete: true})
			continue
		}
		encoded, err := tomlValue(value)
		if err != nil {
			return err
		}
		edits = append(edits, tomlChange{path: change.Path, value: encoded})
	}
	source, err := editSource(m.doc.Policy.Source, edits)
	if err != nil {
		return err
	}
	// Compilation drops credentials without a connection, so compare against what this edit wrote.
	next, st, err := m.prepareCandidate(ctx, source, secrets.clone())
	if err != nil {
		return err
	}
	for id, raw := range secrets.all() {
		if next.Secrets.get(id) == nil && !bytes.Equal(raw, m.doc.Secrets.get(id)) {
			return fmt.Errorf("credential %v has no connection", id)
		}
	}
	return m.activate(ctx, next, st)
}

func sourceDiff(before, after string) string {
	diff, _ := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
		A: difflib.SplitLines(before), B: difflib.SplitLines(after),
		FromFile: "active/policy.toml", ToFile: "proposed/policy.toml", Context: 3,
	})
	return diff
}

// effectiveSource renders an already compiled state; reading it cannot compile
// or change policy. Configuration contains no credential values.
func effectiveSource(st *state) (string, error) {
	v, err := facts.JSON[map[string]any](st.cfg)
	if err != nil {
		return "", err
	}
	ps := map[string]any{}
	for _, acc := range st.cfg.Accounts {
		if ps[acc.Preset], err = facts.JSON[map[string]any](st.cfg.resolved[acc.Preset]); err != nil {
			return "", err
		}
	}
	v["presets"] = ps
	return renderTOML(v)
}

func (m *monitor) policyPreview(next sealed, st *state) (*facts.Policy, error) {
	before, err := effectiveSource(m.live.Load())
	if err != nil {
		return nil, err
	}
	after, err := effectiveSource(st)
	if err != nil {
		return nil, err
	}
	return &facts.Policy{SourceDiff: sourceDiff(m.doc.Policy.Source, next.Policy.Source), EffectiveDiff: sourceDiff(before, after)}, nil
}

func (m *monitor) policyRoutes(mux *http.ServeMux) {
	mux.Handle("GET /policy", owned(m, func(r *http.Request, _ struct{}) (any, error) {
		result := map[string]any{"source": m.doc.Policy.Source}
		var err error
		if r.URL.Query().Has("effective") {
			result["effective"], err = effectiveSource(m.live.Load())
		}
		return result, err
	}))
	mux.Handle("POST /policy/preview", owned(m, func(r *http.Request, input sourceInput) (any, error) {
		next, st, err := m.prepareCandidate(r.Context(), input.Source, nil)
		if err != nil {
			return nil, err
		}
		diff, err := m.policyPreview(next, st)
		return struct {
			Source string `json:"source"`
			*facts.Policy
		}{next.Policy.Source, diff}, err
	}))
	mux.Handle("POST /policy", owned(m, func(r *http.Request, input sourceInput) (any, error) {
		next, st, err := m.prepareCandidate(r.Context(), input.Source, nil)
		if err == nil {
			err = m.activate(r.Context(), next, st)
		}
		return m.view(err)
	}))
	mux.Handle("POST /policy/edits", owned(m, func(r *http.Request, input editsInput) (any, error) {
		return m.view(m.editPolicy(r.Context(), input.Changes))
	}))
}

// agentView splits the configuration into the settings p may read and propose
// changing, and the rest, which a proposal must leave unchanged.
func agentView(cfg *config, p principal) (visible, rest map[string]any, err error) {
	if rest, err = facts.JSON[map[string]any](cfg); err != nil {
		return nil, nil, err
	}
	identities, _ := rest["identities"].(map[string]any)
	identity, _ := identities[p.Name].(map[string]any)
	accounts, _ := rest["accounts"].(map[string]any)
	reachable := map[string]any{}
	for name, a := range accounts {
		if p.reaches(name) {
			reachable[name] = take(a.(map[string]any), "contents", "strangers", "sends", "policy_options")
		}
	}
	visible = map[string]any{"lattices": rest["lattices"], "identities": map[string]any{p.Name: take(identity, "accounts", "rules")}, "accounts": reachable}
	delete(rest, "lattices")
	return visible, rest, nil
}

// take moves the named fields out of m.
func take(m map[string]any, fields ...string) map[string]any {
	out := map[string]any{}
	for _, field := range fields {
		if value, ok := m[field]; ok {
			out[field] = value
			delete(m, field)
		}
	}
	return out
}

// fragmentChanges sets each leaf of a TOML fragment, merging it into the source.
func fragmentChanges(v map[string]any, path []string) (changes []tomlChange) {
	for _, key := range slices.Sorted(maps.Keys(v)) {
		at := append(slices.Clone(path), key)
		if table, ok := v[key].(map[string]any); ok && len(table) > 0 {
			changes = append(changes, fragmentChanges(table, at)...)
		} else {
			changes = append(changes, tomlChange{path: at, value: v[key]})
		}
	}
	return changes
}

// proposePolicy holds an agent's change as an approval card and applies it once the owner allows it.
func (m *monitor) proposePolicy(ctx context.Context, p principal, input proposalInput) (err error) {
	if len(input.Source) > maxProposalBytes || len(input.Reason) > maxProposalReason || strings.TrimSpace(input.Reason) == "" || len(input.Delete) > maxProposalDeletes {
		return fmt.Errorf("proposal needs a reason of 1-%d bytes, at most %d bytes of TOML, and at most %d deletions", maxProposalReason, maxProposalBytes, maxProposalDeletes)
	}
	patch, err := readSource(input.Source)
	if err != nil {
		return err
	}
	changes := fragmentChanges(patch, nil)
	for _, path := range input.Delete {
		changes = append(changes, tomlChange{path: path, delete: true})
	}
	base := m.doc.Policy.Source
	source, err := editSource(base, changes)
	if err != nil {
		return err
	}
	if source == base {
		return errors.New("proposal does not change policy")
	}
	next, st, err := m.prepareCandidate(ctx, source, nil)
	if err != nil {
		return err
	}
	_, before, err := agentView(m.live.Load().cfg, p)
	if err != nil {
		return err
	}
	_, after, err := agentView(st.cfg, p)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(before, after) {
		return errors.New("proposal may edit only your permissions, reachable accounts' policy settings, or lattice switches")
	}
	diff, err := m.policyPreview(next, st)
	if err != nil {
		return err
	}
	r := m.addRecord(&decision{Facts: &facts.Facts{Version: facts.Version, Principal: facts.Principal{Key: p.Key, Name: p.Name},
		Title: "Change policy", Parameters: map[string]any{}, Details: facts.Details{Policy: diff}},
		Requirements: requirements{{ID: "policy", Message: input.Reason}}})
	defer func() { r.settle(err) }()
	if err = m.await(ctx, r); err != nil {
		return err
	}
	if m.doc.Policy.Source != base {
		return errPolicyConflict
	}
	if next, st, err = m.prepareCandidate(ctx, next.Policy.Source, nil); err != nil {
		return err
	}
	return m.activate(ctx, next, st)
}

func (m *monitor) agentPolicyRoutes(mux *http.ServeMux, key string) {
	show := func() (any, error) {
		st := m.live.Load()
		p := st.principals[key]
		visible, _, err := agentView(st.cfg, p)
		if err != nil {
			return nil, err
		}
		source, err := renderTOML(visible)
		return map[string]any{"identity": p.Name, "source": source}, err
	}
	mux.HandleFunc("GET /policy", agentJSON(m, key, func(*http.Request, struct{}, principal) (any, error) {
		return show()
	}))
	mux.HandleFunc("POST /policy/proposals", agentJSON(m, key, func(r *http.Request, input proposalInput, p principal) (any, error) {
		if err := m.proposePolicy(r.Context(), p, input); err != nil {
			return nil, err
		}
		return show()
	}))
}
