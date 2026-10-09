package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	toml "github.com/pelletier/go-toml/v2"
	"github.com/pmezard/go-difflib/difflib"
	"github.com/tinfoilsh/monitor/facts"
)

var errPolicyConflict = errors.New("policy changed; reload it and review a new diff before applying")

const (
	proposalPending  = "pending"
	proposalApproved = "approved"
	proposalRejected = "rejected"
)

type policyProposal struct {
	ID         string    `json:"id"`
	Agent      string    `json:"agent"`
	Key        string    `json:"key"`
	Reason     string    `json:"reason"`
	Time       time.Time `json:"time"`
	State      string    `json:"state"`
	BaseSource string    `json:"base_source"`
	Source     string    `json:"source"`
}

type proposalSummary struct {
	ID     string    `json:"id"`
	Agent  string    `json:"agent"`
	Reason string    `json:"reason"`
	Time   time.Time `json:"time"`
	State  string    `json:"state"`
	Stale  bool      `json:"stale"`
}

func (p policyProposal) summary(source string) proposalSummary {
	return proposalSummary{p.ID, p.Agent, p.Reason, p.Time, p.State, p.BaseSource != source}
}

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

type policyBase struct {
	doc      sealed
	state    *state
	revision uint64
}

type policyCandidate struct {
	base     policyBase
	doc      sealed
	state    *state
	proposal string
	updated  map[secretID]bool // Changed credentials; true means set, false means deleted.
}

// sourceChange replaces or deletes one source value. Tables and rules retain
// their names; edits never reconstruct source from a derived configuration.
type sourceChange struct {
	Path   []string        `json:"path"`
	Value  json.RawMessage `json:"value,omitempty"`
	Delete bool            `json:"delete,omitempty"`
}

func (m *monitor) policySnapshot() (base policyBase, err error) {
	err = m.transact(func(tx *transaction) error {
		if tx.live.Load() == nil {
			return errLocked
		}
		base = policyBase{doc: tx.doc, state: tx.live.Load(), revision: tx.revision}
		return nil
	})
	return
}

func (m *monitor) prepareCandidate(ctx context.Context, base policyBase, source string, secrets secretStore) (*policyCandidate, error) {
	updated := map[secretID]bool{}
	if secrets == nil {
		secrets = base.doc.Secrets.clone()
	} else {
		for id, value := range secrets.all() {
			if !sameCredential(value, base.doc.Secrets.get(id)) {
				updated[id] = true
			}
		}
		for id := range base.doc.Secrets.all() {
			if secrets.get(id) == nil {
				updated[id] = false
			}
		}
	}
	next := base.doc
	next.Policy = clonePolicy(base.doc.Policy)
	next.Policy.Source = source
	next.Secrets = secrets
	st, err := m.build(ctx, next, base.state.Env, base.state, updated)
	if err != nil {
		return nil, err
	}
	if err := pinPresets(st.cfg, next.Policy); err != nil {
		return nil, err
	}
	return &policyCandidate{base: base, doc: next, state: st, updated: updated}, nil
}

func (m *monitor) editPolicy(ctx context.Context, changes []sourceChange) error {
	base, err := m.policySnapshot()
	if err != nil {
		return err
	}
	if len(changes) == 0 {
		return nil
	}
	candidate, err := m.prepareEdits(ctx, base, changes)
	if err != nil {
		return err
	}
	return m.transact(func(tx *transaction) error { return tx.activate(ctx, candidate) })
}

func (m *monitor) prepareEdits(ctx context.Context, base policyBase, changes []sourceChange) (*policyCandidate, error) {
	secrets := base.doc.Secrets.clone()
	edits := make([]tomlChange, 0, len(changes))
	for _, change := range changes {
		if len(change.Path) == 0 {
			return nil, errors.New("an edit requires a source path")
		}
		if change.Delete {
			if len(change.Value) != 0 {
				return nil, errors.New("a deletion cannot have a value")
			}
			for id := range secrets.all() {
				c := base.state.connections[connectionName(id[0], id[1])]
				path := append(c.path(), "secrets", id[2])
				if len(change.Path) <= len(path) && slices.Equal(change.Path, path[:len(change.Path)]) {
					secrets.set(id, nil)
				}
			}
			if !isCredentialPath(change.Path) {
				edits = append(edits, tomlChange{path: change.Path, delete: true})
			}
			continue
		}
		var value any
		if err := facts.DecodeNumbers(change.Value, &value); err != nil {
			return nil, err
		}
		value, secret := separateCredentials(change.Path, value, secrets)
		if secret {
			continue
		}
		value, err := tomlValue(value)
		if err != nil {
			return nil, err
		}
		edits = append(edits, tomlChange{path: change.Path, value: value})
	}
	source, err := editSource(base.doc.Policy.Source, edits)
	if err != nil {
		return nil, err
	}
	candidate, err := m.prepareCandidate(ctx, base, source, secrets)
	if err != nil {
		return nil, err
	}
	for id, set := range candidate.updated {
		c := candidate.state.connections[connectionName(id[0], id[1])]
		if set && (c == nil || c.account != id[0] || c.key != id[1] || c.Secrets == nil) {
			return nil, fmt.Errorf("credential %v has no connection", id)
		}
	}
	return candidate, nil
}

// Account settings write credentials directly to the sealed name store.
func separateCredentials(path []string, value any, secrets secretStore) (any, bool) {
	if isCredentialPath(path) {
		var raw json.RawMessage
		if value != nil {
			raw, _ = json.Marshal(value)
		}
		secrets.set(credentialID(path), raw)
		return nil, true
	}
	if object, ok := value.(map[string]any); ok {
		for key, child := range object {
			next, secret := separateCredentials(append(slices.Clone(path), key), child, secrets)
			if secret {
				delete(object, key)
			} else {
				object[key] = next
			}
		}
	}
	return value, false
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
		preset, err := facts.JSON[map[string]any](st.cfg.resolved[acc.Preset])
		if err != nil {
			return "", err
		}
		ps[acc.Preset] = preset
	}
	v["presets"] = ps
	encoded, err := tomlValue(v)
	if err != nil {
		return "", err
	}
	text, err := toml.Marshal(encoded)
	return string(text), err
}

func policyPreview(next *policyCandidate) (map[string]any, error) {
	before, err := effectiveSource(next.base.state)
	if err != nil {
		return nil, err
	}
	after, err := effectiveSource(next.state)
	if err != nil {
		return nil, err
	}
	return map[string]any{"source": next.doc.Policy.Source,
		"source_diff": sourceDiff(next.base.doc.Policy.Source, next.doc.Policy.Source), "effective_diff": sourceDiff(before, after)}, nil
}

func (m *monitor) policyRoutes(mux *http.ServeMux) {
	mux.Handle("GET /policy", owned(m, func(r *http.Request, _ struct{}) (any, error) {
		base, err := m.policySnapshot()
		if err != nil {
			return nil, err
		}
		result := map[string]any{"source": base.doc.Policy.Source}
		if r.URL.Query().Has("effective") {
			result["effective"], err = effectiveSource(base.state)
		}
		return result, err
	}))
	mux.Handle("POST /policy/preview", owned(m, func(r *http.Request, input sourceInput) (any, error) {
		base, err := m.policySnapshot()
		if err != nil {
			return nil, err
		}
		next, err := m.prepareCandidate(r.Context(), base, input.Source, nil)
		if err != nil {
			return nil, err
		}
		return policyPreview(next)
	}))
	mux.Handle("POST /policy", owned(m, func(r *http.Request, input sourceInput) (any, error) {
		base, err := m.policySnapshot()
		if err != nil {
			return nil, err
		}
		next, err := m.prepareCandidate(r.Context(), base, input.Source, nil)
		if err == nil {
			err = m.transact(func(tx *transaction) error { return tx.activate(r.Context(), next) })
		}
		return m.view(err)
	}))
	mux.Handle("POST /policy/edits", owned(m, func(r *http.Request, input editsInput) (any, error) {
		err := m.editPolicy(r.Context(), input.Changes)
		return m.view(err)
	}))
	mux.Handle("GET /policy/proposals/{id}", owned(m, func(r *http.Request, _ struct{}) (any, error) {
		base, err := m.policySnapshot()
		if err != nil {
			return nil, err
		}
		p, _, err := base.doc.Policy.findProposal(r.PathValue("id"))
		if err != nil {
			return nil, err
		}
		result := map[string]any{"proposal": p.summary(base.doc.Policy.Source), "source": p.Source, "base_source": p.BaseSource,
			"source_diff": sourceDiff(p.BaseSource, p.Source), "stale": p.BaseSource != base.doc.Policy.Source}
		if p.BaseSource == base.doc.Policy.Source {
			next, err := m.prepareCandidate(r.Context(), base, p.Source, nil)
			if err != nil {
				return nil, err
			}
			preview, err := policyPreview(next)
			if err != nil {
				return nil, err
			}
			result["effective_diff"] = preview["effective_diff"]
		}
		return result, nil
	}))
	mux.Handle("POST /policy/proposals/{id}", owned(m, func(r *http.Request, input decisionInput) (any, error) {
		err := m.answerProposal(r.Context(), r.PathValue("id"), input)
		return m.view(err)
	}))
}

func (p *policyDocument) findProposal(id string) (policyProposal, int, error) {
	for i, proposal := range p.Proposals {
		if proposal.ID == id {
			return proposal, i, nil
		}
	}
	return policyProposal{}, -1, errors.New("no such policy proposal")
}

func (m *monitor) answerProposal(ctx context.Context, id string, input decisionInput) error {
	if input.Decision == "reject" {
		err := m.transact(func(tx *transaction) error {
			p, i, err := tx.doc.Policy.findProposal(id)
			if err != nil {
				return err
			}
			if p.State != proposalPending {
				return errors.New("proposal has already been reviewed")
			}
			next := tx.doc
			next.Policy = clonePolicy(next.Policy)
			next.Policy.Proposals[i].State = proposalRejected
			next.Generation++
			return tx.commit(ctx, next)
		})
		return err
	}
	if input.Decision != "approve" {
		return errors.New("decision must be approve or reject")
	}
	base, err := m.policySnapshot()
	if err != nil {
		return err
	}
	p, _, err := base.doc.Policy.findProposal(id)
	if err != nil {
		return err
	}
	next, err := m.prepareCandidate(ctx, base, p.Source, nil)
	if err != nil {
		return err
	}
	next.proposal = id
	return m.transact(func(tx *transaction) error { return tx.activate(ctx, next) })
}

// Fields visible to agents are also the fields they can propose changing.
var agentPolicyFields = map[string][]string{
	"lattices":   {"confidentiality", "integrity"},
	"identities": {"accounts", "rules"},
	"accounts":   {"contents", "strangers", "sends", "policy_options"},
}

func agentPolicySource(cfg *config, p principal) (string, error) {
	v, err := facts.JSON[map[string]any](cfg)
	if err != nil {
		return "", err
	}
	out := map[string]any{}
	for section, fields := range agentPolicyFields {
		paths := [][]string{{section}}
		switch section {
		case "identities":
			paths = [][]string{{section, p.Name}}
		case "accounts":
			paths = nil
			for name := range p.Accounts {
				if p.reaches(name) {
					paths = append(paths, []string{section, name})
				}
			}
			out[section] = map[string]any{}
		}
		for _, path := range paths {
			visible := map[string]any{}
			for _, field := range fields {
				if value, ok := mapValue(v, append(slices.Clone(path), field)); ok {
					visible[field] = value
				}
			}
			if len(path) == 1 {
				out[section] = visible
			} else {
				if out[section] == nil {
					out[section] = map[string]any{}
				}
				out[section].(map[string]any)[path[1]] = visible
			}
		}
	}
	encoded, err := tomlValue(out)
	if err != nil {
		return "", err
	}
	raw, err := toml.Marshal(encoded)
	return string(raw), err
}

func proposalPathAllowed(p principal, path []string) bool {
	if len(path) < 2 {
		return false
	}
	fields := agentPolicyFields[path[0]]
	switch path[0] {
	case "lattices":
		return len(path) == 2 && slices.Contains(fields, path[1])
	case "identities":
		return len(path) >= 3 && path[1] == p.Name && slices.Contains(fields, path[2])
	case "accounts":
		return len(path) >= 3 && p.reaches(path[1]) && slices.Contains(fields, path[2])
	}
	return false
}

func proposalChanges(p principal, v map[string]any, path []string, changes *[]tomlChange) error {
	if len(v) == 0 && !proposalPathAllowed(p, path) {
		return errors.New("proposal may edit only your permissions, reachable accounts' policy settings, or lattice switches")
	}
	for k, value := range v {
		next := append(slices.Clone(path), k)
		if obj, ok := value.(map[string]any); ok && len(obj) > 0 {
			if err := proposalChanges(p, obj, next, changes); err != nil {
				return err
			}
		} else {
			if !proposalPathAllowed(p, next) {
				return fmt.Errorf("proposal cannot edit %s", pointer(next))
			}
			*changes = append(*changes, tomlChange{path: next, value: value})
		}
	}
	return nil
}

func (m *monitor) proposePolicy(ctx context.Context, base policyBase, p principal, input proposalInput) (proposalSummary, error) {

	if len(input.Source) > 64<<10 || len(input.Reason) > 4096 || strings.TrimSpace(input.Reason) == "" || len(input.Delete) > 64 {
		return proposalSummary{}, errors.New("proposal needs a reason of 1-4096 bytes, at most 64 KiB of TOML, and at most 64 deletions")
	}
	patch, err := readSource(input.Source)
	if err != nil {
		return proposalSummary{}, err
	}
	var changes []tomlChange
	if len(patch) > 0 {
		if err := proposalChanges(p, patch, nil, &changes); err != nil {
			return proposalSummary{}, err
		}
	}
	for _, path := range input.Delete {
		if !proposalPathAllowed(p, path) {
			return proposalSummary{}, fmt.Errorf("proposal cannot delete %s", pointer(path))
		}
		changes = append(changes, tomlChange{path: path, delete: true})
	}
	source, err := editSource(base.doc.Policy.Source, changes)
	if err != nil {
		return proposalSummary{}, err
	}
	if source == base.doc.Policy.Source {
		return proposalSummary{}, errors.New("proposal does not change policy")
	}
	candidate, err := m.prepareCandidate(ctx, base, source, nil)
	if err != nil {
		return proposalSummary{}, err
	}
	var proposal policyProposal
	err = m.transact(func(tx *transaction) error {
		if tx.revision != base.revision {
			return errPolicyConflict
		}
		next := tx.doc
		next.Policy = clonePolicy(next.Policy)
		if len(next.Policy.Proposals) >= 32 {
			i := slices.IndexFunc(next.Policy.Proposals, func(p policyProposal) bool { return p.State != proposalPending })
			if i < 0 {
				return errors.New("policy proposal queue is full")
			}
			next.Policy.Proposals = slices.Delete(next.Policy.Proposals, i, i+1)
		}
		count, size := 0, len(source)+len(base.doc.Policy.Source)
		for _, proposal := range next.Policy.Proposals {
			if proposal.State == proposalPending && proposal.Key == p.Key {
				count++
			}
			size += len(proposal.Source) + len(proposal.BaseSource)
		}
		if count >= 4 || size > 8<<20 {
			return errors.New("policy proposal queue is full")
		}
		var id [16]byte
		if _, err := rand.Read(id[:]); err != nil {
			return err
		}
		proposal = policyProposal{ID: hex.EncodeToString(id[:]), Agent: p.Name, Key: p.Key,
			Reason: input.Reason, Time: time.Now().UTC(), State: proposalPending, BaseSource: base.doc.Policy.Source, Source: candidate.doc.Policy.Source}
		next.Policy.Proposals = append(next.Policy.Proposals, proposal)
		next.Generation++
		return tx.commit(ctx, next)
	})
	return proposal.summary(base.doc.Policy.Source), err
}

func (m *monitor) agentPolicyRoutes(mux *http.ServeMux, key string) {
	mux.HandleFunc("GET /policy", agentJSON(m, key, func(_ *http.Request, _ struct{}, base policyBase, p principal) (any, error) {
		source, err := agentPolicySource(base.state.cfg, p)
		return map[string]any{"identity": p.Name, "source": source}, err
	}))
	mux.HandleFunc("GET /policy/proposals", agentJSON(m, key, func(_ *http.Request, _ struct{}, base policyBase, p principal) (any, error) {
		list := []proposalSummary{}
		for _, proposal := range base.doc.Policy.Proposals {
			if proposal.Key == key {
				list = append(list, proposal.summary(base.doc.Policy.Source))
			}
		}
		return list, nil
	}))
	mux.HandleFunc("POST /policy/proposals", agentJSON(m, key, func(r *http.Request, input proposalInput, base policyBase, p principal) (any, error) {
		return m.proposePolicy(r.Context(), base, p, input)
	}))
}
