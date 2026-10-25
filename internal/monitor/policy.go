package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/pmezard/go-difflib/difflib"
	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/internal/config"
	"github.com/tinfoilsh/monitor/internal/policy"
	"github.com/tinfoilsh/monitor/internal/store"
)

// candidate validates source without publishing anything.
func (m *monitor) candidate(ctx context.Context, source string, secrets store.Secrets) (store.Document, *state, error) {
	next := m.store.Doc
	next.Policy = source
	next.Secrets = secrets
	if secrets == nil {
		next.Secrets = m.store.Doc.Secrets
	}
	st, err := m.build(ctx, &next, m.live.Load().Env, m.live.Load())
	return next, st, err
}

func (m *monitor) editPolicy(ctx context.Context, changes []config.Change) error {
	if len(changes) == 0 {
		return nil
	}
	secrets := m.store.Doc.Secrets.Clone()
	var edits []config.Change
	for _, change := range changes {
		if len(change.Path) == 0 {
			return errors.New("an edit requires a source path")
		}
		if change.Delete && change.Value != nil {
			return errors.New("a deletion cannot have a value")
		}
		// Credentials live in the sealed store; removing a connection drops its own.
		if id, ok := credentialID(change.Path); ok {
			delete(secrets, id)
			if change.Value != nil {
				secrets[id], _ = json.Marshal(change.Value)
			}
			continue
		}
		if !change.Delete {
			var err error
			if change.Value, err = config.TOMLValue(change.Value); err != nil {
				return err
			}
		}
		// Replacing a table key by key gives it [header] sections instead of one inline line.
		if table, ok := change.Value.(map[string]any); ok && len(table) > 0 && table["$json"] == nil {
			edits = append(edits, config.Change{Path: change.Path, Delete: true})
			edits = append(edits, config.FragmentChanges(table, change.Path)...)
			continue
		}
		edits = append(edits, change)
	}
	source, err := config.EditSource(m.store.Doc.Policy, edits)
	if err != nil {
		return err
	}
	// Preparation drops credentials without a connection, so compare against what this edit wrote.
	next, st, err := m.candidate(ctx, source, secrets)
	if err != nil {
		return err
	}
	for id, raw := range secrets {
		if next.Secrets[id] == nil && !bytes.Equal(raw, m.store.Doc.Secrets[id]) {
			return fmt.Errorf("credential %v has no connection", id)
		}
	}
	return m.activate(ctx, next, st)
}

var errPolicyConflict = errors.New("policy changed; reload it and review a new diff before applying")

func (m *monitor) policyPreview(next store.Document, st *state) (*facts.Policy, error) {
	before, err := m.live.Load().Config.Effective()
	if err != nil {
		return nil, err
	}
	after, err := st.Config.Effective()
	if err != nil {
		return nil, err
	}
	diff := func(a, b string) string {
		text, _ := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{
			A: difflib.SplitLines(a), B: difflib.SplitLines(b),
			FromFile: "active/policy.toml", ToFile: "proposed/policy.toml", Context: 3,
		})
		return text
	}
	return &facts.Policy{SourceDiff: diff(m.store.Doc.Policy, next.Policy), EffectiveDiff: diff(before, after)}, nil
}

const (
	maxProposalBytes   = 64 << 10
	maxProposalReason  = 4096
	maxProposalDeletes = 64
)

type proposalInput struct {
	Source string     `json:"source"`
	Reason string     `json:"reason"`
	Delete [][]string `json:"delete,omitempty"`
}

// proposePolicy holds an agent's change as an approval card and applies it once the owner allows it.
func (m *monitor) proposePolicy(ctx context.Context, p config.Principal, input proposalInput) (err error) {
	if len(input.Source) > maxProposalBytes || len(input.Reason) > maxProposalReason || strings.TrimSpace(input.Reason) == "" || len(input.Delete) > maxProposalDeletes {
		return fmt.Errorf("proposal needs a reason of 1-%d bytes, at most %d bytes of TOML, and at most %d deletions", maxProposalReason, maxProposalBytes, maxProposalDeletes)
	}
	patch, err := config.ReadSource(input.Source)
	if err != nil {
		return err
	}
	changes := config.FragmentChanges(patch, nil)
	for _, path := range input.Delete {
		changes = append(changes, config.Change{Path: path, Delete: true})
	}
	base := m.store.Doc.Policy
	source, err := config.EditSource(base, changes)
	if err != nil {
		return err
	}
	if source == base {
		return errors.New("proposal does not change policy")
	}
	next, st, err := m.candidate(ctx, source, nil)
	if err != nil {
		return err
	}
	_, before, err := m.live.Load().Config.AgentView(p)
	if err != nil {
		return err
	}
	_, after, err := st.Config.AgentView(p)
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
	r := m.addRecord(&record{Facts: &facts.Facts{Version: facts.Version, Principal: facts.Principal{Key: p.Key, Name: p.Name},
		Title: "Change policy", Parameters: map[string]any{}, Details: facts.Details{Policy: diff}},
		Decision: policy.Decision{Requirements: []policy.Requirement{{ID: "policy", Message: input.Reason}}}})
	defer func() { m.settleRecord(r, err) }()
	if err = m.awaitApproval(ctx, r); err != nil {
		return err
	}
	if m.store.Doc.Policy != base {
		return errPolicyConflict
	}
	if next, st, err = m.candidate(ctx, next.Policy, nil); err != nil {
		return err
	}
	return m.activate(ctx, next, st)
}

func (m *monitor) agentPolicy(key string, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	st := m.live.Load()
	p := st.Principals[key]
	visible, _, err := st.Config.AgentView(p)
	if err != nil {
		return nil, err
	}
	source, err := config.RenderTOML(visible)
	return map[string]any{"identity": p.Name, "source": source}, err
}
