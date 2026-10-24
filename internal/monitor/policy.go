package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/pmezard/go-difflib/difflib"
	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/internal/config"
	"github.com/tinfoilsh/monitor/internal/store"
)

// prepareCandidate validates source without publishing anything.
func (m *monitor) prepareCandidate(ctx context.Context, source string, secrets store.Secrets) (store.Document, *state, error) {
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
			var raw json.RawMessage
			if change.Value != nil {
				raw, _ = json.Marshal(change.Value)
			}
			secrets.Set(id, raw)
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
	next, st, err := m.prepareCandidate(ctx, source, secrets)
	if err != nil {
		return err
	}
	for id, raw := range secrets.All() {
		if next.Secrets.Get(id) == nil && !bytes.Equal(raw, m.store.Doc.Secrets.Get(id)) {
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
