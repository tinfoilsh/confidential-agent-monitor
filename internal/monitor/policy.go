package monitor

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"strings"

	"github.com/pmezard/go-difflib/difflib"
	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/internal/config"
	"github.com/tinfoilsh/monitor/internal/policy"
	"github.com/tinfoilsh/monitor/internal/store"
	"golang.org/x/crypto/ssh"
)

// settingsWrite replaces the policy source, or edits it with changes, and stages
// credentials, nil clearing one. check runs under mu before validation and again
// before persistence. A saved approval is answered atomically with the durable change.
type settingsWrite struct {
	source      *string
	changes     []config.Change
	credentials store.Secrets
	check       func() error
	saved       *savedAnswer
}

func (w settingsWrite) checked() error {
	if w.check == nil {
		return nil
	}
	return w.check()
}

// writeSettings is the single ordered settings path; writes is held, mu is not.
func (m *monitor) writeSettings(ctx context.Context, w settingsWrite) error {
	m.mu.Lock()
	source, current, err := m.store.Doc.Policy, m.settings.Load(), w.checked()
	m.mu.Unlock()
	if err != nil {
		return err
	}
	if w.source != nil {
		source = *w.source
	}
	source, rebuild, err := current.Edit(source, w.changes)
	if err != nil {
		return err
	}
	plan, err := m.prepareSettings(ctx, source, rebuild, w.credentials, current.Env)
	if err != nil {
		return err
	}
	m.mu.Lock()
	var install, retired []*connection
	if err = w.checked(); err == nil {
		install, retired, err = m.commitSettings(ctx, plan, w.saved)
	}
	m.mu.Unlock()
	if err == nil {
		m.installConnections(install, retired)
	}
	return err
}

var errPolicyConflict = errors.New("policy changed; reload it and review a new diff before applying")

// reviewed checks, under mu, that an owner write naming a revision was made against current settings.
func (m *monitor) reviewed(revision *uint64) func() error {
	return func() error {
		if revision != nil && *revision != m.store.Doc.Revision {
			return errPolicyConflict
		}
		return nil
	}
}

// policyDiff compares the owner source and its expanded settings.
type policyDiff struct {
	SourceDiff    string `json:"source_diff"`
	EffectiveDiff string `json:"effective_diff"`
}

func sourceDiff(a, b string) string {
	text, _ := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{A: difflib.SplitLines(a), B: difflib.SplitLines(b), FromFile: "active/policy.toml", ToFile: "proposed/policy.toml", Context: 3})
	return text
}

func (m *monitor) previewPolicy(ctx context.Context, base store.Document, before *settings, source string) (*policyDiff, error) {
	source, _, err := before.Edit(source, nil)
	if err != nil {
		return nil, err
	}
	plan, err := m.prepareSettings(ctx, source, everyConnector, nil, before.Env)
	if err != nil {
		return nil, err
	}
	beforeText, err := before.Config.Effective()
	if err != nil {
		return nil, err
	}
	afterText, err := plan.next.Config.Effective()
	if err != nil {
		return nil, err
	}
	return &policyDiff{SourceDiff: sourceDiff(base.Policy, source), EffectiveDiff: sourceDiff(beforeText, afterText)}, nil
}

const (
	maxProposalChanges = 256
	maxPolicyProposals = 32
)

type proposalInput struct {
	Source  string          `json:"source,omitempty"`
	Changes []config.Change `json:"changes,omitempty"`
	Reason  string          `json:"reason"`
	Delete  [][]string      `json:"delete,omitempty"`
}

type proposalReceipt struct {
	ID         string `json:"id"`
	State      string `json:"state"`
	Connection string `json:"connection"`
}

func (r *record) receipt() proposalReceipt {
	return proposalReceipt{ID: r.ID, State: r.State, Connection: r.summary().Facts.Connection}
}

// proposal renders p's changes to one connection against source for review. It
// fails when they no longer apply, change nothing, or p may not propose them.
func (st *settings) proposal(source string, p config.Principal, target, reason string, changes []config.Change) (string, json.RawMessage, error) {
	if current, ok := st.Principal(p.Key); !ok || current != p {
		return "", nil, errNoAgent
	}
	if _, err := st.ProposalChanges(p, changes); err != nil {
		return "", nil, err
	}
	candidate, _, err := st.Edit(source, changes)
	if err == nil && candidate == source {
		err = errors.New("proposal does not change policy")
	}
	if err != nil {
		return "", nil, err
	}
	raw, _, err := facts.Encode(facts.Facts{Version: facts.Version, Principal: p, Connection: target,
		Service: "policy-proposal", Title: reason, Parameters: map[string]any{},
		Details: map[string]any{"policy": policyDiff{SourceDiff: sourceDiff(source, candidate)}}})
	return candidate, raw, err
}

// proposePolicy publishes one pending record per connection, or none if any fails.
// The owner answers it like a request; approval writes its changes.
func (m *monitor) proposePolicy(ctx context.Context, key string, input proposalInput) ([]proposalReceipt, error) {
	reason := strings.TrimSpace(input.Reason)
	if reason == "" || len(reason) > maxReason {
		return nil, fmt.Errorf("proposal needs a reason of 1-%d bytes", maxReason)
	}
	if (input.Source != "" || input.Delete != nil) == (input.Changes != nil) {
		return nil, errors.New("proposal requires exactly one of a TOML fragment or structured changes")
	}
	changes := input.Changes
	if changes == nil {
		var err error
		if changes, err = config.Fragment(input.Source); err != nil {
			return nil, err
		}
		for _, path := range input.Delete {
			changes = append(changes, config.Change{Path: path, Delete: true})
		}
	}
	if len(changes) == 0 || len(changes) > maxProposalChanges {
		return nil, fmt.Errorf("proposal must contain 1-%d changes", maxProposalChanges)
	}
	m.writes.Lock()
	defer m.writes.Unlock()
	base, before := m.snapshot()
	p, known := before.Principal(key)
	if !known {
		return nil, errNoAgent
	}
	groups, err := before.ProposalChanges(p, changes)
	if err != nil {
		return nil, err
	}
	var proposals []*record
	for _, target := range slices.Sorted(maps.Keys(groups)) {
		candidate, raw, err := before.proposal(base.Policy, p, target, reason, groups[target])
		if err == nil {
			_, err = m.prepareSettings(ctx, candidate, everyConnector, nil, before.Env)
		}
		if err != nil {
			return nil, fmt.Errorf("service %s: %w", target, err)
		}
		proposals = append(proposals, &record{Facts: raw, Changes: groups[target],
			Decision: policy.Decision{Requirements: []facts.Requirement{{ID: "policy", Message: reason}}}})
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	// A principal has one pending proposal per connection; a new one replaces it.
	var replaced []*record
	pending := len(proposals)
	for _, r := range m.records {
		if r.State != statePending || r.Changes == nil {
			continue
		}
		f := r.summary().Facts
		if _, again := groups[f.Connection]; again && f.Principal == p {
			replaced = append(replaced, r)
		} else {
			pending++
		}
	}
	if pending > maxPolicyProposals {
		return nil, errors.New("too many pending policy proposals")
	}
	for _, r := range replaced {
		r.State = stateOutdated
		m.settleRecord(r, nil)
	}
	receipts := make([]proposalReceipt, 0, len(proposals))
	for _, proposal := range proposals {
		m.addRecord(proposal)
		proposal.State = statePending
		receipts = append(receipts, proposal.receipt())
	}
	return receipts, nil
}

type identityEnrollment struct {
	Key      string `json:"key"`
	Operator bool   `json:"routes"`
	Restore  bool   `json:"restore"`
	// Sandbox names the sandbox boot an identity belongs to.
	Sandbox json.RawMessage `json:"sandbox,omitzero"`
}

// enrollmentChanges adds new identities; a revoked key or route access returns only when restored.
// The caller holds mu.
func (m *monitor) enrollmentChanges(input map[string]identityEnrollment) ([]config.Change, error) {
	var changes []config.Change
	for name, id := range input {
		fingerprint, err := config.Fingerprint(id.Key)
		if err != nil {
			return nil, err
		}
		metadata, err := facts.JSON[any](id.Sandbox)
		if err != nil {
			return nil, err
		}
		if principal, ok := m.settings.Load().Principal(fingerprint); ok {
			existing := m.settings.Load().Identities[principal.Name]
			if id.Operator && !existing.Operator {
				if !id.Restore {
					return nil, errors.New("device route access was revoked")
				}
				changes = append(changes, config.Change{Path: []string{"identities", principal.Name, "routes"}, Value: true})
			}
			before, _ := facts.JSON[any](existing.Sandbox)
			if metadata != nil && !reflect.DeepEqual(metadata, before) {
				changes = append(changes, config.Change{Path: []string{"identities", principal.Name, "sandbox"}, Value: metadata})
			}
			continue
		}
		if m.store.Doc.Enrolled[fingerprint] && !id.Restore {
			return nil, errors.New("identity was revoked; restore access explicitly in the Perimeter")
		}
		if _, exists := m.settings.Load().Config.Identities[name]; exists {
			return nil, errors.New("identity name belongs to another key")
		}
		value := map[string]any{"key": id.Key, "routes": id.Operator}
		if metadata != nil {
			value["sandbox"] = metadata
		}
		changes = append(changes, config.Change{Path: []string{"identities", name}, Value: value})
	}
	return changes, nil
}

// Owner unlock may restore its device; ordinary enrollment still honors revocation.
// Authentication and unlocking precede this independent settings write.
func (m *monitor) restoreDevice(ctx context.Context, public string) error {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(public))
	if err != nil {
		return fmt.Errorf("device public key: %w", err)
	}
	public = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	digest := sha256.Sum256([]byte(public))
	return m.enroll(ctx, map[string]identityEnrollment{fmt.Sprintf("device-%x", digest[:8]): {Key: public, Operator: true, Restore: true}})
}

func (m *monitor) enroll(ctx context.Context, identities map[string]identityEnrollment) error {
	m.writes.Lock()
	defer m.writes.Unlock()
	m.mu.Lock()
	changes, err := m.enrollmentChanges(identities)
	m.mu.Unlock()
	if err != nil {
		return err
	}
	return m.writeSettings(ctx, settingsWrite{changes: changes})
}

// viewAfter renders the owner view once an action that ran without mu succeeds.
func (m *monitor) viewAfter(r *http.Request, err error) (ownerView, error) {
	if err != nil {
		return ownerView{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.view(r)
}
