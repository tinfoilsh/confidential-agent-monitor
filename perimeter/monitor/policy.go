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
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/internal/authz"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/internal/config"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/internal/store"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/internal/tomledit"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/policy"
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
func (m *Monitor) writeSettings(ctx context.Context, w settingsWrite) error {
	if m.policy != nil && (w.source != nil || len(w.changes) != 0) {
		return errPolicyFile
	}
	m.mu.Lock()
	source, current, err := m.store.Doc.Policy, m.settings.Load(), w.checked()
	m.mu.Unlock()
	if err != nil {
		return err
	}
	before := source
	if w.source != nil {
		source = *w.source
	}
	source, rebuild, renamed, err := current.Edit(source, w.changes)
	if err != nil {
		return err
	}
	plan, err := m.prepareSettings(ctx, source, rebuild, renamed, w.credentials, current.Env)
	if err != nil {
		return err
	}
	m.mu.Lock()
	if err = w.checked(); err == nil {
		err = m.commitSettings(ctx, plan, w.saved)
	}
	if source != before || len(w.credentials) != 0 {
		m.recordAdmin(ctx, "Change settings", map[string]any{"policy": policyDiff{SourceDiff: sourceDiff(before, source)}, "credentials": slices.Sorted(maps.Keys(w.credentials))}, err)
	}
	m.mu.Unlock()
	if err == nil {
		m.table.Start()
	}
	return err
}

var errPolicyConflict = httpError{errors.New("policy changed; reload it and review a new diff before applying"), http.StatusConflict}

var errPolicyFile = refused("the policy is loaded from a file; change it there")

// reviewed checks, under mu, that an owner write naming a revision was made against current settings.
func (m *Monitor) reviewed(revision *uint64) func() error {
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

func (m *Monitor) previewPolicy(ctx context.Context, base store.Document, before *settings, source string) (*policyDiff, error) {
	source, _, _, err := before.Edit(source, nil)
	if err != nil {
		return nil, err
	}
	plan, err := m.prepareSettings(ctx, source, everyConnector, nil, nil, before.Env)
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

func receipt(r *record) proposalReceipt {
	return proposalReceipt{ID: r.ID, State: r.State, Connection: summarize(r.Record).Facts.Connection}
}

// proposal renders p's changes to one connection against source for review under st. It
// fails when they no longer apply, change nothing, or p may not propose them.
func (m *Monitor) proposal(st *settings, source string, p config.Principal, target, reason string, changes []config.Change) (string, json.RawMessage, error) {
	current, ok := m.identities.Lookup(p.Key)
	if !ok || !current.Same(p) {
		return "", nil, errNoAgent
	}
	if _, err := config.ProposalChanges(p, changes, st.Capable(current, capabilityPropose)); err != nil {
		return "", nil, err
	}
	candidate, _, _, err := st.Edit(source, changes)
	if err == nil && candidate == source {
		err = errors.New("proposal does not change policy")
	}
	if err != nil {
		return "", nil, err
	}
	raw, err := json.Marshal(facts.Facts{Version: facts.Version, Principal: p, Connection: target,
		Service: "policy-proposal", Title: reason, Parameters: map[string]any{},
		Details: map[string]any{"policy": policyDiff{SourceDiff: sourceDiff(source, candidate)}}})
	return candidate, raw, err
}

// proposePolicy publishes one pending record per connection, or none if any fails.
// The owner answers it like a request; approval writes its changes.
func (m *Monitor) proposePolicy(ctx context.Context, key string, input proposalInput) ([]proposalReceipt, error) {
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
		if changes, err = tomledit.Fragment(input.Source); err != nil {
			return nil, err
		}
		for _, path := range input.Delete {
			changes = append(changes, config.Change{Path: path, Delete: true})
		}
	}
	if len(changes) == 0 || len(changes) > maxProposalChanges {
		return nil, fmt.Errorf("proposal must contain 1-%d changes", maxProposalChanges)
	}
	if m.policy != nil {
		return nil, errPolicyFile
	}
	m.writes.Lock()
	defer m.writes.Unlock()
	base, before := m.snapshot()
	p, known := m.identities.Lookup(key)
	if !known {
		return nil, errNoAgent
	}
	groups, err := config.ProposalChanges(p, changes, before.Capable(p, capabilityPropose))
	if err != nil {
		return nil, err
	}
	var proposals []*record
	for _, target := range slices.Sorted(maps.Keys(groups)) {
		candidate, raw, err := m.proposal(before, base.Policy, p, target, reason, groups[target])
		if err == nil {
			_, err = m.prepareSettings(ctx, candidate, everyConnector, nil, nil, before.Env)
		}
		if err != nil {
			return nil, fmt.Errorf("service %s: %w", target, err)
		}
		proposals = append(proposals, &record{Changes: groups[target], Record: &authz.Record{Facts: raw,
			Decision: authz.Decision{Requirements: []authz.Requirement{{ID: "policy", Message: reason}}}}})
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	// A principal has one pending proposal per connection; a new one replaces it.
	var replaced []*record
	pending := len(proposals)
	for _, r := range m.records {
		if r.State != authz.StatePending || r.Changes == nil {
			continue
		}
		f := summarize(r.Record).Facts
		if _, again := groups[f.Connection]; again && f.Principal.Same(p) {
			replaced = append(replaced, r)
		} else {
			pending++
		}
	}
	if pending > maxPolicyProposals {
		return nil, errors.New("too many pending policy proposals")
	}
	for _, r := range replaced {
		m.outdateRecord(r)
	}
	receipts := make([]proposalReceipt, 0, len(proposals))
	for _, proposal := range proposals {
		m.gate.Request(m.addRecord(proposal).Record)
		receipts = append(receipts, receipt(proposal))
	}
	return receipts, nil
}

// Capabilities that policy grants an identity; its stored routes flag grants each.
const (
	capabilityConfig  = "config"
	capabilityPropose = "propose"
)

// Capable reports whether policy grants p capability, refusing it when policy fails.
func (st *settings) Capable(p config.Principal, capability string) bool {
	ok, err := policy.Eval[bool](context.Background(), st.Engine, "capable", capabilityInput{Principal: p, Routes: st.Identities[p.Name].Operator, Capability: capability})
	return ok && err == nil
}

type identityEnrollment struct {
	Key      string `json:"key"`
	Operator bool   `json:"routes"`
	Restore  bool   `json:"restore"`
	// Attributes are the enrollment's other keys.
	Attributes map[string]json.RawMessage `json:",embed"`
}

// enrollmentChanges adds new identities; a revoked key or route access returns only when restored.
// The caller holds mu.
func (m *Monitor) enrollmentChanges(input map[string]identityEnrollment) ([]config.Change, error) {
	var changes []config.Change
	for name, id := range input {
		fingerprint, err := config.Fingerprint(id.Key)
		if err != nil {
			return nil, err
		}
		attributes := map[string]any{}
		for key, raw := range id.Attributes {
			if m.attributes[key] == nil {
				return nil, fmt.Errorf("an enrollment has no field %s", key)
			}
			if attributes[key], err = facts.JSON[any](raw); err != nil {
				return nil, err
			}
		}
		maps.DeleteFunc(attributes, func(_ string, value any) bool { return value == nil })
		if principal, ok := m.settings.Load().Config.Principal(fingerprint); ok {
			existing := m.settings.Load().Identities[principal.Name]
			if id.Operator && !existing.Operator {
				if !id.Restore {
					return nil, errors.New("device route access was revoked")
				}
				changes = append(changes, config.Change{Path: []string{"identities", principal.Name, "routes"}, Value: true})
			}
			for key, value := range attributes {
				if before, _ := facts.JSON[any](existing.Attributes[key]); !reflect.DeepEqual(value, before) {
					changes = append(changes, config.Change{Path: []string{"identities", principal.Name, key}, Value: value})
				}
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
		maps.Copy(value, attributes)
		changes = append(changes, config.Change{Path: []string{"identities", name}, Value: value})
	}
	return changes, nil
}

// Owner unlock may restore its device; ordinary enrollment still honors revocation.
// Authentication and unlocking precede this independent settings write.
func (m *Monitor) restoreDevice(ctx context.Context, public string) error {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(public))
	if err != nil {
		return fmt.Errorf("device public key: %w", err)
	}
	public = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	digest := sha256.Sum256([]byte(public))
	return m.enroll(ctx, map[string]identityEnrollment{fmt.Sprintf("device-%x", digest[:8]): {Key: public, Operator: true, Restore: true}})
}

func (m *Monitor) enroll(ctx context.Context, identities map[string]identityEnrollment) error {
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
func (m *Monitor) viewAfter(r *http.Request, err error) (ownerView, error) {
	if err != nil {
		return ownerView{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.view(r)
}
