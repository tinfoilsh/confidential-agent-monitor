package monitor

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/internal/config"
	"github.com/tinfoilsh/monitor/internal/policy"
	"github.com/tinfoilsh/monitor/internal/store"
)

type proposalState string

const (
	proposalPending   proposalState = "pending"
	proposalApproving proposalState = "approving"

	maxProposalBytes          = 64 << 10
	maxProposalReason         = 4096
	maxProposalDeletes        = 64
	maxProposalChanges        = 256
	maxPolicyProposals        = 32
	maxStoredProposalBytes    = 256 << 10
	maxProposalIdempotencyKey = 200
)

type proposalInput struct {
	Source         string          `json:"source,omitempty"`
	Changes        []config.Change `json:"changes,omitempty"`
	Reason         string          `json:"reason"`
	Delete         [][]string      `json:"delete,omitempty"`
	IdempotencyKey string          `json:"idempotency_key,omitempty"`
}

type proposalDecision struct {
	Digest string `json:"digest"`
}

// Active proposals and their transitions are process-local. Terminal outcomes are
// recorded in the audit log.
type policyProposal struct {
	ID              string
	State           proposalState
	Digest          string
	BaseScopeDigest string
	IdempotencyKey  string
	CreatedAt       string
	Reason          string
	Proposer        facts.Principal
	ProposerKind    string
	Connection      string
	Changes         json.RawMessage
	SourceDiff      string
	Affected        []proposalArea
}

type proposalArea struct {
	Kind   string `json:"kind"`
	Target string `json:"target,omitempty"`
}

type proposalView struct {
	ID           string          `json:"id"`
	State        proposalState   `json:"state"`
	Digest       string          `json:"digest"`
	CreatedAt    string          `json:"created_at"`
	Reason       string          `json:"reason"`
	Proposer     facts.Principal `json:"proposer"`
	ProposerKind string          `json:"proposer_kind"`
	Connection   string          `json:"connection"`
	Affected     []proposalArea  `json:"affected"`
	Changes      []config.Change `json:"changes"`
	SourceDiff   string          `json:"source_diff"`
	Stale        bool            `json:"stale,omitempty"`
}

type proposalReceipt struct {
	ID           string        `json:"id"`
	Digest       string        `json:"digest"`
	State        proposalState `json:"state"`
	Connection   string        `json:"connection"`
	ProposerKind string        `json:"proposer_kind"`
}

type proposalMissing struct{ error }

func (proposalMissing) HTTPStatus() int { return 404 }

type proposalConflict struct{ error }

func (proposalConflict) HTTPStatus() int { return 409 }

func policyDigest(source string) string {
	sum := sha256.Sum256([]byte(source))
	return hex.EncodeToString(sum[:])
}

func storedProposalDigest(p policyProposal) string {
	raw, _ := json.Marshal([]any{
		p.BaseScopeDigest, p.Reason, p.Proposer, p.ProposerKind, p.Connection,
		json.RawMessage(p.Changes), p.SourceDiff,
	})
	return policyDigest(string(raw))
}

func randomProposalID() (string, error) {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func populatedProposalValue(value any) bool {
	switch x := value.(type) {
	case nil:
		return false
	case string:
		return x != ""
	case map[string]any:
		for _, child := range x {
			if populatedProposalValue(child) {
				return true
			}
		}
		return false
	case []any:
		for _, child := range x {
			if populatedProposalValue(child) {
				return true
			}
		}
		return false
	default:
		return true
	}
}

func containsProposalCredential(value any) bool {
	switch x := value.(type) {
	case map[string]any:
		credentialField := false
		for key, child := range x {
			if strings.EqualFold(key, "secret") {
				credentialField, _ = child.(bool)
			}
		}
		for key, child := range x {
			if strings.EqualFold(key, "secrets") && populatedProposalValue(child) {
				return true
			}
			if credentialField && (strings.EqualFold(key, "default") || strings.EqualFold(key, "value")) && populatedProposalValue(child) {
				return true
			}
			if containsProposalCredential(child) {
				return true
			}
		}
	case []any:
		for _, child := range x {
			if containsProposalCredential(child) {
				return true
			}
		}
	}
	return false
}

// proposalMCPPin finds MCP approval snapshots in both leaf edits and parent
// replacements. Tool definitions must pass through the dedicated MCP review.
func proposalMCPPin(path []string, value any) bool {
	inMCP := false
	for _, segment := range path {
		if inMCP && strings.EqualFold(segment, "pin") {
			return true
		}
		inMCP = strings.EqualFold(segment, "mcp")
	}
	var contains func(any, bool) bool
	contains = func(value any, inMCP bool) bool {
		switch x := value.(type) {
		case map[string]any:
			for key, child := range x {
				if inMCP && strings.EqualFold(key, "pin") {
					return true
				}
				if contains(child, inMCP || strings.EqualFold(key, "mcp")) {
					return true
				}
			}
		case []any:
			for _, child := range x {
				if contains(child, inMCP) {
					return true
				}
			}
		}
		return false
	}
	return contains(value, inMCP)
}

// connectionProposalTarget limits proposals to the three connection-owned roots.
// Additional validation below restricts security-sensitive descendants and callers.
func connectionProposalTarget(path []string) (string, bool) {
	switch {
	case len(path) >= 2 && path[0] == "accounts" && path[1] != "":
		return path[1], true
	case len(path) >= 2 && path[0] == "default_access" && path[1] != "":
		return path[1], true
	case len(path) >= 4 && path[0] == "identities" && path[1] != "" && path[2] == "accounts" && path[3] != "":
		return path[3], true
	default:
		return "", false
	}
}

func proposalChanges(input proposalInput) ([]config.Change, error) {
	rawInput, err := json.Marshal(input)
	if err != nil {
		return nil, err
	}
	if len(rawInput) > maxProposalBytes {
		return nil, fmt.Errorf("proposal must be at most %d bytes", maxProposalBytes)
	}
	if strings.TrimSpace(input.Reason) == "" || len(input.Reason) > maxProposalReason {
		return nil, fmt.Errorf("proposal reason must contain 1-%d bytes", maxProposalReason)
	}
	if len(input.Source) > maxProposalBytes || len(input.Delete) > maxProposalDeletes || len(input.Changes) > maxProposalChanges || len(input.IdempotencyKey) > maxProposalIdempotencyKey {
		return nil, errors.New("proposal exceeds its source, change, deletion, or idempotency limit")
	}
	sourceMode := input.Source != "" || input.Delete != nil
	changesMode := input.Changes != nil
	if sourceMode == changesMode {
		return nil, errors.New("proposal requires exactly one of a TOML fragment or structured changes")
	}
	changes := input.Changes
	if sourceMode {
		changes, err = config.Fragment(input.Source)
		if err != nil {
			return nil, err
		}
		for _, path := range input.Delete {
			changes = append(changes, config.Change{Path: path, Delete: true})
		}
	}
	if len(changes) == 0 || len(changes) > maxProposalChanges {
		return nil, fmt.Errorf("proposal must contain 1-%d changes", maxProposalChanges)
	}
	for _, change := range changes {
		if _, allowed := connectionProposalTarget(change.Path); !allowed {
			return nil, errors.New("proposals may change only connection configuration and connection access")
		}
		if change.Delete && change.Value != nil {
			return nil, errors.New("a deletion cannot have a value")
		}
		credentialPath := false
		for _, segment := range change.Path {
			credentialPath = credentialPath || strings.EqualFold(segment, "secrets")
		}
		if _, credential := credentialID(change.Path); credential || credentialPath || containsProposalCredential(change.Value) {
			return nil, errors.New("credentials cannot be proposed; configure them through owner account settings after approval")
		}
		if proposalMCPPin(change.Path, change.Value) {
			return nil, errors.New("MCP tool approvals cannot be proposed; review discovered tools separately after approving the connection")
		}
	}
	return changes, nil
}

func authorizeProposalChanges(proposer facts.Principal, kind string, changes []config.Change) error {
	if kind != "sandbox" {
		return nil
	}
	for _, change := range changes {
		switch change.Path[0] {
		case "accounts":
			// Sandboxes may request shared setup; an owner still reviews the change.
		case "identities":
			if change.Path[1] != proposer.Name {
				return errors.New("a sandbox may propose access changes only for itself")
			}
		case "default_access":
			return errors.New("only a trusted device may propose default access changes")
		}
	}
	return nil
}

// normalizeProposalChanges applies each submitted edit to the candidate in order
// and retains only edits that actually change its source. The resulting list is
// what the owner reviews, approves and later sees in the audit record.
func normalizeProposalChanges(source string, changes []config.Change) (string, []config.Change, error) {
	return config.EditSourceNormalized(source, changes)
}

func splitProposalChanges(changes []config.Change) map[string][]config.Change {
	groups := map[string][]config.Change{}
	for _, change := range changes {
		target, _ := connectionProposalTarget(change.Path)
		groups[target] = append(groups[target], change)
	}
	return groups
}

// connectionScopeDigest binds the state one proposal may change. Identity-specific
// edits additionally bind the target name to its key, so a grant cannot move to a
// replacement principal while pending. Saved rules are included because account
// changes can invalidate their reviewed definitions.
func connectionScopeDigest(cfg *config.Config, connection string, changes []config.Change) string {
	account, accountExists := cfg.Accounts[connection]
	fallback, fallbackExists := cfg.DefaultAccess[connection]
	var preset json.RawMessage
	if accountExists {
		if resolved, err := cfg.Preset(account.Preset); err == nil {
			preset = resolved.Source
		}
	}
	targeted := map[string]bool{}
	for _, change := range changes {
		if len(change.Path) >= 4 && change.Path[0] == "identities" && change.Path[2] == "accounts" && change.Path[3] == connection {
			targeted[change.Path[1]] = true
		}
	}
	identities := map[string]any{}
	for name, identity := range cfg.Identities {
		access := cfg.Access(name, connection)
		rules := map[string]config.Rule{}
		for id, rule := range identity.Rules {
			if rule.Account == connection {
				rules[id] = rule
			}
		}
		if access.Level != "" || len(rules) != 0 || targeted[name] {
			key := ""
			if targeted[name] {
				key = identity.Key
			}
			identities[name] = []any{key, access, identity.Effects, rules}
		}
	}
	for name := range targeted {
		if _, exists := cfg.Identities[name]; !exists {
			identities[name] = []any{"", config.Access{}, nil, nil}
		}
	}
	// These global inputs can change this connection's effective behavior. Another
	// account cannot stale it, but a global policy change appropriately does.
	global := []any{cfg.Effects, cfg.AllowPaidInference, cfg.Lattices, cfg.AllowNetworks, cfg.Policies, cfg.Data}
	raw, _ := json.Marshal([]any{accountExists, account, preset, fallbackExists, fallback, identities, global})
	return policyDigest(string(raw))
}

func proposalScopeDigest(cfg *config.Config, proposal policyProposal) string {
	var changes []config.Change
	_ = json.Unmarshal(proposal.Changes, &changes)
	return connectionScopeDigest(cfg, proposal.Connection, changes)
}

func proposalViewOf(p policyProposal, stale bool) proposalView {
	var changes []config.Change
	_ = json.Unmarshal(p.Changes, &changes)
	return proposalView{
		ID: p.ID, State: p.State, Digest: p.Digest, CreatedAt: p.CreatedAt, Reason: p.Reason,
		Proposer: p.Proposer, ProposerKind: p.ProposerKind, Connection: p.Connection,
		Affected: p.Affected, Changes: changes, SourceDiff: p.SourceDiff,
		Stale: stale,
	}
}

func proposalReceiptOf(p policyProposal) proposalReceipt {
	return proposalReceipt{
		ID: p.ID, Digest: p.Digest, State: p.State, Connection: p.Connection,
		ProposerKind: p.ProposerKind,
	}
}

func sameProposalSubmission(a, b policyProposal) bool {
	return a.BaseScopeDigest == b.BaseScopeDigest && a.Reason == b.Reason &&
		a.Proposer == b.Proposer && a.ProposerKind == b.ProposerKind &&
		a.Connection == b.Connection && bytes.Equal(a.Changes, b.Changes)
}

func proposalCallerKind(before *settings, proposer facts.Principal) string {
	if proposer.Key == "" {
		return "owner_api"
	}
	if before.Config.Identities[proposer.Name].Routes {
		return "trusted_device"
	}
	return "sandbox"
}

func (m *monitor) buildPolicyProposal(ctx context.Context, base store.Document, before *settings, proposer facts.Principal, kind, connection, reason, idempotency string, changes []config.Change) (policyProposal, error) {
	candidate, normalized, err := normalizeProposalChanges(base.Policy, changes)
	if err != nil {
		return policyProposal{}, err
	}
	if candidate == base.Policy {
		return policyProposal{}, errors.New("proposal does not change policy")
	}
	diff, err := m.previewPolicy(ctx, base, before, candidate)
	if err != nil {
		return policyProposal{}, err
	}
	id, err := randomProposalID()
	if err != nil {
		return policyProposal{}, err
	}
	rawChanges, err := json.Marshal(normalized)
	if err != nil {
		return policyProposal{}, err
	}
	proposal := policyProposal{
		ID: id, State: proposalPending, BaseScopeDigest: connectionScopeDigest(before.Config, connection, normalized),
		IdempotencyKey: idempotency, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Reason: strings.TrimSpace(reason), Proposer: proposer, ProposerKind: kind,
		Connection: connection, Changes: rawChanges, SourceDiff: diff.SourceDiff,
		Affected: []proposalArea{{Kind: "connection", Target: connection}},
	}
	if stored, err := json.Marshal(proposal); err != nil {
		return policyProposal{}, err
	} else if len(stored) > maxStoredProposalBytes {
		return policyProposal{}, errors.New("resolved proposal is too large")
	}
	proposal.Digest = storedProposalDigest(proposal)
	return proposal, nil
}

// submitPolicyProposals validates every split candidate before publishing all new
// pending proposals in memory. A crash/restart intentionally discards them.
func (m *monitor) submitPolicyProposals(ctx context.Context, proposer facts.Principal, input proposalInput) ([]policyProposal, error) {
	changes, err := proposalChanges(input)
	if err != nil {
		return nil, err
	}
	groups := splitProposalChanges(changes)
	targets := mapsKeys(groups)
	slices.Sort(targets)

	m.writes.Lock()
	defer m.writes.Unlock()
	base, before := m.snapshot()
	if proposer.Key != "" {
		current, ok := before.Principal(proposer.Key)
		if !ok || current.Name != proposer.Name {
			return nil, errNoAgent
		}
	}
	kind := proposalCallerKind(before, proposer)
	if err := authorizeProposalChanges(proposer, kind, changes); err != nil {
		return nil, err
	}
	proposals := make([]policyProposal, 0, len(targets))
	for _, target := range targets {
		idempotency := ""
		if input.IdempotencyKey != "" {
			idempotency = policyDigest(input.IdempotencyKey + "\x00" + target)
		}
		proposal, err := m.buildPolicyProposal(ctx, base, before, proposer, kind, target, input.Reason, idempotency, groups[target])
		if err != nil {
			return nil, fmt.Errorf("connection %s: %w", target, err)
		}
		proposals = append(proposals, proposal)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]policyProposal, 0, len(proposals))
	newCount := 0
	for _, proposal := range proposals {
		var matched *policyProposal
		for _, existing := range m.proposals {
			if proposal.IdempotencyKey != "" && existing.IdempotencyKey == proposal.IdempotencyKey && existing.Proposer == proposer {
				if !sameProposalSubmission(existing, proposal) {
					return nil, proposalConflict{fmt.Errorf("idempotency key belongs to a different proposal for %s", proposal.Connection)}
				}
				copy := existing
				matched = &copy
				break
			}
			if existing.Digest == proposal.Digest {
				copy := existing
				matched = &copy
				break
			}
		}
		if matched != nil {
			result = append(result, *matched)
			continue
		}
		result = append(result, proposal)
		newCount++
	}
	if len(m.proposals)+newCount > maxPolicyProposals {
		return nil, errors.New("too many pending policy proposals")
	}
	for _, proposal := range result {
		if _, exists := m.proposals[proposal.ID]; !exists {
			m.proposals[proposal.ID] = proposal
		}
	}
	return result, nil
}

// mapsKeys avoids a package-wide maps import for one deterministic grouping.
func mapsKeys[V any](values map[string]V) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	return keys
}

func (m *monitor) policyProposals() []proposalView {
	m.mu.Lock()
	defer m.mu.Unlock()
	result := make([]proposalView, 0, len(m.proposals))
	for _, proposal := range m.proposals {
		stale := proposal.State == proposalPending && proposalScopeDigest(m.settings.Load().Config, proposal) != proposal.BaseScopeDigest
		result = append(result, proposalViewOf(proposal, stale))
	}
	slices.SortFunc(result, func(a, b proposalView) int {
		if order := strings.Compare(a.CreatedAt, b.CreatedAt); order != 0 {
			return order
		}
		return strings.Compare(a.ID, b.ID)
	})
	return result
}

func (m *monitor) policyProposalView(id string) (proposalView, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	proposal, ok := m.proposals[id]
	if !ok {
		return proposalView{}, proposalMissing{errors.New("policy proposal not found")}
	}
	stale := proposal.State == proposalPending && proposalScopeDigest(m.settings.Load().Config, proposal) != proposal.BaseScopeDigest
	return proposalViewOf(proposal, stale), nil
}

func (m *monitor) beginPolicyProposalApproval(id string, decision proposalDecision) (policyProposal, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	proposal, ok := m.proposals[id]
	if !ok {
		return proposal, proposalMissing{errors.New("policy proposal not found")}
	}
	if err := checkProposalDecision(proposal, decision); err != nil {
		return proposal, err
	}
	if proposal.State != proposalPending {
		return proposal, proposalConflict{errors.New("policy proposal is already being applied")}
	}
	proposal.State = proposalApproving
	m.proposals[id] = proposal
	return proposal, nil
}

func (m *monitor) restorePolicyProposalPending(proposal policyProposal) {
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.proposals[proposal.ID]
	if ok && current.Digest == proposal.Digest && current.State == proposalApproving {
		current.State = proposalPending
		m.proposals[proposal.ID] = current
	}
}

func checkProposalDecision(proposal policyProposal, decision proposalDecision) error {
	if decision.Digest == "" || decision.Digest != proposal.Digest || storedProposalDigest(proposal) != proposal.Digest {
		return proposalConflict{errors.New("policy proposal changed; review it again")}
	}
	return nil
}

func decodeProposalChanges(proposal policyProposal) ([]config.Change, error) {
	var changes []config.Change
	if err := json.Unmarshal(proposal.Changes, &changes); err != nil {
		return nil, err
	}
	for _, change := range changes {
		if target, allowed := connectionProposalTarget(change.Path); !allowed || target != proposal.Connection {
			return nil, errors.New("stored proposal exceeds its connection scope")
		}
	}
	return changes, nil
}

// expireStaleProposals consumes pending proposals whose reviewed connection
// context changed after a successful settings write. A proposal being applied owns
// the write that changed its scope and completes its own terminal transition.
func (m *monitor) expireStaleProposals() {
	cfg := m.settings.Load().Config
	var outdated []policyProposal
	m.mu.Lock()
	for id, proposal := range m.proposals {
		if proposal.State == proposalPending && proposalScopeDigest(cfg, proposal) != proposal.BaseScopeDigest {
			delete(m.proposals, id)
			outdated = append(outdated, proposal)
		}
	}
	m.mu.Unlock()
	for _, proposal := range outdated {
		m.recordPolicyProposalOutdated(proposal)
	}
}

func (m *monitor) proposalDecisionFacts(proposal policyProposal) (json.RawMessage, error) {
	raw, _, err := facts.Encode(facts.Facts{
		Version: facts.Version, Principal: proposal.Proposer,
		Account: proposal.Connection, Connection: proposal.Connection,
		Service: "policy-proposal", Title: proposal.Reason,
		Parameters: map[string]any{"connection": proposal.Connection},
		Details: map[string]any{"policy": map[string]any{
			"source_diff": proposal.SourceDiff,
		}},
	})
	return raw, err
}

func (m *monitor) consumeOutdatedProposal(proposal policyProposal) {
	m.mu.Lock()
	current, ok := m.proposals[proposal.ID]
	if ok && current.Digest == proposal.Digest {
		delete(m.proposals, proposal.ID)
	}
	m.mu.Unlock()
	if ok && current.Digest == proposal.Digest {
		m.recordPolicyProposalOutdated(proposal)
	}
}

func (m *monitor) recordPolicyProposalOutdated(proposal policyProposal) {
	raw, err := m.proposalDecisionFacts(proposal)
	if err != nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	record := m.addRecord(&record{
		Facts: raw,
		Decision: policy.Decision{Requirements: []policy.Requirement{{
			ID: "policy.outdated", Message: "Settings affecting this connection changed before the proposal was reviewed.",
		}}},
	})
	record.State = stateOutdated
	m.settleRecord(record, nil)
}

func (m *monitor) recordPolicyProposalDecision(proposal policyProposal, approved bool) {
	raw, err := m.proposalDecisionFacts(proposal)
	if err != nil {
		return
	}
	choice, state := answerDeny, stateDenied
	if approved {
		choice, state = answerOnce, stateApproved
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	record := m.addRecord(&record{
		Facts:    raw,
		Decision: policy.Decision{Requirements: []policy.Requirement{{ID: "policy", Message: proposal.Reason}}},
		Reviews:  []reviewAnswer{{By: "owner", answerInput: answerInput{Choice: choice}, Time: time.Now()}},
	})
	record.State = state
	m.settleRecord(record, nil)
}

func (m *monitor) rejectPolicyProposal(_ context.Context, id string, decision proposalDecision) error {
	m.writes.Lock()
	defer m.writes.Unlock()
	m.mu.Lock()
	proposal, ok := m.proposals[id]
	if !ok {
		m.mu.Unlock()
		return proposalMissing{errors.New("policy proposal not found")}
	}
	if err := checkProposalDecision(proposal, decision); err != nil {
		m.mu.Unlock()
		return err
	}
	if proposal.State != proposalPending {
		m.mu.Unlock()
		return proposalConflict{errors.New("policy proposal is already being applied")}
	}
	delete(m.proposals, id)
	m.mu.Unlock()
	m.recordPolicyProposalDecision(proposal, false)
	return nil
}

func (m *monitor) approvePolicyProposal(ctx context.Context, id string, decision proposalDecision) error {
	m.writes.Lock()
	defer m.writes.Unlock()
	proposal, err := m.beginPolicyProposalApproval(id, decision)
	if err != nil {
		return err
	}
	defer m.restorePolicyProposalPending(proposal)
	base, before := m.snapshot()
	if proposalScopeDigest(before.Config, proposal) != proposal.BaseScopeDigest {
		m.consumeOutdatedProposal(proposal)
		return errPolicyConflict
	}
	changes, err := decodeProposalChanges(proposal)
	if err != nil {
		return err
	}
	// Rebase this connection's reviewed changes onto unrelated configuration edits.
	candidate, err := config.EditSource(base.Policy, changes)
	if err != nil {
		return err
	}
	if _, err := m.previewPolicy(ctx, base, before, candidate); err != nil {
		return err
	}
	err = m.writeSettings(ctx, nil, changes, func() error {
		current, ok := m.proposals[id]
		if !ok {
			return proposalMissing{errors.New("policy proposal not found")}
		}
		if current.State != proposalApproving {
			return proposalConflict{errors.New("policy proposal is no longer being applied")}
		}
		if proposalScopeDigest(m.settings.Load().Config, current) != current.BaseScopeDigest {
			return errPolicyConflict
		}
		return checkProposalDecision(current, decision)
	}, nil)
	if err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.proposals, id)
	m.mu.Unlock()
	m.recordPolicyProposalDecision(proposal, true)
	return nil
}
