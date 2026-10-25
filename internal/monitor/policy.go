package monitor

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"

	"github.com/pmezard/go-difflib/difflib"
	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/internal/policy"
	"github.com/tinfoilsh/monitor/internal/store"
	"golang.org/x/crypto/ssh"
)

func (m *monitor) editPolicy(ctx context.Context, changes []policy.Change) error {
	if len(changes) == 0 {
		return nil
	}
	secrets := m.store.Doc.Secrets.Clone()
	var edits []policy.Change
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
			if change.Value, err = policy.TOMLValue(change.Value); err != nil {
				return err
			}
		}
		// Replacing a table key by key gives it [header] sections instead of one inline line.
		if table, ok := change.Value.(map[string]any); ok && len(table) > 0 && table["$json"] == nil {
			edits = append(edits, policy.Change{Path: change.Path, Delete: true})
			edits = append(edits, policy.FragmentChanges(table, change.Path)...)
			continue
		}
		edits = append(edits, change)
	}
	source, err := policy.EditSource(m.store.Doc.Policy, edits)
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
func (m *monitor) proposePolicy(ctx context.Context, p policy.Principal, input proposalInput) (err error) {
	if len(input.Source) > maxProposalBytes || len(input.Reason) > maxProposalReason || strings.TrimSpace(input.Reason) == "" || len(input.Delete) > maxProposalDeletes {
		return fmt.Errorf("proposal needs a reason of 1-%d bytes, at most %d bytes of TOML, and at most %d deletions", maxProposalReason, maxProposalBytes, maxProposalDeletes)
	}
	patch, err := policy.ReadSource(input.Source)
	if err != nil {
		return err
	}
	changes := policy.FragmentChanges(patch, nil)
	for _, path := range input.Delete {
		changes = append(changes, policy.Change{Path: path, Delete: true})
	}
	base := m.store.Doc.Policy
	source, err := policy.EditSource(base, changes)
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

type identityEnrollment struct {
	Key     string `json:"key"`
	Routes  bool   `json:"routes"`
	Restore bool   `json:"restore"`
	// Sandbox names the boots the Monitor may attest and log in to for shells.
	Sandbox policy.Boot `json:"sandbox,omitzero"`
}

// enrollmentChanges adds new identities; a revoked key or route access returns only when restored.
// The caller holds mu.
func (m *monitor) enrollmentChanges(input map[string]identityEnrollment) ([]policy.Change, error) {
	var changes []policy.Change
	for name, id := range input {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(id.Key))
		if err != nil {
			return nil, err
		}
		fingerprint := ssh.FingerprintSHA256(key)
		var boot map[string]any
		if id.Sandbox != (policy.Boot{}) {
			if err := id.Sandbox.Validate(); err != nil {
				return nil, err
			}
			boot = map[string]any{"source": id.Sandbox.Source, "instance_id": id.Sandbox.InstanceID}
		}
		if existing, ok := m.live.Load().Principals[fingerprint]; ok {
			if id.Routes && !existing.Routes {
				if !id.Restore {
					return nil, errors.New("device route access was revoked")
				}
				changes = append(changes, policy.Change{Path: []string{"identities", existing.Name, "routes"}, Value: true})
			}
			if boot != nil && id.Sandbox != existing.Sandbox {
				changes = append(changes, policy.Change{Path: []string{"identities", existing.Name, "sandbox"}, Value: boot})
			}
			continue
		}
		if m.store.Doc.Enrolled[fingerprint] && !id.Restore {
			return nil, errors.New("identity was revoked; restore access explicitly in Monitor")
		}
		if _, exists := m.live.Load().Config.Identities[name]; exists {
			return nil, errors.New("identity name belongs to another key")
		}
		value := map[string]any{"key": id.Key, "routes": id.Routes}
		if boot != nil {
			value["sandbox"] = boot
		}
		changes = append(changes, policy.Change{Path: []string{"identities", name}, Value: value})
	}
	return changes, nil
}

// Owner unlock may restore its device; ordinary enrollment still honors revocation.
// The caller holds mu after authenticating and unlocking the state.
func (m *monitor) restoreDevice(ctx context.Context, public string) error {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(public))
	if err != nil {
		return fmt.Errorf("device public key: %w", err)
	}
	st := m.live.Load()
	if existing, ok := st.Principals[ssh.FingerprintSHA256(key)]; ok {
		if existing.Routes {
			return nil
		}
		return m.editPolicy(ctx, []policy.Change{{Path: []string{"identities", existing.Name, "routes"}, Value: true}})
	}
	public = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	digest := sha256.Sum256([]byte(public))
	name := fmt.Sprintf("device-%x", digest[:8])
	if _, exists := st.Config.Identities[name]; exists {
		return errors.New("device identity name belongs to another key")
	}
	return m.editPolicy(ctx, []policy.Change{{Path: []string{"identities", name}, Value: map[string]any{"key": public, "routes": true}}})
}

// sandboxMonitor is the Monitor as the sandbox package sees it.
type sandboxMonitor struct{ m *monitor }

func (s sandboxMonitor) Boot(name string) policy.Boot {
	return s.m.live.Load().Config.Identities[name].Sandbox
}

func (s sandboxMonitor) HostKey() ssh.Signer { return s.m.live.Load().HostKey }

func (s sandboxMonitor) CheckIdentity(name, key string, boot policy.Boot) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	_, err := s.m.enrollmentChanges(map[string]identityEnrollment{name: {Key: key, Sandbox: boot}})
	return err
}

func (s sandboxMonitor) AddIdentity(ctx context.Context, name, key string, boot policy.Boot) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	changes, err := s.m.enrollmentChanges(map[string]identityEnrollment{name: {Key: key, Sandbox: boot}})
	if err != nil {
		return err
	}
	return s.m.editPolicy(ctx, changes)
}
