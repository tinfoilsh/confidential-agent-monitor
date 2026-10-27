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
	"github.com/tinfoilsh/monitor/internal/config"
	"github.com/tinfoilsh/monitor/internal/policy"
	"github.com/tinfoilsh/monitor/internal/store"
	"github.com/tinfoilsh/monitor/internal/tinfoil/sandbox"
	"golang.org/x/crypto/ssh"
)

// writeSettings is the single ordered settings path; writes is held, mu is not.
// check runs under mu before validation and again before persistence. A saved
// approval is answered atomically with the durable settings change.
func (m *monitor) writeSettings(ctx context.Context, source *string, changes []config.Change, check func() error, saved *savedAnswer) error {
	m.mu.Lock()
	if check != nil {
		if err := check(); err != nil {
			m.mu.Unlock()
			return err
		}
	}
	base, env := m.store.Doc, m.settings.Load().Env
	m.mu.Unlock()
	next := base
	next.Secrets = base.Secrets.Clone()
	var edits []config.Change
	for _, change := range changes {
		if change.Delete && change.Value != nil {
			return errors.New("a deletion cannot have a value")
		}
		if id, ok := credentialID(change.Path); ok {
			var raw json.RawMessage
			if change.Value != nil {
				var err error
				if raw, err = json.Marshal(change.Value); err != nil {
					return err
				}
			}
			next.Secrets.Set(id, raw)
		} else {
			edits = append(edits, change)
		}
	}
	var err error
	if source != nil {
		next.Policy = *source
	} else if next.Policy, err = config.EditSource(base.Policy, edits); err != nil {
		return err
	}
	plan, err := m.prepareSettings(ctx, base, next, env)
	if err != nil {
		return err
	}
	for _, change := range changes {
		if id, ok := credentialID(change.Path); ok && next.Secrets.Get(id) != nil && plan.secrets.Get(id) == nil {
			return fmt.Errorf("credential %v has no connection", id)
		}
	}
	m.mu.Lock()
	if check != nil {
		if err := check(); err != nil {
			m.mu.Unlock()
			return err
		}
	}
	install, retired, err := m.commitSettings(ctx, base, plan, saved)
	m.mu.Unlock()
	if err == nil {
		m.installConnections(install, retired)
	}
	return err
}

var errPolicyConflict = errors.New("policy changed; reload it and review a new diff before applying")

// previewPolicy runs under writes and prepares source against base without committing it.
func (m *monitor) previewPolicy(ctx context.Context, base store.Document, before *settings, source string) (*facts.PolicyDiff, error) {
	next := base
	next.Policy = source
	plan, err := m.prepareSettings(ctx, base, next, before.Env)
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
	diff := func(a, b string) string {
		text, _ := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{A: difflib.SplitLines(a), B: difflib.SplitLines(b), FromFile: "active/policy.toml", ToFile: "proposed/policy.toml", Context: 3})
		return text
	}
	return &facts.PolicyDiff{SourceDiff: diff(base.Policy, source), EffectiveDiff: diff(beforeText, afterText)}, nil
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
func (m *monitor) proposePolicy(ctx context.Context, key string, input proposalInput) (err error) {
	if len(input.Source) > maxProposalBytes || len(input.Reason) > maxProposalReason || strings.TrimSpace(input.Reason) == "" || len(input.Delete) > maxProposalDeletes {
		return fmt.Errorf("proposal needs a reason of 1-%d bytes, at most %d bytes of TOML, and at most %d deletions", maxProposalReason, maxProposalBytes, maxProposalDeletes)
	}
	changes, err := config.Fragment(input.Source)
	if err != nil {
		return err
	}
	for _, path := range input.Delete {
		changes = append(changes, config.Change{Path: path, Delete: true})
	}
	m.writes.Lock()
	base, before := m.snapshot()
	next := base
	p, known := before.Principal(key)
	if !known {
		err = errNoAgent
	} else if err = before.AgentChanges(p, changes); err == nil {
		next.Policy, err = config.EditSource(base.Policy, changes)
	}
	if err == nil && next.Policy == base.Policy {
		err = errors.New("proposal does not change policy")
	}
	var diff *facts.PolicyDiff
	if err == nil {
		diff, err = m.previewPolicy(ctx, base, before, next.Policy)
	}
	m.writes.Unlock()
	if err != nil {
		return err
	}
	m.mu.Lock()
	if m.store.Doc.Policy != base.Policy {
		m.mu.Unlock()
		return errPolicyConflict
	}
	raw, _, err := facts.Encode(facts.Facts{Version: facts.Version, Principal: facts.Principal{Key: p.Fingerprint, Name: p.Name}, Title: "Change policy", Parameters: map[string]any{}, Details: map[string]any{"policy": diff}})
	if err != nil {
		m.mu.Unlock()
		return err
	}
	r := m.addRecord(&record{Facts: raw, Decision: policy.Decision{Requirements: []policy.Requirement{{ID: "policy", Message: input.Reason}}}})
	err = m.awaitAnswer(ctx, r)
	m.mu.Unlock()
	if err == nil {
		m.writes.Lock()
		err = m.writeSettings(ctx, &next.Policy, nil, func() error {
			if m.store.Doc.Policy != base.Policy {
				return errPolicyConflict
			}
			return ctx.Err()
		}, nil)
		m.writes.Unlock()
	}
	m.mu.Lock()
	m.settleRecord(r, err)
	m.mu.Unlock()
	return err
}

type identityEnrollment struct {
	Key     string `json:"key"`
	Routes  bool   `json:"routes"`
	Restore bool   `json:"restore"`
	// Sandbox names the boots the Monitor may attest and log in to for shells.
	Sandbox json.RawMessage `json:"sandbox,omitzero"`
}

// enrollmentChanges adds new identities; a revoked key or route access returns only when restored.
// The caller holds mu.
func (m *monitor) enrollmentChanges(input map[string]identityEnrollment) ([]config.Change, error) {
	var changes []config.Change
	for name, id := range input {
		if err := sandbox.ValidateMetadata(id.Sandbox); err != nil {
			return nil, err
		}
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(id.Key))
		if err != nil {
			return nil, err
		}
		fingerprint := ssh.FingerprintSHA256(key)
		metadata, err := facts.JSON[any](id.Sandbox)
		if err != nil {
			return nil, err
		}
		if principal, ok := m.settings.Load().Principal(fingerprint); ok {
			existing := m.settings.Load().Identities[principal.Name]
			if id.Routes && !existing.Routes {
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
			return nil, errors.New("identity was revoked; restore access explicitly in Monitor")
		}
		if _, exists := m.settings.Load().Config.Identities[name]; exists {
			return nil, errors.New("identity name belongs to another key")
		}
		value := map[string]any{"key": id.Key, "routes": id.Routes}
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
	return m.enroll(ctx, map[string]identityEnrollment{fmt.Sprintf("device-%x", digest[:8]): {Key: public, Routes: true, Restore: true}})
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
	return m.writeSettings(ctx, nil, changes, nil, nil)
}

// IdentityMetadata returns the sandbox metadata validated during settings preparation.
func (m *monitor) IdentityMetadata(name string) json.RawMessage {
	return bytes.Clone(m.settings.Load().Identities[name].Sandbox)
}
func (m *monitor) CheckIdentity(name, key string, metadata json.RawMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	_, err := m.enrollmentChanges(map[string]identityEnrollment{name: {Key: key, Sandbox: metadata}})
	return err
}
func (m *monitor) AddIdentity(ctx context.Context, name, key string, metadata json.RawMessage) error {
	return m.enroll(ctx, map[string]identityEnrollment{name: {Key: key, Sandbox: metadata}})
}

// viewAfter renders the owner view once an action that ran without mu succeeds.
func (m *monitor) viewAfter(err error) (any, error) {
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.view()
}
