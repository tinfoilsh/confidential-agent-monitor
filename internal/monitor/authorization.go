package monitor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/mcp"
	"github.com/tinfoilsh/monitor/connector/web"
	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/internal/config"
	"github.com/tinfoilsh/monitor/internal/tinfoil/sandboxroute"
)

var (
	errChanged      = errors.New("configuration changed while waiting for approval; retry the request")
	errLabelChanged = errors.New("the agent's security label changed while waiting for approval; retry the request")
	errNoAgent      = errors.New("this agent's identity was removed")
)

// input binds parsed protocol input to its authenticated routing identity.
type input struct {
	stream     *connector.Stream
	Key        string
	Connection string
	Request    connector.Request
}

// gate describes captured input under the authorization lock. Approval waits
// release the lock, so other streams and the opposite direction can progress.
// Once admitted, this operation may finish under its decision.
func (m *monitor) gate(ctx context.Context, in input) (err error) {
	if in.stream != nil {
		if err := in.stream.Context.Err(); err != nil {
			return err
		}
		var cancel context.CancelFunc
		ctx, cancel = connector.Bind(ctx, in.stream.Context)
		defer cancel()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if m.audit.Backlogged() {
		return errAuditBacklog
	}
	st := m.live.Load()
	p, ok := st.Principals[in.Key]
	if !ok {
		return errNoAgent
	}
	c := st.connections[in.Connection]
	if c == nil {
		return errors.New("connection removed")
	}
	a := st.Config.Accounts[c.Account]
	preset := st.Config.Resolved[a.Preset]
	cc := connector.Context{Title: preset.Title, Connection: c.Name, Config: c.Server, Options: a.PolicyOptions}
	switch in.Request.(type) {
	case *web.Request:
		cc.Spec = preset.HTTP
	case *mcp.Request:
		cc.Spec = preset.MCP
	}
	f, describeErr := in.Request.Describe(cc)
	f.Version, f.Account, f.Service, f.Connection = facts.Version, c.Account, a.Preset, c.Name
	if f.Kind == "" {
		f.Kind = facts.KindOperation
	}
	if f.Operation != nil {
		f.Operation = preset.Catalog.Operation(*f.Operation)
	}
	if f.Parameters == nil {
		f.Parameters = map[string]any{}
	}
	if f.Scope == nil {
		f.Scope = f.Parameters
	}
	f.Principal, f.Context.Label = facts.Principal{Key: p.Key, Name: p.Name}, m.currentLabel(p.Key)
	if describeErr != nil {
		f.Operation = nil
		f, _, err := f.Snapshot()
		if err != nil {
			return err
		}
		r := m.addRecord(&record{Facts: &f})
		r.Invalid = true
		m.settleRecord(r, describeErr)
		return describeErr
	}
	// Approval definitions bind semantics and configuration, independently of facts
	// shown to users. Display edits and current labels do not invalidate a grant.
	modes := st.Config.EffectModes(p.Name, c.Account, f.Operation)
	raw, _ := json.Marshal([]any{st.Engine.Program, st.Config.Lattices, modes, f.Kind, a.Preset, c.Name, c.Config, a.PolicyOptions,
		a.Contents, a.Strangers, a.Sends, preset.PublicScope, f.Definition, f.Operation, f.Context.Sends, f.Context.Observes})
	sum := sha256.Sum256(raw)
	definition := hex.EncodeToString(sum[:])
	grant, err := facts.JSON[map[string]any](f.Scope)
	if err != nil {
		return fmt.Errorf("approval scope: %w", err)
	}
	// Policy and audit share one snapshot, independent of connector buffers.
	f, policyFacts, err := f.Snapshot()
	if err != nil {
		return err
	}
	access, _ := facts.JSON[map[string]any](p.Accounts[c.Account])
	d, err := st.Engine.Decide(ctx, map[string]any{"facts": policyFacts,
		"authorization": map[string]any{"access": access, "effects": modes, "rules": p.Rules, "definition": definition, "grant": grant},
		"account":       map[string]any{"contents": a.Contents, "strangers": a.Strangers, "sends": a.Sends, "private": a.PolicyOptions.Private, "public_scope": preset.PublicScope}})
	if err != nil {
		return err
	}
	r := m.addRecord(&record{Decision: d, Facts: &f, Grant: grant, Definition: definition})
	defer func() { m.settleRecord(r, err) }()
	if len(d.Deny) != 0 {
		return errors.New(strings.Join(d.Deny, "; "))
	}
	if len(d.Requirements) != 0 {
		r.Reviewer = p.Reviewer
		if err = m.awaitApproval(ctx, r); err != nil {
			return err
		}
		if m.live.Load() != st {
			return errChanged
		}
		label := m.currentLabel(p.Key)
		if label.Audience != f.Context.Label.Audience || label.Trust != f.Context.Label.Trust {
			return errLabelChanged
		}
	}
	if err = ctx.Err(); err != nil {
		return err
	}
	return m.observe(ctx, p.Key, d.Next, in.stream)
}

func (m *monitor) saveRule(ctx context.Context, r *record) error {
	f := r.Facts
	if f.Operation == nil || f.Operation.ID == "" {
		return errors.New("a request without a known operation cannot be saved")
	}
	p, exists := m.live.Load().Principals[f.Principal.Key]
	if !exists || p.Name != f.Principal.Name {
		return errors.New("the requesting identity was revoked or replaced")
	}
	value, err := facts.JSON[map[string]any](config.Rule{Account: f.Account, Action: f.Operation.Action, Operation: f.Operation.ID,
		Definition: r.Definition, Scope: r.Grant, Requirements: slices.Clone(r.Requirements)})
	if err != nil {
		return err
	}
	return m.editPolicy(ctx, []config.Change{{Path: []string{"identities", p.Name, "rules", r.ID}, Value: value}})
}

var cleanLabel = facts.Label{Trust: "trusted", Audience: "anyone"}

func (m *monitor) currentLabel(fingerprint string) facts.Label {
	if l, ok := m.store.Doc.Labels[fingerprint]; ok {
		return l
	}
	return cleanLabel
}

// observe persists a changed label before the operation runs. Message-gated
// streams use the shared label on their next operation; opaque sessions close.
func (m *monitor) observe(ctx context.Context, fingerprint string, l facts.Label, source *connector.Stream) error {
	if old := m.currentLabel(fingerprint); old.Trust == l.Trust && old.Audience == l.Audience {
		return nil
	}
	next := m.store.Doc
	next.Labels = maps.Clone(m.store.Doc.Labels)
	next.Labels[fingerprint] = l
	if err := m.store.Commit(ctx, next); err != nil {
		return err
	}
	// An opaque source may finish the session it just admitted. Other opaque
	// sessions cannot recheck their bytes, so revoke them. Sandbox routes carry
	// end-to-end traffic under Routes alone. An owner reset (source == nil)
	// closes all connector streams so old deliveries cannot recontaminate it.
	for s, key := range m.streams {
		if key == fingerprint && s != source && !sandboxroute.Reserved(s.Host) {
			c := m.live.Load().connections[s.Name]
			if source == nil || c == nil || !m.kinds[c.Protocol].PerMessage {
				s.Close()
			}
		}
	}
	return nil
}
