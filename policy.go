package main

import (
	"cmp"
	"context"
	"crypto/rand"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/mcp"
	"github.com/tinfoilsh/monitor/connector/web"
	"github.com/tinfoilsh/monitor/facts"
)

//go:embed presets/policy/lib.rego
var policySource string

var (
	errChanged      = errors.New("configuration changed while waiting for approval; retry the request")
	errLabelChanged = errors.New("the agent's security label changed while waiting for approval; retry the request")
	errRuleSaved    = errors.New("approval rule saved; retry the request")
	errNoAgent      = errors.New("this agent's identity was removed")
)

// input binds parsed protocol input to its authenticated routing identity.
type input struct {
	stream     *connector.Stream
	Key        string
	Connection string
	Request    connector.Request
}

// IDs bind approval waivers; messages explain them without granting authority.
type requirement struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}

// preparePolicy also returns a hash of everything the policy's meaning depends on.
func preparePolicy(ctx context.Context, cfg *config) (q rego.PreparedEvalQuery, program string, err error) {
	reserved := []string{"monitor", "lattices", "levels"}
	for _, name := range reserved {
		if _, ok := cfg.Data[name]; ok {
			return q, program, fmt.Errorf("data.%s is reserved for the monitor", name)
		}
	}
	data := maps.Clone(cfg.Data)
	if data == nil {
		data = map[string]any{}
	}
	data["levels"] = map[string]any{"audiences": facts.Audiences, "trusts": facts.Trusts, "effects": facts.Effects}
	data["lattices"] = map[string]any{"confidentiality": cfg.Lattices.Confidentiality, "integrity": cfg.Lattices.Integrity}
	opts := []func(*rego.Rego){rego.Query("data.monitor.decision"), rego.Module("monitor/lib.rego", policySource),
		rego.Store(inmem.NewFromObjectWithOpts(data, inmem.OptReturnASTValuesOnRead(true))), rego.StrictBuiltinErrors(true)}
	h := sha256.New()
	fmt.Fprintf(h, "facts-v%d%q%q", facts.Version, "monitor/lib.rego", policySource)
	for _, name := range slices.Sorted(maps.Keys(cfg.Policies)) {
		filename := "policies/" + name
		module, err := ast.ParseModule(filename, cfg.Policies[name])
		if err != nil {
			return q, program, err
		}
		for _, r := range reserved {
			if module.Package.Path.HasPrefix(ast.MustParseRef("data." + r)) {
				return q, program, fmt.Errorf("policy %s: data.%s is reserved for the monitor", name, r)
			}
		}
		fmt.Fprintf(h, "%q%q", filename, cfg.Policies[name])
		opts = append(opts, rego.ParsedModule(module))
	}
	raw, err := json.Marshal(cfg.Data)
	if err != nil {
		return q, program, err
	}
	h.Write(raw)
	q, err = rego.New(opts...).PrepareForEval(ctx)
	return q, hex.EncodeToString(h.Sum(nil)), err
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
		ctx, cancel = context.WithCancel(ctx)
		defer cancel()
		stop := context.AfterFunc(in.stream.Context, cancel)
		defer stop()
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	st := m.live.Load()
	p, ok := st.principals[in.Key]
	if !ok {
		return errNoAgent
	}
	c := st.connections[in.Connection]
	if c == nil {
		return errors.New("connection removed")
	}
	a := st.cfg.Accounts[c.account]
	preset := st.cfg.resolved[a.Preset]
	cc := connector.Context{Title: preset.Title, Connection: c.name, Config: c.connector, Options: a.PolicyOptions}
	switch in.Request.(type) {
	case *web.Request:
		cc.Spec = preset.HTTP
	case *mcp.Request:
		cc.Spec = preset.MCP
	}
	f, describeErr := in.Request.Describe(cc)
	f.Version, f.Account, f.Service, f.Connection = facts.Version, c.account, a.Preset, c.name
	if f.Kind == "" {
		f.Kind = facts.KindOperation
	}
	if f.Operation != nil {
		op := *f.Operation
		op.Lineage = actionLineage(op.Action)
		effects := op.Effects
		for i := 0; effects == nil && i < len(op.Lineage); i++ {
			effects = preset.Catalog.Actions[op.Lineage[i]].Effects
		}
		// An action without configured semantics is unknown.
		if op.Action == "" || effects == nil {
			f.Operation = nil
		} else {
			op.Effects, op.ID = slices.Compact(slices.Sorted(slices.Values(effects))), cmp.Or(op.ID, op.Action)
			f.Operation = &op
		}
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
		r.settle(describeErr)
		return describeErr
	}
	// Approval definitions bind semantics and configuration, independently of facts
	// shown to users. Display edits and current labels do not invalidate a grant.
	var operationEffects []string
	if f.Operation != nil {
		operationEffects = f.Operation.Effects
	}
	effects := st.cfg.effectModes(p.Name, c.account, operationEffects...)
	raw, _ := json.Marshal([]any{st.program, st.cfg.Lattices, effects, f.Kind, a.Preset, c.name, c.config, a.PolicyOptions,
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
	access, _ := facts.JSON[map[string]any](p.Accounts[c.account])
	// Each evaluation owns its lazy objects: OPA caches fields as it reads them.
	parsed := ast.LazyObject(map[string]any{"facts": policyFacts,
		"authorization": map[string]any{"access": access, "effects": effects, "rules": p.Rules, "definition": definition, "grant": grant},
		"account":       map[string]any{"contents": a.Contents, "strangers": a.Strangers, "sends": a.Sends, "private": a.PolicyOptions.Private, "public_scope": preset.PublicScope}})
	results, err := st.query.Eval(ctx, rego.EvalParsedInput(parsed))
	if err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	if len(results) != 1 || len(results[0].Expressions) != 1 {
		return errors.New("policy returned no decision")
	}
	d, err := facts.JSON[record](results[0].Expressions[0].Value)
	if err != nil {
		return fmt.Errorf("policy returned an invalid decision: %w", err)
	}
	d.Facts, d.Grant, d.Definition = &f, grant, definition
	r := m.addRecord(&d)
	defer func() { r.settle(err) }()
	if len(d.Deny) != 0 {
		return errors.New(strings.Join(d.Deny, "; "))
	}
	if len(d.Requirements) != 0 {
		if err = m.await(ctx, r); err != nil {
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

const (
	approvalWait = 2 * time.Minute
	maxRecords   = 1000

	statePending  = "pending"
	stateExpired  = "expired"
	stateAllowed  = "allowed"
	stateRefused  = "refused"
	stateApproved = "approved"
	stateDenied   = "denied"

	answerOnce = "once"
	answerSave = "save"
	answerDeny = "deny"
)

// A record is one decision; requests are the pending and expired ones.
type record struct {
	ID           string         `json:"id"`
	State        string         `json:"state"`
	Invalid      bool           `json:"invalid,omitempty"`
	Time         time.Time      `json:"time"`
	Expires      time.Time      `json:"expires,omitzero"`
	Facts        *facts.Facts   `json:"facts"`
	Deny         []string       `json:"deny"`
	Requirements []requirement  `json:"requirements"`
	Sends        string         `json:"sends"`
	Next         facts.Label    `json:"next"`
	Definition   string         `json:"definition"`
	Grant        map[string]any `json:"grant"`
	answered     chan struct{}
}

func (m *monitor) addRecord(r *record) *record {
	r.ID, r.Time, r.State = rand.Text(), time.Now(), stateAllowed
	m.records = append(m.records, r)
	if len(m.records) > maxRecords {
		m.records = m.records[1:]
	}
	return r
}

// await holds a record for the owner's answer, releasing the lock while it waits.
func (m *monitor) await(ctx context.Context, r *record) error {
	r.State, r.Expires, r.answered = statePending, r.Time.Add(approvalWait), make(chan struct{})
	wait, cancel := context.WithDeadline(ctx, r.Expires)
	m.mu.Unlock()
	select {
	case <-r.answered:
	case <-wait.Done():
	}
	cancel()
	m.mu.Lock()
	if err := ctx.Err(); err != nil {
		return err
	}
	switch r.State {
	case statePending, stateExpired:
		r.State = stateExpired
		return errors.New("waiting for the owner's approval in the monitor timed out")
	case stateDenied:
		return errors.New("the owner denied this request")
	case stateRefused:
		return errors.New(strings.Join(r.Deny, "; "))
	}
	return nil
}

// settle marks a record refused when its request fails for a reason other than the owner's answer.
func (r *record) settle(err error) {
	if err != nil && r.State != stateDenied && r.State != stateExpired {
		r.State = stateRefused
		if len(r.Deny) == 0 {
			r.Deny = []string{err.Error()}
		}
	}
}

// Saving a rule applies to future attempts. Only an unexpired allow-once answer resumes a call.
func (m *monitor) answer(ctx context.Context, id, choice string) error {
	if !slices.Contains([]string{answerOnce, answerSave, answerDeny}, choice) {
		return fmt.Errorf("decision must be %s, %s or %s", answerOnce, answerSave, answerDeny)
	}
	i := slices.IndexFunc(m.records, func(r *record) bool { return r.ID == id })
	if i < 0 {
		return fmt.Errorf("no request %s", id)
	}
	r := m.records[i]
	if r.State == statePending && !time.Now().Before(r.Expires) {
		r.State = stateExpired
		close(r.answered)
	}
	if r.State != statePending && !(r.State == stateExpired && choice == answerSave) {
		return fmt.Errorf("request %s is %s", id, r.State)
	}
	if choice == answerSave {
		if err := m.saveRule(ctx, r); err != nil {
			return err
		}
		if r.State == statePending {
			close(r.answered)
		}
		r.State, r.Deny = stateRefused, []string{errRuleSaved.Error()}
		return nil
	}
	r.State = stateApproved
	if choice == answerDeny {
		r.State = stateDenied
	}
	close(r.answered)
	return nil
}

func (m *monitor) saveRule(ctx context.Context, r *record) error {
	f := r.Facts
	if f.Operation == nil || f.Operation.ID == "" {
		return errors.New("a request without a known operation cannot be saved")
	}
	p, exists := m.live.Load().principals[f.Principal.Key]
	if !exists || p.Name != f.Principal.Name {
		return errors.New("the requesting identity was revoked or replaced")
	}
	value, err := facts.JSON[map[string]any](rule{Account: f.Account, Action: f.Operation.Action, Operation: f.Operation.ID,
		Definition: r.Definition, Scope: r.Grant, Requirements: slices.Clone(r.Requirements)})
	if err != nil {
		return err
	}
	return m.editPolicy(ctx, []sourceChange{{Path: []string{"identities", p.Name, "rules", r.ID}, Value: value}})
}

var cleanLabel = facts.Label{Trust: "trusted", Audience: "anyone"}

type principal struct {
	Key  string
	Name string
	identity
}

func (p principal) reaches(account string) bool {
	level := p.Accounts[account].Level
	return level != "" && level != "off"
}

func (m *monitor) currentLabel(fingerprint string) facts.Label {
	if l, ok := m.store.doc.Labels[fingerprint]; ok {
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
	next := m.store.doc
	next.Labels = maps.Clone(m.store.doc.Labels)
	next.Labels[fingerprint] = l
	if err := m.store.commit(ctx, next); err != nil {
		return err
	}
	// An opaque source may finish the session it just admitted. Other opaque
	// sessions cannot recheck their bytes, so revoke them. Sandbox routes carry
	// end-to-end traffic under Routes alone. An owner reset (source == nil)
	// closes all connector streams so old deliveries cannot recontaminate it.
	for s, key := range m.streams {
		if key == fingerprint && s != source && !reservedRoute(s.Host) {
			c := m.live.Load().connections[s.Name]
			if source == nil || c == nil || !connectorKinds[c.protocol].PerMessage {
				s.Close()
			}
		}
	}
	return nil
}
