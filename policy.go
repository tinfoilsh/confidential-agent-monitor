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
	"log"
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
	errChanged = errors.New("the request needs more than the owner approved")
	errNoAgent = errors.New("this agent's identity was removed")
)

// input retains only the parsed request and its routing identity.
type input struct {
	stream     *connector.Stream
	Key        string
	Connection string
	Request    connector.Request
}

type decision struct {
	Facts        *facts.Facts   `json:"facts"`
	Deny         []string       `json:"deny"`
	Requirements []requirement  `json:"requirements"`
	Sends        string         `json:"sends"`
	Next         facts.Label    `json:"next"`
	Definition   string         `json:"definition"`
	Grant        map[string]any `json:"grant"`
}

// IDs bind approval waivers; messages explain them without granting authority.
type requirement struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}

func (d *decision) authority() string {
	raw, _ := json.Marshal([]any{d.Facts.Parameters, d.Definition, d.Grant})
	return string(raw)
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

// evaluate asks the connector what parsed input does under live routing, settings and label,
// then decides it on one snapshot. It runs again after approval, without reparsing or executing.
func (m *monitor) evaluate(ctx context.Context, in input) (*decision, principal, error) {
	if err := ctx.Err(); err != nil {
		return nil, principal{}, err
	}
	st := m.live.Load()
	p, ok := st.principals[in.Key]
	if !ok {
		return nil, p, errNoAgent
	}
	c := st.connections[in.Connection]
	if c == nil {
		return nil, p, errors.New("connection removed")
	}
	a := st.cfg.Accounts[c.account]
	record := st.cfg.resolved[a.Preset]
	cc := connector.Context{Title: record.Title, Connection: c.name, Config: c.connector, Options: a.PolicyOptions}
	switch in.Request.(type) {
	case *web.Request:
		cc.Spec = record.HTTP
	case *mcp.Request:
		cc.Spec = record.MCP
	}
	f, describeErr := in.Request.Describe(cc)
	f.Version, f.Account, f.Service, f.Connection = facts.Version, c.account, a.Preset, c.name
	if f.Kind == "" {
		f.Kind = facts.KindOperation
	}
	if op := f.Operation; op != nil {
		op.Lineage = actionLineage(op.Action)
		effects := op.Effects
		for i := 0; effects == nil && i < len(op.Lineage); i++ {
			effects = record.Catalog.Actions[op.Lineage[i]].Effects
		}
		// An action without configured semantics is unknown.
		if op.Action == "" || effects == nil {
			f.Operation = nil
		} else {
			op.Effects, op.ID = slices.Compact(slices.Sorted(slices.Values(effects))), cmp.Or(op.ID, op.Action)
		}
	}
	if f.Parameters == nil {
		f.Parameters = map[string]any{}
	}
	if f.Scope == nil {
		f.Scope = f.Parameters
	}
	f.Principal, f.Context.Label = facts.Principal{Key: p.Key, Name: p.Name}, m.currentLabel(p.Key)
	// Approval definitions bind semantics and configuration, independently of facts
	// shown to users. Display edits and current labels do not invalidate a grant.
	raw, _ := json.Marshal([]any{st.program, st.cfg.Lattices, f.Kind, a.Preset, c.name, c.config, a.PolicyOptions,
		a.Contents, a.Strangers, a.Sends, record.PublicScope, f.Definition, f.Operation, f.Context.Sends, f.Context.Observes})
	sum := sha256.Sum256(raw)
	definition := hex.EncodeToString(sum[:])
	grant, err := facts.JSON[map[string]any](f.Scope)
	if err != nil {
		return nil, p, fmt.Errorf("approval scope: %w", err)
	}
	// Policy and audit share one snapshot, independent of connector buffers.
	f, policyFacts, err := f.Snapshot()
	if err != nil {
		return nil, p, err
	}
	access, _ := facts.JSON[map[string]any](p.Accounts[c.account])
	// Each evaluation owns its lazy objects: OPA caches fields as it reads them.
	parsed := ast.LazyObject(map[string]any{"facts": policyFacts,
		"authorization": map[string]any{"access": access, "rules": p.Rules, "definition": definition, "grant": grant},
		"account":       map[string]any{"contents": a.Contents, "strangers": a.Strangers, "sends": a.Sends, "private": a.PolicyOptions.Private, "public_scope": record.PublicScope}})
	results, err := st.query.Eval(ctx, rego.EvalParsedInput(parsed))
	if err != nil {
		return nil, p, fmt.Errorf("policy: %w", err)
	}
	if len(results) != 1 || len(results[0].Expressions) != 1 {
		return nil, p, errors.New("policy returned no decision")
	}
	d, err := facts.JSON[decision](results[0].Expressions[0].Value)
	if err != nil {
		return nil, p, fmt.Errorf("policy returned an invalid decision: %w", err)
	}
	d.Facts, d.Grant, d.Definition = &f, grant, definition
	if describeErr != nil {
		d.Deny = append(d.Deny, describeErr.Error())
	}
	return &d, p, nil
}

// gate evaluates and records a request under the authorization lock; approval waits release it.
func (m *monitor) gate(ctx context.Context, in input) (err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	d, p, err := m.evaluate(ctx, in)
	if err != nil {
		return err
	}
	r := m.addRecord(d)
	if p.Profile {
		return nil
	}
	defer func() { r.settle(err) }()
	if err = refusal(d.Deny); err != nil {
		return err
	}
	if len(d.Requirements) != 0 {
		if err = m.await(ctx, r); err != nil {
			return err
		}
		if d, err = m.recheck(ctx, r, in); err != nil {
			return err
		}
		r.decision = d
	}
	return m.observe(ctx, in.Key, d.Next, in.stream)
}

// recheck evaluates an approved request again, since the label or the owner's settings may have moved.
func (m *monitor) recheck(ctx context.Context, r *record, in input) (*decision, error) {
	d, _, err := m.evaluate(ctx, in)
	if err != nil {
		return nil, err
	}
	if len(d.Deny) > 0 {
		return nil, refusal(d.Deny)
	}
	if d.authority() != r.authority() {
		return nil, errChanged
	}
	for _, need := range d.Requirements {
		if !slices.ContainsFunc(r.Requirements, func(q requirement) bool { return q.ID == need.ID }) {
			return nil, errChanged
		}
	}
	return d, nil
}

func refusal(deny []string) error {
	if len(deny) == 0 {
		return nil
	}
	reason := strings.Join(deny, "; ")
	log.Printf("denied: %s", reason)
	return errors.New(reason)
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
	ID      string    `json:"id"`
	State   string    `json:"state"`
	Time    time.Time `json:"time"`
	Expires time.Time `json:"expires,omitzero"`
	*decision
	answered chan struct{}
}

func (m *monitor) addRecord(d *decision) *record {
	r := &record{ID: rand.Text(), Time: time.Now(), State: stateAllowed, decision: d}
	m.records = append(m.records, r)
	if len(m.records) > maxRecords {
		m.records = m.records[1:]
	}
	return r
}

// await holds a record for the owner's answer, releasing the lock while it waits.
func (m *monitor) await(ctx context.Context, r *record) error {
	r.State, r.Expires, r.answered = statePending, r.Time.Add(approvalWait), make(chan struct{})
	m.mu.Unlock()
	wait, cancel := context.WithDeadline(ctx, r.Expires)
	select {
	case <-r.answered:
	case <-wait.Done():
	}
	cancel()
	m.mu.Lock()
	switch r.State {
	case statePending:
		r.State = stateExpired
		return errors.New("waiting for the owner's approval in the monitor timed out")
	case stateDenied:
		return errors.New("the owner denied this request")
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

// Expired requests can still save a rule, but cannot resume the original call.
func (m *monitor) answer(ctx context.Context, id, choice string) error {
	if !slices.Contains([]string{answerOnce, answerSave, answerDeny}, choice) {
		return fmt.Errorf("decision must be %s, %s or %s", answerOnce, answerSave, answerDeny)
	}
	i := slices.IndexFunc(m.records, func(r *record) bool { return r.ID == id })
	if i < 0 {
		return fmt.Errorf("no request %s", id)
	}
	r := m.records[i]
	if r.State != statePending && !(r.State == stateExpired && choice == answerSave) {
		return fmt.Errorf("request %s is %s", id, r.State)
	}
	if choice == answerSave {
		if err := m.saveRule(ctx, r); err != nil {
			return err
		}
	}
	if r.State == statePending {
		r.State = stateApproved
		if choice == answerDeny {
			r.State = stateDenied
		}
		close(r.answered)
	}
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
