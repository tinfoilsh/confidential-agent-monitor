package main

import (
	"context"
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

	"github.com/gobwas/glob"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/web"
	"github.com/tinfoilsh/monitor/facts"
)

//go:embed presets/policy/lib.rego
var policySource string

var (
	errExpired = errors.New("waiting for the owner's approval in the monitor timed out")
	errDenied  = errors.New("the owner denied this request")
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
	Requirements requirements   `json:"requirements"`
	Next         facts.Label    `json:"next"`
	Definition   string         `json:"definition"`
	Grant        map[string]any `json:"grant"`
}

// IDs bind approval waivers; messages explain them without granting authority.
type requirement struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}

type requirements []requirement

func (rs requirements) contains(id string) bool {
	return slices.ContainsFunc(rs, func(r requirement) bool { return r.ID == id })
}

func (d *decision) authority() string {
	f := d.Facts
	binding := []any{f.Parameters, d.Definition, d.Grant}
	// Unknown operations have no definition hash to bind these fields.
	if f.Operation == nil {
		binding = append(binding, f.Kind, f.Context.Sends)
	}
	raw, _ := json.Marshal(binding)
	return string(raw)
}

func (d *decision) operationID() string {
	if d.Facts.Operation == nil {
		return ""
	}
	return d.Facts.Operation.ID
}

// policyQuery holds the prepared authorization policy for one configuration.
type policyQuery struct {
	query   rego.PreparedEvalQuery
	program string
}

func preparePolicy(ctx context.Context, cfg *config) (program policyQuery, err error) {
	modules := map[string]string{"monitor/lib.rego": policySource}
	data := maps.Clone(cfg.Data)
	if data == nil {
		data = map[string]any{}
	}
	data["levels"] = map[string]any{"audiences": facts.Audiences, "trusts": facts.Trusts}
	data["lattices"] = map[string]any{"confidentiality": cfg.Lattices.Confidentiality, "integrity": cfg.Lattices.Integrity}
	opts := []func(*rego.Rego){rego.Query("data.monitor.decision"),
		rego.Store(inmem.NewFromObjectWithOpts(data, inmem.OptReturnASTValuesOnRead(true))), rego.StrictBuiltinErrors(true)}
	for _, name := range slices.Sorted(maps.Keys(cfg.Policies)) {
		filename := "policies/" + name
		module, err := ast.ParseModule(filename, cfg.Policies[name])
		if err != nil {
			return program, err
		}
		for _, reserved := range []string{"data.monitor", "data.lattices", "data.levels"} {
			if module.Package.Path.HasPrefix(ast.MustParseRef(reserved)) {
				return program, fmt.Errorf("policy %s: %s is reserved for the monitor", name, reserved)
			}
		}
		modules[filename] = cfg.Policies[name]
		opts = append(opts, rego.ParsedModule(module))
	}
	h := sha256.New()
	fmt.Fprintf(h, "facts-v%d", facts.Version)
	for _, name := range slices.Sorted(maps.Keys(modules)) {
		source := modules[name]
		fmt.Fprintf(h, "%q%q", name, source)
		if strings.HasPrefix(name, "monitor/") {
			opts = append(opts, rego.Module(name, source))
		}
	}
	raw, err := json.Marshal(cfg.Data)
	if err != nil {
		return program, err
	}
	h.Write(raw)
	q, err := rego.New(opts...).PrepareForEval(ctx)
	if err != nil {
		return program, err
	}
	program = policyQuery{query: q, program: hex.EncodeToString(h.Sum(nil))}
	return program, nil
}

// describeRequest assembles one snapshot, with defaults from current account and
// preset settings. It runs again after approval, without reparsing or executing.
func describeRequest(presets map[string]*presetRecord, request connector.Request, p principal, conn *connection, a account, label facts.Label) (facts.Facts, error) {
	observation := facts.Label{Audience: a.Contents, Trust: "trusted"}
	if a.Strangers {
		observation.Trust = "untrusted"
	}
	c := connector.Context{Connection: conn.name, Config: conn.connector, Options: a.PolicyOptions,
		Label: label, Observation: observation}
	record := presets[a.Preset]
	c.Title = record.Title
	switch conn.protocol {
	case "http":
		c.Spec = record.http
	case "mcp":
		c.Spec = record.mcp
	}
	f, err := request.Describe(c)
	f.Version, f.Account, f.Service, f.Connection = facts.Version, a.name, a.Preset, conn.name
	f.Principal = facts.Principal{Key: p.Key, Name: p.Name}
	if f.Kind == "" {
		f.Kind = facts.KindOperation
	}
	if op := f.Operation; op != nil {
		// Descriptions may refer to shared definitions; normalization owns its copy.
		copy := *op
		op, f.Operation = &copy, &copy
		op.Lineage = actionLineage(op.Action)
		effects := op.Effects
		if effects == nil {
			effects = record.EffectsFor(op.Lineage)
		}
		// An action without configured semantics is unknown.
		if op.Action == "" || effects == nil {
			f.Operation = nil
		} else {
			effects = slices.Clone(effects)
			slices.Sort(effects)
			op.Effects = slices.Compact(effects)
			op.Obligations = facts.ObligationsFor(op.Effects)
			if op.ID == "" {
				op.ID = op.Action
			}
		}
	}
	sendsOverride := f.Context.Sends
	f.Context.Label = c.Label
	if f.Context.Observes.Audience == "" && f.Context.Observes.Trust == "" {
		f.Context.Observes = observation
	}
	if f.Context.Cause == "" {
		f.Context.Cause = a.name
	}
	if f.Context.Sends == "" {
		f.Context.Sends = a.Sends
		if op := f.Operation; op != nil && op.Obligations.Discloses {
			f.Context.Sends = "anyone"
		}
	} else if f.Context.Sends == "account" {
		f.Context.Sends = a.Sends
	}
	record.applyVisibility(&f, &a, sendsOverride, a.private)
	f.Definition = []any{f.Definition, record.PublicScope}
	if f.Operation == nil {
		f.Context.Observes = facts.Label{Audience: "me", Trust: "untrusted"}
	}
	if f.Parameters == nil {
		f.Parameters = map[string]any{}
	}
	if f.Scope == nil {
		f.Scope = f.Parameters
	}
	return f, err
}

// applyVisibility applies the preset's public resource scopes to account labels.
func (record *presetRecord) applyVisibility(f *facts.Facts, account *account, sendsOverride string, privatePatterns []glob.Glob) {
	ctx := &f.Context
	if len(record.PublicScope) == 0 {
		return
	}
	parts := make([]string, 0, len(record.PublicScope))
	for _, key := range record.PublicScope {
		value, ok := f.Parameters[key].(string)
		if !ok || value == "" {
			return
		}
		parts = append(parts, value)
	}
	scope := strings.Join(parts, "/")
	private := slices.ContainsFunc(privatePatterns, func(g glob.Glob) bool { return g.Match(scope) })

	if !private {
		ctx.Observes.Audience = "anyone"
	}
	if f.Operation != nil && f.Operation.Obligations.Change {
		if !private {
			ctx.Sends = "anyone"
		} else if sendsOverride == "" {
			ctx.Sends = account.Sends
		}
	}
}

// decide describes parsed input using current settings before authorization.
func (st *state) decide(ctx context.Context, request connector.Request, p principal, c *connection, a account, label facts.Label) (*decision, error) {
	f, describeErr := describeRequest(st.cfg.resolved, request, p, c, a, label)
	definition := approvalDefinition(st, f, c, a)
	grant, err := facts.JSON[map[string]any](f.Scope)
	if err != nil {
		return nil, fmt.Errorf("approval scope: %w", err)
	}
	// Policy and audit share one snapshot, independent of connector buffers.
	f, policyFacts, err := f.Snapshot()
	if err != nil {
		return nil, err
	}
	access, _ := facts.JSON[map[string]any](p.Accounts[a.name])
	auth := map[string]any{"access": access, "rules": p.Rules, "definition": definition, "grant": grant}
	// Each evaluation owns its lazy objects: OPA caches fields as it reads them.
	parsed := ast.LazyObject(map[string]any{"facts": policyFacts, "authorization": auth})
	results, err := st.decision.query.Eval(ctx, rego.EvalParsedInput(parsed))
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if len(results) != 1 || len(results[0].Expressions) != 1 {
		return nil, errors.New("policy returned no decision")
	}
	output, err := facts.JSON[struct {
		Deny         []string     `json:"deny"`
		Requirements requirements `json:"requirements"`
	}](results[0].Expressions[0].Value)
	if err != nil {
		return nil, fmt.Errorf("policy returned an invalid decision: %w", err)
	}
	d := &decision{Facts: &f, Grant: grant, Definition: definition, Next: f.Context.Label, Deny: output.Deny, Requirements: output.Requirements}
	if describeErr != nil {
		d.Deny = append(d.Deny, describeErr.Error())
	}
	slices.Sort(d.Deny)
	d.Deny = slices.Compact(d.Deny)
	slices.SortFunc(d.Requirements, func(a, b requirement) int { return strings.Compare(a.ID, b.ID) })
	if f.Kind != facts.KindAdmission && describeErr == nil {
		d.Next = d.Next.Observe(f.Context.Observes, f.Context.Cause)
	}
	return d, nil
}

// Approval definitions bind semantics and configuration, independently of facts
// shown to users. Display edits and current labels do not invalidate a grant.
func approvalDefinition(st *state, f facts.Facts, c *connection, a account) string {
	if f.Operation == nil {
		return ""
	}
	var observed any = f.Context.Observes
	if f.Kind == facts.KindAdmission {
		observed = nil
	}
	raw, _ := json.Marshal([]any{st.decision.program, st.cfg.Lattices, f.Kind, a.Preset, c.name, c.config, a.PolicyOptions,
		a.Contents, a.Strangers, a.Sends, f.Definition, f.Operation, f.Context.Sends, observed})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// refreshInput resolves routing and authorization from live state under the lock.
func (m *transaction) refreshInput(ctx context.Context, in input) (st *state, p principal, c *connection, a account, label facts.Label, err error) {
	if err = ctx.Err(); err != nil {
		return
	}
	st = m.live.Load()
	var ok bool
	if p, ok = st.principals[in.Key]; !ok {
		err = errNoAgent
		return
	}
	c = st.connections[in.Connection]
	if c == nil {
		err = errors.New("connection removed")
		return
	}
	a = st.cfg.Accounts[c.account]
	label = m.currentLabel(p.Key)
	return
}

// A corpus entry is one request to a preset's account and the operation it reached, for replay against later presets.
type corpusEntry struct {
	Preset    string         `json:"preset"`
	Origin    string         `json:"origin,omitempty"`
	Operation string         `json:"operation"`
	HTTP      *facts.HTTP    `json:"http"`
	GraphQL   *facts.GraphQL `json:"graphql,omitempty"`
}

// gate evaluates and records a request under the authorization lock.
func (m *monitor) gate(ctx context.Context, in input) error {
	var pending *record
	err := m.transact(func(tx *transaction) error {
		st, p, c, a, label, err := tx.refreshInput(ctx, in)
		if err != nil {
			return err
		}
		d, err := st.decide(ctx, in.Request, p, c, a, label)
		if err != nil {
			return err
		}
		if request, ok := in.Request.(*web.Request); m.corpus != nil && ok {
			o := a.PolicyOptions
			if err := m.corpus.Encode(corpusEntry{a.Preset, o.Origin, d.operationID(), request.HTTP, request.GraphQL}); err != nil {
				log.Printf("corpus: %v", err)
			}
		}
		r := tx.record(d)
		if p.Profile {
			return nil
		}
		if err := refusal(d.Deny); err != nil {
			return tx.finish(r, err)
		}
		if len(d.Requirements) != 0 {
			r.State, r.Expires, r.answered = statePending, r.Time.Add(approvalWait), make(chan struct{})
			pending = r
			return nil
		}
		return tx.finish(r, tx.observe(ctx, in.Key, d.Next, in.stream))
	})
	if err != nil || pending == nil {
		return err
	}

	waitApproval(ctx, pending)
	return m.transact(func(tx *transaction) error {
		if pending.State == statePending {
			pending.State = stateExpired
		}
		d, err := tx.recheck(ctx, pending.State, pending, in)
		if err != nil {
			return tx.finish(pending, err)
		}
		pending.decision = d
		return tx.finish(pending, tx.observe(ctx, in.Key, d.Next, in.stream))
	})
}

// recheck evaluates an approved request again, since the label or the owner's settings may have moved.
func (m *transaction) recheck(ctx context.Context, answer string, r *record, in input) (*decision, error) {
	switch answer {
	case stateExpired:
		return nil, errExpired
	case stateDenied:
		return nil, errDenied
	}
	st, p, c, a, label, err := m.refreshInput(ctx, in)
	if err != nil {
		return nil, err
	}
	d, err := st.decide(ctx, in.Request, p, c, a, label)
	if err != nil {
		return nil, err
	}
	if len(d.Deny) > 0 {
		return nil, refusal(d.Deny)
	}
	if d.authority() != r.authority() {
		return nil, errChanged
	}
	for _, requirement := range d.Requirements {
		if !r.Requirements.contains(requirement.ID) {
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
