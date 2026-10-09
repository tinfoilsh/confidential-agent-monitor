package main

import (
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

	"github.com/gobwas/glob"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/web"
	"github.com/tinfoilsh/monitor/facts"
)

// Bump this when compiled parsing, description, normalization, label, or approval
// semantics change. It invalidates saved approvals even if the facts schema and
// Rego sources stay the same. Display-only edits do not require a bump.
const approvalSemanticsVersion = 6

//go:embed presets/policy/lib.rego
var policySource string

//go:embed presets/policy/labels.rego
var labelPolicySource string

var (
	errExpired = errors.New("waiting for the owner's approval in the monitor timed out")
	errDenied  = errors.New("the owner denied this request")
	errChanged = errors.New("the request needs more than the owner approved")
	errNoAgent = errors.New("this agent's identity was removed")
)

type namedAccount struct {
	Name string `json:"name"`
	account
}

// input retains parsed input and current monitor settings.
type input struct {
	stream           *connector.Stream
	Principal        principal         `json:"principal"`
	Connection       string            `json:"connection"`
	ConnectionConfig json.RawMessage   `json:"connection_config,omitempty"`
	Account          *namedAccount     `json:"account"`
	Access           access            `json:"access"`
	Rules            []rule            `json:"rules"`
	Label            label             `json:"label"`
	Request          connector.Request `json:"-"`
}

type decision struct {
	Facts      *facts.Facts   `json:"facts"`
	Deny       []string       `json:"deny"`
	Gaps       []string       `json:"gaps"`
	Next       label          `json:"next"`
	Definition string         `json:"definition"`
	Grant      map[string]any `json:"grant"`
}

func (d *decision) authority() string {
	f := d.Facts
	raw, _ := json.Marshal([]any{f.Kind, f.Operation, f.Parameters, f.Context.Sends, d.Definition, d.Grant})
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
	query            rego.PreparedEvalQuery
	presets          map[string]*presetRecord
	program          string
	lattices         latticeOptions
	semanticsVersion int
}

type compiledOptions struct {
	raw     json.RawMessage
	private []glob.Glob
}

func compileOptions(options policyOptions) (*compiledOptions, error) {
	raw, _ := json.Marshal(options)
	out := &compiledOptions{raw: raw}
	for _, pattern := range options.Private {
		g, err := glob.Compile(pattern, '/')
		if err != nil {
			return nil, fmt.Errorf("invalid private pattern %q: %w", pattern, err)
		}
		out.private = append(out.private, g)
	}
	return out, nil
}

func preparePolicy(ctx context.Context, cfg *config) (program policyQuery, err error) {
	for name, a := range cfg.Accounts {
		if a.PolicyOptions.compiled == nil {
			a.PolicyOptions.compiled, err = compileOptions(a.PolicyOptions)
			if err != nil {
				return program, fmt.Errorf("account %s: %w", name, err)
			}
			cfg.Accounts[name] = a
		}
	}
	for _, reserved := range []string{"monitor", "lattices"} {
		if _, ok := cfg.Data[reserved]; ok {
			return program, fmt.Errorf("data.%s is reserved for the monitor", reserved)
		}
	}
	vocabulary, err := json.Marshal(facts.Effects)
	if err != nil {
		return program, err
	}
	levels, err := json.Marshal(map[string][]string{"audiences": facts.Audiences, "trusts": facts.Trusts})
	if err != nil {
		return program, err
	}
	modules := map[string]string{
		"monitor/lib.rego":     policySource,
		"monitor/labels.rego":  labelPolicySource,
		"monitor/effects.rego": "package monitor\nvocabulary := " + string(vocabulary),
		"monitor/levels.rego":  "package monitor.labels\nlevels := " + string(levels),
	}
	data := maps.Clone(cfg.Data)
	if data == nil {
		data = map[string]any{}
	}
	data["lattices"] = map[string]any{"confidentiality": cfg.Lattices.Confidentiality, "integrity": cfg.Lattices.Integrity}
	opts := []func(*rego.Rego){rego.Query("data.monitor.decision"),
		rego.Store(inmem.NewFromObjectWithOpts(data, inmem.OptReturnASTValuesOnRead(true))), rego.StrictBuiltinErrors(true)}
	for _, name := range slices.Sorted(maps.Keys(cfg.Policies)) {
		filename := "policies/" + name
		module, err := ast.ParseModule(filename, cfg.Policies[name])
		if err != nil {
			return program, err
		}
		for _, reserved := range []string{"data.monitor", "data.lattices"} {
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
	program = policyQuery{query: q, presets: cfg.resolved, program: hex.EncodeToString(h.Sum(nil)), lattices: cfg.Lattices, semanticsVersion: approvalSemanticsVersion}
	return program, nil
}

func (st *state) decide(ctx context.Context, in input) (*decision, error) {
	return evaluateDecision(ctx, st.decision, in)
}

// describeRequest assembles one snapshot, with defaults from current account and
// preset settings. It runs again after approval, without reparsing or executing.
func describeRequest(presets map[string]*presetRecord, in input) (facts.Facts, connector.Approval, error) {
	a := in.Account
	observation := facts.Label{Audience: a.Contents, Trust: "trusted"}
	if a.Strangers {
		observation.Trust = "untrusted"
	}
	options := a.PolicyOptions.compiled
	if options == nil {
		var err error
		options, err = compileOptions(a.PolicyOptions)
		if err != nil {
			return facts.Facts{}, connector.Approval{}, fmt.Errorf("account %s: %w", a.Name, err)
		}
	}
	c := connector.Context{Connection: in.Connection, Config: in.ConnectionConfig, Options: options.raw,
		Label: in.Label, Observation: observation, Specs: map[string]any{}}
	record := presets[a.Preset]
	if record != nil {
		c.Title = record.Title
		if record.HTTP != nil {
			c.Specs["http"] = record.HTTP
		}
		if record.MCP != nil {
			c.Specs["mcp"] = record.MCP
		}
	}
	f, binding, err := in.Request.Describe(c)
	f.Version, f.Account, f.Service, f.Connection = facts.Version, a.Name, a.Preset, in.Connection
	f.Principal = facts.Principal{Key: in.Principal.Key, Name: in.Principal.Name}
	if f.Kind == "" {
		f.Kind = facts.KindOperation
	}
	if op := f.Operation; op != nil {
		// Descriptions may refer to shared definitions; normalization owns its copy.
		copy := *op
		op, f.Operation = &copy, &copy
		effects := slices.Clone(op.Effects)
		if effects == nil && record != nil {
			effects = record.EffectsFor(op.Action)
		}
		// An action without configured semantics is unknown. An explicit empty or
		// invalid effect list is malformed and must survive to validation below.
		if op.Action != "" && effects == nil {
			f.Operation = nil
		} else {
			slices.Sort(effects)
			op.Effects = slices.Compact(effects)
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
		f.Context.Cause = a.Name
	}
	if f.Context.Sends == "" {
		f.Context.Sends = a.Sends
		if op := f.Operation; op != nil && facts.ObligationsFor(op.Effects).Discloses {
			f.Context.Sends = "anyone"
		}
	} else if f.Context.Sends == "account" {
		f.Context.Sends = a.Sends
	}
	if record != nil {
		record.applyVisibility(&f, a, sendsOverride, options.private)
		binding.Definition = []any{binding.Definition, record.PublicScope}
	}
	if f.Operation == nil {
		f.Context.Observes = facts.Label{Audience: "me", Trust: "untrusted"}
	}
	if f.Parameters == nil {
		f.Parameters = map[string]any{}
	}
	if binding.Scope == nil {
		binding.Scope = f.Parameters
	}
	return f, binding, errors.Join(err, f.Validate())
}

// applyVisibility applies the preset's public resource scopes to account labels.
func (record *presetRecord) applyVisibility(f *facts.Facts, account *namedAccount, sendsOverride string, privatePatterns []glob.Glob) {
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
	var effects []string
	if f.Operation != nil {
		effects = f.Operation.Effects
	}
	if facts.ObligationsFor(effects).Change {
		if !private {
			ctx.Sends = "anyone"
		} else if sendsOverride == "" {
			ctx.Sends = account.Sends
		}
	}
}

// evaluateDecision describes parsed input using current settings before authorization.
func evaluateDecision(ctx context.Context, q policyQuery, in input) (*decision, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if in.Account == nil {
		return nil, errors.New("policy request has no account")
	}
	if in.Request == nil {
		return nil, errors.New("policy request has no parsed input")
	}
	f, binding, describeErr := describeRequest(q.presets, in)
	definition := approvalDefinition(q, f, binding, in)
	// Policy and audit share one snapshot, independent of connector buffers.
	f, err := f.Clone()
	if err != nil {
		return nil, err
	}
	grant := connector.JSONFields(binding.Scope)
	var errs []string
	if describeErr != nil {
		errs = append(errs, describeErr.Error())
	}
	auth := map[string]any{"access": policyAccess(in.Access), "rules": in.Rules, "definition": definition, "grant": grant, "errors": errs}
	// Each evaluation owns its lazy objects: OPA caches fields as it reads them.
	parsed := ast.LazyObject(map[string]any{"facts": policyFacts(f), "authorization": auth})
	results, err := q.query.Eval(ctx, rego.EvalParsedInput(parsed))
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	if len(results) != 1 || len(results[0].Expressions) != 1 {
		return nil, errors.New("policy returned no decision")
	}
	output, ok := results[0].Expressions[0].Value.(map[string]any)
	if !ok {
		return nil, errors.New("policy returned an invalid decision")
	}
	d := &decision{Facts: &f, Grant: grant, Definition: definition, Next: f.Context.Label}
	if d.Deny, err = policyMessages(output["deny"]); err != nil {
		return nil, err
	}
	if d.Gaps, err = policyMessages(output["gaps"]); err != nil {
		return nil, err
	}
	if f.Kind != facts.KindAdmission && describeErr == nil {
		d.Next = d.Next.Observe(f.Context.Observes, f.Context.Cause)
	}
	return d, nil
}

func policyMessages(value any) ([]string, error) {
	values, ok := value.([]any)
	if !ok {
		return nil, errors.New("policy decision must contain sets or arrays of strings")
	}
	messages := make([]string, 0, len(values))
	for _, value := range values {
		message, ok := value.(string)
		if !ok {
			return nil, errors.New("policy decision must contain only strings")
		}
		messages = append(messages, message)
	}
	slices.Sort(messages)
	return slices.Compact(messages), nil
}

// Expose common fields as native objects so OPA can read them without encoding
// the full snapshot. Protocol structs retain their JSON representation and are
// converted by OPA only when a policy reads details.
func policyFacts(f facts.Facts) map[string]any {
	var operation any
	if op := f.Operation; op != nil {
		var effects any
		if op.Effects != nil {
			effects = op.Effects
		}
		operation = map[string]any{"id": op.ID, "action": op.Action, "effects": effects, "requires_trust": op.RequiresTrust}
	}
	context := map[string]any{"label": policyLabel(f.Context.Label), "observes": policyLabel(f.Context.Observes),
		"sends": f.Context.Sends, "cause": f.Context.Cause}
	if f.Context.Channel != nil {
		context["channel"] = policyLabel(*f.Context.Channel)
	}
	var parameters any
	if f.Parameters != nil {
		parameters = f.Parameters
	}
	return map[string]any{"version": f.Version, "kind": string(f.Kind), "principal": f.Principal,
		"account": f.Account, "service": f.Service, "connection": f.Connection,
		"operation": operation, "parameters": parameters, "title": f.Title, "details": f.Details, "context": context}
}

func policyLabel(l label) map[string]any {
	out := map[string]any{"audience": l.Audience, "trust": l.Trust}
	if len(l.Because) > 0 {
		out["because"] = l.Because
	}
	return out
}

func policyAccess(a access) map[string]any {
	out := map[string]any{"level": a.Level}
	if len(a.Actions) > 0 {
		out["actions"] = a.Actions
	}
	return out
}

// Approval definitions bind semantics and configuration, independently of facts
// shown to users. Display edits and current labels do not invalidate a grant.
func approvalDefinition(q policyQuery, f facts.Facts, binding connector.Approval, in input) string {
	if f.Operation == nil {
		return ""
	}
	a := in.Account
	var observed any = f.Context.Observes
	if f.Kind == facts.KindAdmission {
		observed = nil
	}
	raw, _ := json.Marshal([]any{q.program, q.semanticsVersion, q.lattices, f.Kind, a.Preset, in.Connection, in.ConnectionConfig, a.PolicyOptions,
		a.Contents, a.Strangers, a.Sends, binding.Definition, f.Operation, f.Context.Sends, observed})
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

// refreshInput captures the current configuration and label under flow. State
// snapshots and published labels are immutable after this function returns.
func (m *monitor) refreshInput(ctx context.Context, in *input, account string) (*state, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	st := m.live.Load()
	if st == nil {
		return nil, errNoAgent
	}
	p, ok := st.principals[in.Principal.Key]
	if !ok {
		return nil, errNoAgent
	}
	a := st.cfg.Accounts[account]
	a.Connections = nil
	in.ConnectionConfig = nil
	if c := st.connections[in.Connection]; c != nil {
		in.ConnectionConfig = redactedConnection(c)
	}
	in.Principal = p
	in.Access = p.Accounts[account]
	in.Rules = p.Rules
	in.Label = m.label(p.Key)
	in.Account = &namedAccount{Name: account, account: a}
	return st, nil
}

// refreshAndEvaluate is used for a recheck while flow is held.
func (m *monitor) refreshAndEvaluate(ctx context.Context, in *input, account string) (*decision, error) {
	st, err := m.refreshInput(ctx, in, account)
	if err != nil {
		return nil, err
	}
	return st.decide(ctx, *in)
}

// A corpus entry is one request to a preset's account and the operation it reached, for replay against later presets.
type corpusEntry struct {
	Preset    string              `json:"preset"`
	Origin    string              `json:"origin,omitempty"`
	Operation string              `json:"operation"`
	HTTP      *web.HTTPDetails    `json:"http"`
	GraphQL   *web.GraphQLDetails `json:"graphql,omitempty"`
}

// gate describes and evaluates independent requests concurrently. Before any
// authorization is used, flow verifies that its configuration and label remain
// current, and orders the label update and its persistence with other requests.
func (m *monitor) gate(ctx context.Context, in input, account string) error {
	m.flow.Lock()
	st, err := m.refreshInput(ctx, &in, account)
	m.flow.Unlock()
	if err != nil {
		return err
	}
	d, err := st.decide(ctx, in)

	m.flow.Lock()
	defer m.flow.Unlock()
	current := m.label(in.Principal.Key)
	if st != m.live.Load() || current.Audience != in.Label.Audience || current.Trust != in.Label.Trust || !maps.Equal(current.Because, in.Label.Because) {
		// Fall back under the lock on a concurrent change, so repeated updates
		// cannot starve a request or admit it using stale authority.
		d, err = m.refreshAndEvaluate(ctx, &in, account)
	}

	if err != nil {
		log.Printf("decision: %v", err)
		return err
	}

	if request, ok := in.Request.(*web.Request); m.corpus != nil && ok {
		o := in.Account.PolicyOptions
		if err := m.corpus.Encode(corpusEntry{in.Account.Preset, o.Origin, d.operationID(), request.HTTP, request.GraphQL}); err != nil {
			log.Printf("corpus: %v", err)
		}
	}
	r := &record{
		ID:       rand.Text(),
		State:    stateAllowed,
		Time:     time.Now(),
		decision: d,
	}
	switch {
	case in.Principal.Profile:
		m.records.add(r)
		return nil

	case len(d.Deny) > 0:
		r.State = stateRefused
		m.records.add(r)
		return refusal(d.Deny)

	case len(d.Gaps) > 0:
		r.State = statePending
		r.Expires = r.Time.Add(approvalWait)
		r.answered = make(chan struct{})
		m.records.add(r)

		// Other requests may change the label while this request waits.
		m.flow.Unlock()
		answer := m.records.wait(ctx, r)
		m.flow.Lock()

		d, err = m.recheck(ctx, answer, r, &in, account)
		if err != nil {
			m.records.refuseApproved(r)
			return err
		}
		m.records.mu.Lock()
		r.decision = d
		m.records.mu.Unlock()

	default:
		m.records.add(r)
	}

	return m.relabel(ctx, in.Principal.Key, d.Next, in.stream)
}

// recheck evaluates an approved request again, since the label or the owner's settings may have moved.
func (m *monitor) recheck(ctx context.Context, answer string, r *record, in *input, account string) (*decision, error) {
	switch answer {
	case stateExpired:
		return nil, errExpired
	case stateDenied:
		return nil, errDenied
	}
	d, err := m.refreshAndEvaluate(ctx, in, account)
	if err != nil {
		return nil, err
	}
	if len(d.Deny) > 0 {
		return nil, refusal(d.Deny)
	}
	if d.authority() != r.authority() {
		return nil, errChanged
	}
	for _, gap := range d.Gaps {
		if !slices.Contains(r.Gaps, gap) {
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
