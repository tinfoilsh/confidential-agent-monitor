package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"maps"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gobwas/glob"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/web"
	"github.com/tinfoilsh/monitor/facts"
)

const decisionQuery = "data.monitor.decision"

// Bump this when compiled parsing, description, normalization, label, or approval
// semantics change. It invalidates saved approvals even if the facts schema and
// Rego sources stay the same. Display-only edits do not require a bump.
const approvalSemanticsVersion = 2

//go:embed presets/policy/*.rego
var policyFiles embed.FS

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

var policySources = sync.OnceValue(func() map[string]string {
	files, _ := fs.Glob(policyFiles, "presets/policy/*.rego")
	sources := map[string]string{}
	for _, name := range files {
		src, _ := policyFiles.ReadFile(name)
		sources[name] = string(src)
	}
	// Keep the shared vocabulary in the policy sources so approval hashes bind it.
	vocabulary, _ := json.Marshal(facts.Effects)
	sources["effects.rego"] = "package monitor\nvocabulary := " + string(vocabulary)
	levels, _ := json.Marshal(map[string][]string{"audiences": facts.Audiences, "trusts": facts.Trusts})
	sources["label-levels.rego"] = "package monitor.labels\nlevels := " + string(levels)
	return sources
})

func policyModules() (opts []func(*rego.Rego)) {
	for name, src := range policySources() {
		opts = append(opts, rego.Module(name, src))
	}
	return opts
}

// policyQuery authorizes the snapshot described by each request.
type policyQuery struct {
	query            rego.PreparedEvalQuery
	presets          map[string]*presetRecord
	program          string
	lattices         latticeOptions
	semanticsVersion int
}

func preparePolicy(ctx context.Context, cfg *config) (program policyQuery, err error) {
	data := maps.Clone(cfg.Data)
	if data == nil {
		data = map[string]any{}
	}
	data["lattices"] = map[string]any{"confidentiality": cfg.Lattices.Confidentiality, "integrity": cfg.Lattices.Integrity}
	h := sha256.New()
	fmt.Fprintf(h, "facts-v%d", facts.Version)
	for _, name := range slices.Sorted(maps.Keys(policySources())) {
		fmt.Fprintf(h, "%q%q", name, policySources()[name])
	}
	for _, name := range slices.Sorted(maps.Keys(cfg.Policies)) {
		fmt.Fprintf(h, "%q%q", name, cfg.Policies[name])
	}
	raw, _ := json.Marshal(cfg.Data)
	h.Write(raw)
	opts := append(policyModules(), rego.Query(decisionQuery), rego.Store(inmem.NewFromObject(data)))
	for name, src := range cfg.Policies {
		opts = append(opts, rego.Module(path.Join("policies", name), src))
	}
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
	options, _ := json.Marshal(a.PolicyOptions)
	c := connector.Context{Connection: in.Connection, Config: in.ConnectionConfig, Options: options,
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
		record.applyVisibility(&f, a, sendsOverride)
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
func (record *presetRecord) applyVisibility(f *facts.Facts, account *namedAccount, sendsOverride string) {
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
	private := slices.ContainsFunc(account.PolicyOptions.Private, func(pattern string) bool {
		g, err := glob.Compile(pattern, '/')
		return err == nil && g.Match(scope)
	})
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
	if in.Account == nil {
		return nil, errors.New("policy request has no account")
	}
	if in.Request == nil {
		return nil, errors.New("policy request has no parsed input")
	}
	f, binding, describeErr := describeRequest(q.presets, in)
	definition := approvalDefinition(q, f, binding, in)
	// Freeze the snapshot before the connector resumes and can reuse its buffers.
	// Policy and audit both receive these same JSON values.
	rawFacts, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	var snapshot facts.Facts
	if err := connector.DecodeNumbers(rawFacts, &snapshot); err != nil {
		return nil, err
	}
	f = snapshot
	grant := connector.JSONFields(binding.Scope)
	var errs []string
	if describeErr != nil {
		errs = append(errs, describeErr.Error())
	}
	auth := map[string]any{"access": in.Access, "rules": in.Rules, "definition": definition, "grant": grant, "errors": errs}
	rs, err := q.query.Eval(ctx, rego.EvalInput(map[string]any{"facts": f, "authorization": auth}))
	if err != nil {
		return nil, err
	}
	if len(rs) == 0 {
		return nil, errors.New("policy decision is undefined")
	}
	raw, err := json.Marshal(rs[0].Expressions[0].Value)
	if err != nil {
		return nil, err
	}
	var d decision
	if err = connector.DecodeNumbers(raw, &d); err != nil {
		return nil, err
	}
	d.Facts = &f
	d.Grant = grant
	d.Definition = definition
	d.Next = f.Context.Label
	if f.Kind != facts.KindAdmission && describeErr == nil {
		d.Next = d.Next.Observe(f.Context.Observes, f.Context.Cause)
	}
	return &d, nil
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

// refreshAndEvaluate refreshes the input from current settings. The caller must hold m.flow.
func (m *monitor) refreshAndEvaluate(ctx context.Context, in *input, account string) (*decision, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	st := m.live.Load()
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

// gate admits, refuses or holds one request; the flow lock is released only while it waits for the owner.
func (m *monitor) gate(ctx context.Context, in input, account string) error {
	m.flow.Lock()
	defer m.flow.Unlock()
	d, err := m.refreshAndEvaluate(ctx, &in, account)
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
