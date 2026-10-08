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

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/tinfoilsh/monitor/connector"
)

const (
	decisionQuery = "data.monitor.decision"
	messageQuery  = "data.monitor.messages.decision"
)

//go:embed presets/policy/*.rego presets/*.rego
var policyFiles embed.FS

var (
	errExpired = errors.New("waiting for the owner's approval in the monitor timed out")
	errDenied  = errors.New("the owner denied this request")
	errChanged = errors.New("the request needs more than the owner approved")
	errNoAgent = errors.New("this agent's identity was removed")
)

type tcpLayer struct {
	Host string `json:"host"`
	Port uint32 `json:"port"`
}

type namedAccount struct {
	Name string `json:"name"`
	account
}

// input carries either the tunnel's tcp layer or a connector's layers, never both.
type input struct {
	stream           *connector.Stream
	Principal        principal       `json:"principal"`
	Connection       string          `json:"connection"`
	ConnectionConfig json.RawMessage `json:"connection_config,omitempty"`
	Protocol         string          `json:"protocol"`
	TCP              *tcpLayer       `json:"tcp,omitempty"`
	Account          *namedAccount   `json:"account"`
	Access           access          `json:"access"`
	Rules            []rule          `json:"rules"`
	Label            label           `json:"label"`
	*connector.Event
}

type decision struct {
	Deny   []string       `json:"deny"`
	Action *string        `json:"action"`
	Title  string         `json:"title"`
	Scope  map[string]any `json:"scope"`
	Sends  string         `json:"sends"`
	Gaps   []string       `json:"gaps"`
	Next   label          `json:"next"`
	// The authority an approval grants: the operation, its definition, effects and scope.
	Operation  string         `json:"operation"`
	Definition string         `json:"definition"`
	Effects    []string       `json:"effects"`
	Grant      map[string]any `json:"grant"`
}

func (d *decision) authority() string {
	raw, _ := json.Marshal([]any{d.Action, d.Operation, d.Definition, d.Effects, d.Scope, d.Grant, d.Sends})
	return string(raw)
}

var policySources = sync.OnceValue(func() map[string]string {
	files, _ := fs.Glob(policyFiles, "presets/*.rego")
	shared, _ := fs.Glob(policyFiles, "presets/policy/*.rego")
	files = append(files, shared...)
	sources := map[string]string{}
	for _, name := range files {
		src, _ := policyFiles.ReadFile(name)
		sources[name] = string(src)
	}
	return sources
})

func policyModules() (opts []func(*rego.Rego)) {
	for name, src := range policySources() {
		opts = append(opts, rego.Module(name, src))
	}
	return opts
}

var effectVocabulary = sync.OnceValues(func() (any, error) {
	rs, err := rego.New(append(policyModules(), rego.Query("data.monitor.vocabulary"))...).Eval(context.Background())
	if err != nil {
		return nil, err
	}
	return rs[0].Expressions[0].Value, nil
})

// catalog is the resolved preset metadata and operations used by the owner's app.
func catalog(all map[string]preset) (any, error) {
	vocabulary, err := effectVocabulary()
	if err != nil {
		return nil, err
	}
	entries := map[string]any{}
	for name, p := range all {
		entry := maps.Clone(p.catalog)
		entry["title"], entry["operations"] = p.record["title"], p.record["operations"]
		entry["vocabulary"] = vocabulary
		entries[name] = entry
	}
	return entries, nil
}

// preparePolicies compiles the modules and builds their data once for both queries.
// Saved approvals name data.definitions.program, the digest of all policy sources.
func preparePolicies(ctx context.Context, cfg *config) (connectors, messages rego.PreparedEvalQuery, err error) {
	data := maps.Clone(cfg.Data)
	if data == nil {
		data = map[string]any{}
	}
	records := map[string]any{}
	for name, p := range cfg.resolved {
		records[name] = p.record
	}
	data["presets"] = records
	data["lattices"] = map[string]any{"confidentiality": cfg.Lattices.Confidentiality, "integrity": cfg.Lattices.Integrity}
	h := sha256.New()
	for _, name := range slices.Sorted(maps.Keys(policySources())) {
		fmt.Fprintf(h, "%q%q", name, policySources()[name])
	}
	for _, name := range slices.Sorted(maps.Keys(cfg.Policies)) {
		fmt.Fprintf(h, "%q%q", name, cfg.Policies[name])
	}
	data["definitions"] = map[string]any{"program": hex.EncodeToString(h.Sum(nil))}
	compiler := ast.NewCompiler()
	store := inmem.NewFromObject(data)
	opts := append(policyModules(), rego.Compiler(compiler), rego.Query(decisionQuery), rego.Store(store))
	for name, src := range cfg.Policies {
		opts = append(opts, rego.Module(path.Join("policies", name), src))
	}
	if connectors, err = rego.New(opts...).PrepareForEval(ctx); err != nil {
		return connectors, messages, err
	}
	messages, err = rego.New(rego.Compiler(compiler), rego.Store(store), rego.Query(messageQuery)).PrepareForEval(ctx)
	return connectors, messages, err
}

func (st *state) decide(ctx context.Context, in input) (*decision, error) {
	return evaluateDecision(ctx, st.decision, in)
}

func evaluateDecision(ctx context.Context, query rego.PreparedEvalQuery, in any) (*decision, error) {
	rs, err := query.Eval(ctx, rego.EvalInput(in))
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
	return &d, connector.DecodeNumbers(raw, &d)
}

// evaluate refreshes the input from current settings. The caller must hold m.flow.
func (m *monitor) evaluate(ctx context.Context, in *input, account string) (*decision, error) {
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
		in.ConnectionConfig = c.config
		for _, field := range c.connector.Fields() {
			if field.Redact {
				in.ConnectionConfig, _ = jsonpatch.MergePatch(in.ConnectionConfig, valuePatch(field.Path, json.RawMessage("null")))
			}
		}
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
	Preset    string                  `json:"preset"`
	Origin    string                  `json:"origin,omitempty"`
	Operation string                  `json:"operation"`
	HTTP      *connector.HTTPLayer    `json:"http"`
	GraphQL   *connector.GraphQLLayer `json:"graphql,omitempty"`
}

// gate admits, refuses or holds one request; the flow lock is released only while it waits for the owner.
func (m *monitor) gate(ctx context.Context, in input, account string) error {
	m.flow.Lock()
	defer m.flow.Unlock()
	d, err := m.evaluate(ctx, &in, account)
	if err != nil {
		log.Printf("decision: %v", err)
		return err
	}
	if in.TCP != nil {
		return refusal(d.Deny)
	}
	if o := in.Account.PolicyOptions; m.corpus != nil && in.Event != nil && in.HTTP != nil {
		if err := m.corpus.Encode(corpusEntry{in.Account.Preset, o.Origin, d.Operation, in.HTTP, in.GraphQL}); err != nil {
			log.Printf("corpus: %v", err)
		}
	}
	r := &record{
		ID:       rand.Text(),
		State:    stateAllowed,
		Time:     time.Now(),
		Identity: in.Principal.Name,
		Account:  account,
		Label:    in.Label,
		decision: d,
	}
	switch {
	case in.Principal.Profile:
		r.Event = &auditEvent{Event: in.Event}
		m.records.add(r)
		return nil

	case len(d.Deny) > 0:
		r.State = stateRefused
		r.Event = &auditEvent{Event: in.Event}
		m.records.add(r)
		return refusal(d.Deny)

	case len(d.Gaps) > 0:
		r.State = statePending
		r.Event = &auditEvent{Event: in.Event}
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
	d, err := m.evaluate(ctx, in, account)
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
