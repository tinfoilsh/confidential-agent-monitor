package main

import (
	"context"
	"crypto/rand"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/tinfoilsh/monitor/connector"
)

const (
	templateDir   = "templates"
	decisionQuery = "data.monitor.decision"
	catalogQuery  = `{t: object.union(c, {"changes": object.get(data.templates, [t, "changes"], [])}) | c := data.templates[t].catalog}`
)

//go:embed templates/*.rego
var templates embed.FS

var (
	cleanLabel = label{Trust: "trusted", Audience: "anyone"}
	errExpired = errors.New("waiting for the owner's approval in the monitor timed out")
	errDenied  = errors.New("the owner denied this request")
	errChanged = errors.New("the request needs more than the owner approved")
	errNoAgent = errors.New("this agent's identity was removed")
)

type label struct {
	Trust    string            `json:"trust"`
	Audience string            `json:"audience"`
	Because  map[string]string `json:"because,omitempty"`
}

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
}

func templateModules() (opts []func(*rego.Rego)) {
	files, _ := fs.Glob(templates, templateDir+"/*.rego")
	for _, name := range files {
		src, _ := templates.ReadFile(name)
		opts = append(opts, rego.Module(name, string(src)))
	}
	return opts
}

// catalog is what the owner's app needs to know of each template.
var catalog = sync.OnceValues(func() (any, error) {
	rs, err := rego.New(append(templateModules(), rego.Query(catalogQuery))...).Eval(context.Background())
	if err != nil {
		return nil, err
	}
	return rs[0].Expressions[0].Value, nil
})

func prepareDecision(ctx context.Context, cfg *config) (rego.PreparedEvalQuery, error) {
	if cfg.Data == nil {
		cfg.Data = map[string]any{}
	}
	opts := append(templateModules(), rego.Query(decisionQuery), rego.Store(inmem.NewFromObject(cfg.Data)))
	for name, src := range cfg.Policies {
		opts = append(opts, rego.Module(path.Join("policies", name), src))
	}
	return rego.New(opts...).PrepareForEval(ctx)
}

func (st *state) decide(ctx context.Context, in input) (*decision, error) {
	rs, err := st.decision.Eval(ctx, rego.EvalInput(in))
	if err != nil {
		return nil, err
	}
	if len(rs) == 0 {
		return nil, fmt.Errorf("%s is undefined", decisionQuery)
	}
	raw, err := json.Marshal(rs[0].Expressions[0].Value)
	if err != nil {
		return nil, err
	}
	var d decision
	return &d, json.Unmarshal(raw, &d)
}

// evaluate refreshes the input from current settings. The caller must hold m.flow.
func (m *monitor) evaluate(ctx context.Context, in *input, account string) (*decision, error) {
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
	}
	in.Principal = p
	in.Access = p.Accounts[account]
	in.Rules = p.Rules
	in.Label = m.label(p.Key)
	in.Account = &namedAccount{Name: account, account: a}
	return st.decide(ctx, *in)
}

func (m *monitor) label(fingerprint string) label {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.labelLocked(fingerprint)
}

// labelLocked requires mu.
func (m *monitor) labelLocked(fingerprint string) label {
	if l, ok := m.doc.Labels[fingerprint]; ok {
		return l
	}
	return cleanLabel
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
	case len(d.Deny) > 0:
		r.State = stateRefused
		r.Event = in.Event
		m.records.add(r)
		return refusal(d.Deny)

	case len(d.Gaps) > 0:
		r.State = statePending
		r.Event = in.Event
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

	if d.Next.Trust != in.Label.Trust || d.Next.Audience != in.Label.Audience {
		return m.relabel(in.Principal.Key, d.Next)
	}
	return nil
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

// relabel lowers a label in memory before persisting, so a failed write still leaves it lowered.
func (m *monitor) relabel(fingerprint string, l label) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.doc.Labels == nil {
		m.doc.Labels = map[string]label{}
	}
	m.doc.Labels[fingerprint] = l
	m.doc.Generation++
	return m.persist(context.Background(), m.doc, m.owner)
}
