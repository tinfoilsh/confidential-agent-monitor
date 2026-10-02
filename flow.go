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
	"net/http"
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
	approvalWait  = 2 * time.Minute
	maxRecords    = 1000

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

var (
	//go:embed templates/*.rego
	templates embed.FS

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

type decision struct {
	Deny   []string       `json:"deny"`
	Action *string        `json:"action"`
	Title  string         `json:"title"`
	Scope  map[string]any `json:"scope"`
	Sends  string         `json:"sends"`
	Gaps   []string       `json:"gaps"`
	Next   label          `json:"next"`
}

// A record is one decision; requests are the pending and expired ones.
type record struct {
	ID       string           `json:"id"`
	State    string           `json:"state"`
	Time     time.Time        `json:"time"`
	Expires  time.Time        `json:"expires,omitzero"`
	Identity string           `json:"identity"`
	Account  string           `json:"account"`
	Label    label            `json:"label"`
	Event    *connector.Event `json:"event,omitempty"`
	*decision
	answered chan struct{}
}

type records struct {
	sync.Mutex
	list []*record
}

func prepareDecision(ctx context.Context, cfg *config) (rego.PreparedEvalQuery, error) {
	if cfg.Data == nil {
		cfg.Data = map[string]any{}
	}
	opts := []func(*rego.Rego){rego.Query(decisionQuery), rego.Store(inmem.NewFromObject(cfg.Data))}
	files, _ := fs.Glob(templates, templateDir+"/*.rego")
	for _, name := range files {
		src, _ := templates.ReadFile(name)
		opts = append(opts, rego.Module(name, string(src)))
	}
	for name, src := range cfg.Policies {
		opts = append(opts, rego.Module(path.Join("policies", name), src))
	}
	return rego.New(opts...).PrepareForEval(ctx)
}

func (m *monitor) label(fingerprint string) label {
	if l, ok := m.labels[fingerprint]; ok {
		return l
	}
	return cleanLabel
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

func (m *monitor) evaluate(ctx context.Context, in *input, account string) (*decision, error) {
	st := m.live.Load()
	p, ok := st.principals[in.Principal.Key]
	if !ok {
		return nil, errNoAgent
	}
	a := st.cfg.Accounts[account]
	a.Connections = nil
	in.Principal, in.Access, in.Rules, in.Label = p, p.Accounts[account], p.Rules, m.label(p.Key)
	in.Account = &namedAccount{account, a}
	return st.decide(ctx, *in)
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
	r := &record{ID: rand.Text(), State: stateAllowed, Time: time.Now(), Identity: in.Principal.Name, Account: account, Label: in.Label, decision: d}
	switch {
	case len(d.Deny) > 0:
		r.State, r.Event = stateRefused, in.Event
	case len(d.Gaps) > 0:
		r.State, r.Event, r.Expires, r.answered = statePending, in.Event, r.Time.Add(approvalWait), make(chan struct{})
	}
	m.records.add(r)
	if len(d.Deny) > 0 {
		return refusal(d.Deny)
	}
	if len(d.Gaps) > 0 {
		m.flow.Unlock()
		answer := m.records.wait(ctx, r)
		m.flow.Lock()
		if d, err = m.recheck(ctx, answer, r, &in, account); err != nil {
			m.records.Lock()
			if r.State == stateApproved {
				r.State = stateRefused
			}
			m.records.Unlock()
			return err
		}
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
	switch {
	case err != nil:
		return nil, err
	case len(d.Deny) > 0:
		return nil, refusal(d.Deny)
	case slices.ContainsFunc(d.Gaps, func(g string) bool { return !slices.Contains(r.Gaps, g) }):
		return nil, errChanged
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
	m.labels[fingerprint] = l
	st := m.live.Load()
	st.Generation++
	return m.persist(context.Background(), st, m.owner)
}

func (rs *records) add(r *record) {
	rs.Lock()
	defer rs.Unlock()
	rs.list = append(rs.list, r)
	if len(rs.list) > maxRecords {
		rs.list = rs.list[1:]
	}
}

func (rs *records) wait(ctx context.Context, r *record) string {
	ctx, cancel := context.WithDeadline(ctx, r.Expires)
	defer cancel()
	select {
	case <-r.answered:
	case <-ctx.Done():
	}
	rs.Lock()
	defer rs.Unlock()
	if r.State == statePending {
		r.State = stateExpired
	}
	return r.State
}

func (rs *records) marshal() (json.RawMessage, error) {
	rs.Lock()
	defer rs.Unlock()
	newest := append([]*record{}, rs.list...)
	slices.Reverse(newest)
	return json.Marshal(newest)
}

// answer approves or denies a pending request; save also appends a rule, and is all an expired request takes.
func (m *monitor) answer(ctx context.Context, id, choice string) error {
	m.records.Lock()
	i := slices.IndexFunc(m.records.list, func(r *record) bool { return r.ID == id })
	var r *record
	state := ""
	if i >= 0 {
		r, state = m.records.list[i], m.records.list[i].State
	}
	m.records.Unlock()
	switch {
	case r == nil:
		return fmt.Errorf("no request %s", id)
	case !slices.Contains([]string{answerOnce, answerSave, answerDeny}, choice):
		return fmt.Errorf("decision must be %s, %s or %s", answerOnce, answerSave, answerDeny)
	case state != statePending && (state != stateExpired || choice != answerSave):
		return fmt.Errorf("request %s is %s", id, state)
	case choice == answerSave && r.Action == nil:
		return errors.New("an unknown request cannot be saved")
	}
	if choice == answerSave {
		rules := append(slices.Clone(m.live.Load().cfg.Identities[r.Identity].Rules), rule{Account: r.Account, Action: *r.Action, Scope: r.Scope, Waives: r.Gaps})
		patch, err := json.Marshal(map[string]any{"identities": map[string]any{r.Identity: map[string]any{"rules": rules}}})
		if err != nil {
			return err
		}
		if _, err := m.patch(ctx, patch); err != nil {
			return err
		}
	}
	m.records.Lock()
	defer m.records.Unlock()
	if r.State == statePending {
		r.State = stateApproved
		if choice == answerDeny {
			r.State = stateDenied
		}
		close(r.answered)
	}
	return nil
}

func (m *monitor) requests(mux *http.ServeMux) {
	mux.Handle("GET /requests", m.owned(true, func(*http.Request, []byte) (any, error) { return m.records.marshal() }))
	mux.Handle("POST /requests/{id}", m.owned(true, func(r *http.Request, _ []byte) (any, error) {
		var req struct {
			Decision string `json:"decision"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, err
		}
		return nil, m.answer(r.Context(), r.PathValue("id"), req.Decision)
	}))
}
