package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/config"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/connections"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/format"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/catalog"
	"github.com/tinfoilsh/confidential-agent-monitor/core"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/netx"
)

var (
	errRemoved      = errors.New("this agent's identity was removed")
	errChanged      = errors.New("configuration changed; retry the request")
	errAuditBacklog = errors.New("the Perimeter cannot write its audit log; requests are refused until storage recovers")
	errRuleSaved    = errors.New("approval rule saved; retry the request")
	errNoAccess     = errors.New("key has no agent access")
)

const (
	statePending  = "pending"
	stateExpired  = "expired"
	stateOutdated = "outdated"
	stateAllowed  = "allowed"
	stateRefused  = "refused"
	stateApproved = "approved"
	stateDenied   = "denied"

	answerOnce = "once"
	answerSave = "save"
	answerDeny = "deny"

	approvalWait = 2 * time.Minute
	maxRecords   = 1000
)

type Answer struct {
	Choice string `json:"decision"`
	Reason string `json:"reason,omitempty"`
}

type Review struct {
	By string `json:"by"`
	Answer
	Time time.Time `json:"time"`
}

type Decision struct {
	Deny         []string             `json:"deny"`
	Requirements []config.Requirement `json:"requirements"`
	Sends        string               `json:"sends"`
	Next         format.Label         `json:"next"`
}

type record struct {
	ID      string          `json:"id"`
	State   string          `json:"state"`
	Invalid bool            `json:"invalid,omitempty"`
	Time    time.Time       `json:"time"`
	Expires time.Time       `json:"expires,omitzero"`
	Facts   json.RawMessage `json:"facts"`
	Decision
	Grant   map[string]any  `json:"grant"`
	Reviews []Review        `json:"reviews,omitempty"`
	Changes []format.Change `json:"changes,omitempty"`
}

func (r *record) settle(err error) {
	if err != nil && r.State != stateDenied && r.State != stateExpired {
		r.State = stateRefused
		if len(r.Deny) == 0 {
			r.Deny = []string{err.Error()}
		}
	}
}

type admitted struct {
	key, connection string
	capability      string
	perMessage      bool
	valid           func() bool
	grants          []*grant
}

type grant struct {
	kind     string
	event    facts.Event
	admit    *requestFacts
	label    format.Label
	approved []string
}

type requestFacts struct {
	Scope      map[string]any             `json:"-"`
	Version    int                        `json:"version"`
	Kind       string                     `json:"kind"`
	Principal  facts.Principal            `json:"principal"`
	Service    string                     `json:"service"`
	Connection string                     `json:"connection"`
	Operation  *operation                 `json:"operation"`
	Parameters map[string]any             `json:"parameters"`
	Context    connections.RequestContext `json:"context"`
	Title      string                     `json:"title"`
	Details    any                        `json:"details"`
}

type operation struct {
	ID      string   `json:"id"`
	Action  string   `json:"action"`
	Effects []string `json:"effects"`
	Lineage []string `json:"lineage"`
}

func resolveOperation(id, action string, effects []string, actions map[string]catalog.Action) *operation {
	op := operation{ID: id, Action: action}
	for a := action; a != ""; {
		op.Lineage = append(op.Lineage, a)
		i := strings.LastIndexByte(a, '.')
		if i < 0 {
			break
		}
		a = a[:i]
	}
	for i := 0; effects == nil && i < len(op.Lineage); i++ {
		effects = actions[op.Lineage[i]].Effects
	}
	if op.Action == "" || effects == nil {
		return nil
	}
	op.Effects, op.ID = slices.Compact(slices.Sorted(slices.Values(effects))), cmp.Or(op.ID, op.Action)
	return &op
}

type decisionInput struct {
	Facts         json.RawMessage    `json:"facts"`
	Authorization authorizationInput `json:"authorization"`
	Connection    connectionInput    `json:"connection"`
}

type authorizationInput struct {
	Access             config.Access       `json:"access"`
	Reaches            bool                `json:"reaches"`
	Effects            []map[string]string `json:"effects"`
	AllowPaidInference bool                `json:"allow_paid_inference"`
	Rules              []config.Rule       `json:"rules"`
	Approved           []string            `json:"approved"`
	Grant              map[string]any      `json:"grant"`
}

type connectionInput struct {
	Contents    string   `json:"contents"`
	Strangers   bool     `json:"strangers"`
	Sends       string   `json:"sends"`
	Private     []string `json:"private"`
	PublicScope []string `json:"public_scope"`
}

type adminCall struct {
	Caller policyCaller `json:"caller"`
	Route  string       `json:"route"`
	Answer any          `json:"answer,omitempty"`
	Record any          `json:"record,omitempty"`
}

type policyCaller struct {
	Name   string         `json:"name"`
	Owner  bool           `json:"owner"`
	Claims map[string]any `json:"claims"`
}

type capabilityInput struct {
	Principal  facts.Principal `json:"principal"`
	Routes     bool            `json:"routes"`
	Capability string          `json:"capability"`
}

const (
	capabilityConfig  = "config"
	capabilityPropose = "propose"
	capabilityRoutes  = "routes"
)

func (st *settings) capable(p facts.Principal, capability string) bool {
	var ok bool
	err := st.policy.Eval(context.Background(), config.QueryCapable, capabilityInput{Principal: p, Routes: st.Identities[p.Name].Operator, Capability: capability}, &ok)
	return ok && err == nil
}

func (st *settings) enforced() bool { return st.Lattices.Confidentiality || st.Lattices.Integrity }

func (st *settings) observe(connection string, event facts.Event) (requestFacts, error) {
	o, err := event.Decode()
	f := requestFacts{Parameters: o.Parameters, Scope: o.Scope, Title: o.Title, Details: o.Details}
	c := st.connections[connection]
	if c == nil {
		return f, errChanged
	}
	if refused := c.Hint(&o, &f.Context); err == nil {
		err = refused
	}
	if o.Operation != nil {
		f.Operation = resolveOperation(o.Operation.ID, o.Operation.Action, o.Operation.Effects, presets[st.Connections[connection].Preset].Catalog.Actions)
	}
	return f, err
}

func (st *settings) describe(p facts.Principal, connection string, gr *grant) (requestFacts, error) {
	var f requestFacts
	var err error
	if gr.admit != nil {
		f = *gr.admit
	} else {
		f, err = st.observe(connection, gr.event)
	}
	f.Version, f.Kind = config.FactsVersion, gr.kind
	f.Service, f.Connection = st.Connections[connection].Preset, connection
	f.Principal, f.Context.Label = p, gr.label
	if f.Parameters == nil {
		f.Parameters = map[string]any{}
	}
	if f.Scope == nil {
		f.Scope = f.Parameters
	}
	return f, err
}

func (st *settings) decide(ctx context.Context, p facts.Principal, connection string, gr *grant) (*record, error) {
	f, describeErr := st.describe(p, connection, gr)
	if describeErr != nil {
		f.Operation = nil
		raw, err := json.Marshal(f)
		if err != nil {
			return nil, err
		}
		return &record{Facts: raw, Invalid: true}, describeErr
	}
	encoded, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	access, settings := st.Access(p.Name, connection), st.Connections[connection]
	effects := []map[string]string{st.Effects, settings.Effects, st.Identities[p.Name].Effects, access.Effects}
	for i, scope := range effects {
		if scope == nil {
			effects[i] = map[string]string{}
		}
	}
	input := decisionInput{
		Facts: encoded,
		Authorization: authorizationInput{Access: access, Reaches: st.Reaches(p.Name, connection), Effects: effects, AllowPaidInference: st.AllowPaidInference,
			Rules: slices.Collect(maps.Values(st.Identities[p.Name].Rules)), Approved: gr.approved, Grant: f.Scope},
		Connection: connectionInput{Contents: settings.Contents, Strangers: settings.Strangers, Sends: settings.Sends,
			Private: append([]string{}, settings.PolicyOptions.Private...), PublicScope: append([]string{}, st.publicScope[connection]...)},
	}
	next := &record{Facts: encoded, Grant: f.Scope}
	err = st.policy.Eval(ctx, config.QueryDecision, input, &next.Decision)
	return next, err
}

func (s *state) label(key string) format.Label {
	if l, ok := s.doc.Labels[key]; ok {
		return l
	}
	return config.InitialLabel
}

func (s *state) decideGrant(ctx context.Context, a *admitted, gr *grant) (*record, error) {
	p, ok := s.identities.Lookup(a.key)
	if !ok {
		return nil, errRemoved
	}
	if !a.valid() {
		return nil, errChanged
	}
	return s.settings.Load().decide(ctx, p, a.connection, gr)
}

func (s *state) authorize(ctx context.Context, a *admitted, gr *grant) (*record, error) {
	var r *record
	gr.approved = []string{}
	for {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		if s.audit.Backlogged() {
			return r, errAuditBacklog
		}
		gr.label = s.label(a.key)
		next, err := s.decideGrant(ctx, a, gr)
		if next != nil && next.Invalid {
			s.addRecord(next)
			return next, err
		}
		if err != nil {
			return r, err
		}
		if r == nil {
			s.addRecord(next)
			r = next
		}
		r.Facts, r.Decision, r.Grant = next.Facts, next.Decision, next.Grant
		if len(r.Deny) != 0 {
			return r, errors.New(strings.Join(r.Deny, "; "))
		}
		if len(r.Requirements) == 0 {
			if r.State == statePending {
				r.State = stateAllowed
			}
			return r, ctx.Err()
		}
		if err := s.awaitAnswer(ctx, r); err != nil {
			return r, err
		}
		if r.State == stateApproved {
			for _, requirement := range r.Requirements {
				gr.approved = append(gr.approved, requirement.ID)
			}
		}
	}
}

func (s *state) awaitAnswer(ctx context.Context, r *record) error {
	if r.State != statePending {
		r.State, r.Expires = statePending, time.Now().Add(approvalWait)
		s.announce(r)
	}
	expired := s.records.Wait(ctx, r.Expires)
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.State == stateDenied {
		return errors.New("this request was denied")
	}
	if r.State == stateApproved || !expired {
		return nil
	}
	r.State = stateExpired
	return errors.New("waiting for approval in the Perimeter timed out")
}

func (s *state) admit(ctx context.Context, p facts.Principal, req core.Request) (core.Watch, error) {
	a := &admitted{key: p.Key, connection: req.Connection, perMessage: req.PerMessage, valid: req.Valid}
	gr := &grant{kind: config.KindAdmission, admit: &requestFacts{
		Operation:  &operation{Action: "session.admit", Effects: []string{"session"}},
		Title:      "Open " + req.Connection,
		Parameters: map[string]any{"host": req.Host, "port": req.Port},
		Details:    map[string]any{"tcp": map[string]any{"host": req.Host, "port": req.Port}},
		Context:    connections.RequestContext{Observes: config.InitialLabel},
	}}
	var err error
	s.locked(func() {
		var r *record
		r, err = s.authorize(ctx, a, gr)
		if r != nil {
			s.settleRecord(r, err)
		}
		a.grants = []*grant{gr}
	})
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, end func()) (gate core.Gate, ok bool) {
		s.locked(func() {
			if ok = s.recheck(a); !ok {
				return
			}
			remove := s.admissions.Add(a, end)
			context.AfterFunc(ctx, func() { s.locked(remove) })
			gate = func(op context.Context, event facts.Event) error { return s.operation(op, ctx, a, event) }
		})
		return gate, ok
	}, nil
}

func (s *state) operation(ctx, stream context.Context, a *admitted, event facts.Event) error {
	if err := stream.Err(); err != nil {
		return err
	}
	ctx, cancel := netx.Bind(ctx, stream)
	defer cancel()
	var err error
	s.locked(func() {
		gr := &grant{kind: config.KindOperation, event: event}
		var r *record
		r, err = s.authorize(ctx, a, gr)
		if r != nil {
			if err == nil {
				err = s.relabel(ctx, a.key, r.Next, a)
			}
			s.settleRecord(r, err)
		}
		if err == nil {
			a.grants = append(a.grants[:1], gr)
		}
	})
	return err
}

func (s *state) recheck(a *admitted) bool {
	if a.capability != "" {
		return s.capable(a.key, a.capability)
	}
	for _, gr := range a.grants {
		if d, err := s.decideGrant(context.Background(), a, gr); err != nil || len(d.Deny) != 0 || len(d.Requirements) != 0 {
			return false
		}
	}
	return true
}

func (s *state) relabel(ctx context.Context, key string, l format.Label, source *admitted) error {
	if old := s.label(key); old.Trust == l.Trust && old.Audience == l.Audience {
		return nil
	}
	next := s.doc
	next.Labels = maps.Clone(next.Labels)
	next.Labels[key] = l
	if err := s.commit(ctx, next); err != nil {
		return err
	}
	if source != nil && !s.settings.Load().enforced() {
		return nil
	}
	s.admissions.Recheck(func(a *admitted) bool {
		return a.key != key || a.capability != "" || a == source || source != nil && a.perMessage
	})
	return nil
}

func (s *state) capable(key, capability string) bool {
	p, known := s.identities.Lookup(key)
	st := s.settings.Load()
	return known && st != nil && st.capable(p, capability)
}

func (s *state) hold(ctx context.Context, key, capability string) (context.Context, context.CancelFunc, bool) {
	ctx, release, ok := s.identities.Hold(ctx, key)
	if !ok {
		return nil, nil, false
	}
	var cancel context.CancelFunc
	s.locked(func() {
		if ok = s.capable(key, capability); !ok {
			release()
			return
		}
		ctx, cancel = context.WithCancel(ctx)
		remove := s.admissions.Add(&admitted{key: key, capability: capability}, cancel)
		context.AfterFunc(ctx, func() { s.locked(remove) })
	})
	if !ok {
		return nil, nil, false
	}
	return ctx, func() { cancel(); release() }, true
}

func (s *state) recheckAll() {
	s.admissions.Recheck(s.recheck)
	s.records.Notify()
}
