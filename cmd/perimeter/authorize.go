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
	errNotAllowed   = errors.New("policy does not allow this request")
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

type record struct {
	ID      string          `json:"id"`
	State   string          `json:"state"`
	Invalid bool            `json:"invalid,omitempty"`
	Time    time.Time       `json:"time"`
	Expires time.Time       `json:"expires,omitzero"`
	Facts   json.RawMessage `json:"facts"`
	config.Decision
	Scope   map[string]any  `json:"grant"`
	Reviews []Review        `json:"reviews,omitempty"`
	Changes []format.Change `json:"changes,omitempty"`
}

type admitted struct {
	fingerprint, connection string
	capability              string
	perMessage              bool
	valid                   func() bool
	admission, latest       *grant
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

const (
	capabilityConfig  = "config"
	capabilityPropose = "propose"
	capabilityRoutes  = "routes"
)

func (st *settings) capable(p facts.Principal, capability string) bool {
	var ok bool
	err := st.policy.Eval(context.Background(), config.QueryCapable, config.CapabilityInput{Principal: p, Routes: st.Identities[p.Name].Routes, Capability: capability}, &ok)
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

func (st *settings) decide(ctx context.Context, p facts.Principal, connection string, gr *grant) (*record, error) {
	var f requestFacts
	var invalid error
	if gr.admit != nil {
		f = *gr.admit
	} else {
		f, invalid = st.observe(connection, gr.event)
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
	if invalid != nil {
		f.Operation = nil
		raw, err := json.Marshal(f)
		if err != nil {
			return nil, err
		}
		return &record{Facts: raw, Invalid: true}, invalid
	}

	encoded, err := json.Marshal(f)
	if err != nil {
		return nil, err
	}
	access, conn := st.Access(p.Name, connection), st.Connections[connection]
	effects := []map[string]string{st.Effects, conn.Effects, st.Identities[p.Name].Effects, access.Effects}
	for i, scope := range effects {
		if scope == nil {
			effects[i] = map[string]string{}
		}
	}
	input := config.DecisionInput{
		Facts: encoded,
		Authorization: config.AuthorizationInput{Access: access, Reaches: st.Reaches(p.Name, connection), Effects: effects, AllowPaidInference: st.AllowPaidInference,
			Rules: slices.Collect(maps.Values(st.Identities[p.Name].Rules)), Approved: gr.approved, Scope: f.Scope},
		Connection: config.ConnectionInput{Contents: conn.Contents, Strangers: conn.Strangers, Sends: conn.Sends,
			Private: append([]string{}, conn.PolicyOptions.Private...), PublicScope: append([]string{}, st.publicScope[connection]...)},
	}
	next := &record{Facts: encoded, Scope: f.Scope}
	err = st.policy.Eval(ctx, config.QueryDecision, input, &next.Decision)
	return next, err
}

func (s held) label(fingerprint string) format.Label {
	if l, ok := s.doc.Labels[fingerprint]; ok {
		return l
	}
	return config.InitialLabel
}

func (s held) decideGrant(ctx context.Context, a *admitted, gr *grant) (*record, error) {
	p, ok := s.identities.Lookup(a.fingerprint)
	if !ok {
		return nil, errRemoved
	}
	if !a.valid() {
		return nil, errChanged
	}
	return s.settings.Load().decide(ctx, p, a.connection, gr)
}

func (s held) authorize(ctx context.Context, a *admitted, gr *grant) (*record, error) {
	var r *record
	gr.approved = []string{}
	for {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		if s.audit.Backlogged() {
			return r, errAuditBacklog
		}
		gr.label = s.label(a.fingerprint)
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
		r.Facts, r.Decision, r.Scope = next.Facts, next.Decision, next.Scope
		if r.Allow {
			if r.State == statePending {
				r.State = stateAllowed
			}
			return r, ctx.Err()
		}
		if len(r.Deny) != 0 {
			return r, errors.New(strings.Join(r.Deny, "; "))
		}
		if len(r.Requirements) == 0 {
			return r, errNotAllowed
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

func (s held) awaitAnswer(ctx context.Context, r *record) error {
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
	a := &admitted{fingerprint: p.Key, connection: req.Connection, perMessage: req.PerMessage, valid: req.Valid}
	gr := &grant{kind: config.KindAdmission, admit: &requestFacts{
		Operation:  &operation{Action: "session.admit", Effects: []string{"session"}},
		Title:      "Open " + req.Connection,
		Parameters: map[string]any{"host": req.Host, "port": req.Port},
		Details:    map[string]any{"tcp": map[string]any{"host": req.Host, "port": req.Port}},
		Context:    connections.RequestContext{Observes: config.InitialLabel},
	}}
	var err error
	s.locked(func(h held) {
		var r *record
		r, err = h.authorize(ctx, a, gr)
		if r != nil {
			h.settleRecord(r, err)
		}
		a.admission = gr
	})
	if err != nil {
		return nil, err
	}
	return func(ctx context.Context, end func()) (gate core.Gate, ok bool) {
		s.locked(func(h held) {
			if ok = h.recheck(a); !ok {
				return
			}
			remove := h.admissions.Add(a, end)
			context.AfterFunc(ctx, func() { s.locked(func(held) { remove() }) })
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
	s.locked(func(h held) {
		gr := &grant{kind: config.KindOperation, event: event}
		var r *record
		r, err = h.authorize(ctx, a, gr)
		if r != nil {
			if err == nil {
				err = h.relabel(ctx, a.fingerprint, r.Next, a)
			}
			h.settleRecord(r, err)
		}
		if err == nil {
			a.latest = gr
		}
	})
	return err
}

func (s held) recheck(a *admitted) bool {
	if a.capability != "" {
		return s.capable(a.fingerprint, a.capability)
	}
	for _, gr := range []*grant{a.admission, a.latest} {
		if gr == nil {
			continue
		}
		if d, err := s.decideGrant(context.Background(), a, gr); err != nil || !d.Allow {
			return false
		}
	}
	return true
}

func (s held) relabel(ctx context.Context, fingerprint string, l format.Label, source *admitted) error {
	if old := s.label(fingerprint); old.Trust == l.Trust && old.Audience == l.Audience {
		return nil
	}
	next := s.doc
	next.Labels = maps.Clone(next.Labels)
	next.Labels[fingerprint] = l
	if err := s.commit(ctx, next); err != nil {
		return err
	}
	if source != nil && !s.settings.Load().enforced() {
		return nil
	}
	s.admissions.Recheck(func(a *admitted) bool {
		unaffected := a.fingerprint != fingerprint || a.capability != ""
		gated := source != nil && a.perMessage
		return unaffected || a == source || gated
	})
	return nil
}

func (s *state) capable(fingerprint, capability string) bool {
	p, known := s.identities.Lookup(fingerprint)
	st := s.settings.Load()
	return known && st != nil && st.capable(p, capability)
}

func (s *state) hold(ctx context.Context, fingerprint, capability string) (context.Context, context.CancelFunc, bool) {
	ctx, release, ok := s.identities.Hold(ctx, fingerprint)
	if !ok {
		return nil, nil, false
	}
	var cancel context.CancelFunc
	s.locked(func(h held) {
		if ok = s.capable(fingerprint, capability); !ok {
			release()
			return
		}
		ctx, cancel = context.WithCancel(ctx)
		remove := h.admissions.Add(&admitted{fingerprint: fingerprint, capability: capability}, cancel)
		context.AfterFunc(ctx, func() { s.locked(func(held) { remove() }) })
	})
	if !ok {
		return nil, nil, false
	}
	return ctx, func() { cancel(); release() }, true
}

func (s held) recheckAll() {
	s.admissions.Recheck(s.recheck)
	s.records.Notify()
}
