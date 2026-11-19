package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/config"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/connections"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/format"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/catalog"
	"github.com/tinfoilsh/confidential-agent-monitor/core"
	"github.com/tinfoilsh/confidential-agent-monitor/core/connector"
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
	errRestarted    = errors.New("the Perimeter restarted before this request was answered; retry it")
)

const approvalWait = 2 * time.Minute

type admitted struct {
	fingerprint, connection string
	name                    string
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
	Operation  *catalog.Operation         `json:"operation"`
	Parameters map[string]any             `json:"parameters"`
	Context    connections.RequestContext `json:"context"`
	Title      string                     `json:"title"`
	Details    any                        `json:"details"`
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
		f.Operation = presets[st.Connections[connection].Preset].Catalog.Resolve(o.Operation.ID, o.Operation.Action, o.Operation.Effects)
	}
	if st.Connections[connection].MatchOnly && err == nil {
		matchOnly(&f, presets[st.Connections[connection].Preset].Title)
	}
	return f, err
}

// A match-only connection describes every valid request as its one broad request, sent to the connection's audience.
// Sign-ins keep their own description, and invalid requests stay refused.
func matchOnly(f *requestFacts, title string) {
	if f.Operation != nil && slices.Contains(f.Operation.Effects, "session") {
		return
	}
	// The one operation's name says nothing, so an HTTP request is titled by what it asks for.
	var details struct {
		HTTP *struct{ Method, Host, Path string } `json:"http"`
	}
	if raw, err := json.Marshal(f.Details); err == nil && json.Unmarshal(raw, &details) == nil && details.HTTP != nil && details.HTTP.Method != "" {
		f.Title = fmt.Sprintf("%s: %s %s%s", cmp.Or(title, "Service"), details.HTTP.Method, details.HTTP.Host, details.HTTP.Path)
	}
	if f.Operation == nil || f.Operation.Action != config.MatchOnlyAction {
		f.Operation = &catalog.Operation{ID: config.MatchOnlyAction, Action: config.MatchOnlyAction, Effects: slices.Clone(config.MatchOnlyEffects), Lineage: []string{config.MatchOnlyAction}}
	}
	if f.Context.Sends == "" {
		f.Context.Sends = config.SendsConnection
	}
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

func (s held) label(name string) format.Label {
	if l, ok := s.doc.Labels[name]; ok {
		return l
	}
	return config.InitialLabel
}

func (s held) decideGrant(ctx context.Context, a *admitted, gr *grant) (*record, error) {
	p, ok := s.identities.Lookup(a.fingerprint)
	if !ok || p.Name != a.name {
		return nil, errRemoved
	}
	if !a.valid() {
		return nil, errChanged
	}
	return s.settings.Load().decide(ctx, p, a.connection, gr)
}

func (s held) authorize(ctx context.Context, a *admitted, gr *grant) (r *record, err error) {
	defer func() {
		if r != nil {
			err = cmp.Or(err, s.queue(s.life, r, false))
		}
	}()
	gr.approved = []string{}
	for {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		if s.audit.Backlogged() {
			return r, errAuditBacklog
		}
		gr.label = s.label(a.name)
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
	fresh := r.State != statePending
	if fresh {
		r.State, r.Expires = statePending, time.Now().Add(approvalWait)
	}
	if err := s.queue(ctx, r, true); err != nil {
		return err
	}
	if fresh {
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

// A record stays in the stored document while it awaits an answer, so the next unlock settles it.
func (s held) queue(ctx context.Context, r *record, pending bool) error {
	var raw json.RawMessage
	if pending {
		var err error
		if raw, err = json.Marshal(r); err != nil {
			return err
		}
	}
	if stored, queued := s.doc.Pending[r.ID]; queued == pending && bytes.Equal(stored, raw) {
		return nil
	}
	next := s.doc
	next.Pending = map[string]json.RawMessage{}
	maps.Copy(next.Pending, s.doc.Pending)
	delete(next.Pending, r.ID)
	if pending {
		next.Pending[r.ID] = raw
	}
	return s.commit(ctx, next)
}

func (s *state) admit(ctx context.Context, p facts.Principal, req core.Request) (core.Watch, error) {
	a := &admitted{fingerprint: p.Key, name: p.Name, connection: req.Connection, valid: req.Valid}
	gr := &grant{kind: config.KindAdmission, admit: &requestFacts{
		Operation:  &catalog.Operation{Action: "session.admit", Effects: []string{"session"}},
		Title:      "Open " + req.Connection,
		Parameters: map[string]any{"host": req.Target.Host, "port": req.Target.Port},
		Details:    map[string]any{req.Target.Network: map[string]any{"host": req.Target.Host, "port": req.Target.Port}},
		Context:    connections.RequestContext{Observes: config.InitialLabel},
	}}
	var err error
	s.locked(func(h held) {
		if c := h.settings.Load().connections[req.Connection]; c != nil {
			a.perMessage = c.PerMessage
		}
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
	return func(ctx context.Context, end func()) (gate connector.Gate, ok bool) {
		s.locked(func(h held) {
			if ok = h.recheck(a); !ok {
				return
			}
			h.admissions.Hold(ctx, a, end)
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
				err = h.relabel(ctx, a.name, r.Next, a)
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

func (s held) relabel(ctx context.Context, name string, l format.Label, source *admitted) error {
	if old := s.label(name); old.Trust == l.Trust && old.Audience == l.Audience {
		return nil
	}
	next := s.doc
	next.Labels = maps.Clone(next.Labels)
	next.Labels[name] = l
	if err := s.commit(ctx, next); err != nil {
		return err
	}
	if source != nil && !s.settings.Load().enforced() {
		return nil
	}
	s.admissions.Recheck(func(a *admitted) bool {
		unaffected := a.name != name || a.capability != ""
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
		h.admissions.Hold(ctx, &admitted{fingerprint: fingerprint, capability: capability}, cancel)
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
