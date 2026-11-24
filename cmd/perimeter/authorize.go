package main

import (
	"bytes"
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
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

type cause string

const (
	causeInvalid      cause = "invalid"
	causePrecondition cause = "precondition"
	causeDenied       cause = "denied"
	causeRejected     cause = "rejected"
	causeExpired      cause = "expired"
)

type refusal struct {
	Cause   cause    `json:"cause"`
	Reasons []string `json:"reasons,omitempty"`
}

func refuse(c cause, reasons ...string) *refusal { return &refusal{Cause: c, Reasons: reasons} }

func (r *refusal) Error() string { return strings.Join(r.Reasons, "; ") }

// An expired ask is forbidden too, since a retry would only ask again.
func (r *refusal) HTTPStatus() int {
	switch {
	case r == errChanged || r == errRemoved:
		return http.StatusConflict
	case r.Cause == causePrecondition:
		return http.StatusServiceUnavailable
	case r.Cause == causeInvalid:
		return http.StatusBadRequest
	}
	return http.StatusForbidden
}

func precondition(err error) *refusal {
	if err == nil {
		return nil
	}
	return refuse(causePrecondition, err.Error())
}

func (r *refusal) state() string {
	switch r.Cause {
	case causeRejected:
		return stateDenied
	case causeExpired:
		return stateExpired
	}
	return stateRefused
}

var (
	errRemoved      = refuse(causePrecondition, "this agent's identity was removed")
	errChanged      = refuse(causePrecondition, "configuration changed; retry the request")
	errAuditBacklog = refuse(causePrecondition, "the Perimeter cannot write its audit log; requests are refused until storage recovers")
	errRestarted    = refuse(causePrecondition, "the Perimeter restarted before this request was answered; retry it")
	errRejected     = refuse(causeRejected, "this request was denied")
	errExpired      = refuse(causeExpired, "waiting for approval in the Perimeter timed out")
)

var errNoAccess = errors.New("key has no agent access")

const (
	approvalWait = 2 * time.Minute
	// A stream forgets its oldest allowed event beyond this many.
	maxStreamEvents = 256
)

type stream struct {
	fingerprint, connection string
	name                    string
	perMessage              bool
	valid                   func() bool
	opened                  *request
	allowed                 []*request
}

// The perimeter connection is built in, so it never changes.
func apiStream(fingerprint, name string) *stream {
	return &stream{fingerprint: fingerprint, connection: config.PerimeterConnection, name: name, valid: func() bool { return true }}
}

type request struct {
	kind     string
	event    facts.Event
	known    *requestFacts
	label    format.Label
	approved []string
}

type requestFacts struct {
	Scope      map[string]any     `json:"-"`
	Version    int                `json:"version"`
	Kind       string             `json:"kind"`
	Principal  facts.Principal    `json:"principal"`
	Service    string             `json:"service"`
	Connection string             `json:"connection"`
	Operation  *catalog.Operation `json:"operation"`
	Parameters map[string]any     `json:"parameters"`
	Context    requestContext     `json:"context"`
	Title      string             `json:"title"`
	Details    any                `json:"details"`
}

type requestContext struct {
	Label format.Label `json:"label"`
	connections.Flow
}

func (st *settings) latticesOn() bool { return st.Lattices.Confidentiality || st.Lattices.Integrity }

func (st *settings) eventFacts(connection string, event facts.Event) (requestFacts, *refusal) {
	o, err := event.Decode()
	c := st.connections[connection]
	if c != nil && err == nil {
		return st.observationFacts(connection, o, c.Observe)
	}
	f := requestFacts{Parameters: o.Parameters, Scope: o.Scope, Title: o.Title, Details: o.Details}
	if c == nil {
		return f, errChanged
	}
	return f, refuse(causeInvalid, err.Error())
}

func (st *settings) observationFacts(connection string, o facts.Observation, observe connections.Observe) (requestFacts, *refusal) {
	f := requestFacts{Parameters: o.Parameters, Scope: o.Scope, Title: o.Title, Details: o.Details, Context: requestContext{Flow: observe(o)}}
	// An operation with no effects would skip every access setting.
	if o.Operation != nil && o.Operation.Effects != nil && !config.ValidEffects(o.Operation.Effects) {
		return f, refuse(causeInvalid, "an operation's effects must be one or more effects of the vocabulary")
	}
	actions := st.Presets[st.Connections[connection].Preset].Catalog
	if o.Operation != nil {
		f.Operation = actions.Resolve(o.Operation.ID, o.Operation.Action, o.Operation.Effects)
	}
	// A match-only connection does not fail closed: a valid request it does not recognize is a Custom API request.
	if f.Operation == nil && st.Connections[connection].MatchOnly {
		if websocket, _ := connections.WebSocket(o); !websocket {
			f.Operation = actions.Resolve("", config.CustomAction, config.CustomEffects)
			f.Context.Sends = config.SendsConnection
		}
	}
	return f, nil
}

func (st *settings) decide(ctx context.Context, p facts.Principal, connection string, req *request) (*record, *refusal) {
	var f requestFacts
	var refused *refusal
	if req.known != nil {
		f = *req.known
	} else {
		f, refused = st.eventFacts(connection, req.event)
	}
	st.completeFacts(&f, p, connection, req.kind, req.label)
	if refused != nil {
		f.Operation = nil
	}
	encoded, err := json.Marshal(f)
	if err != nil {
		return nil, refuse(causeInvalid, err.Error())
	}
	r := &record{Facts: encoded, Scope: f.Scope}
	if refused != nil {
		return r, refused
	}
	conn := st.Connections[connection]
	input := config.DecisionInput{
		Facts: encoded,
		Authorization: config.AuthorizationInput{Modes: st.EffectModes(p.Name, p.Groups, connection, f.Operation, req.kind), Rules: st.LiveRules(p.Name, time.Now()),
			Approved: req.approved, Scope: f.Scope},
		Connection: config.ConnectionInput{Contents: conn.Contents, Strangers: conn.Strangers, Sends: conn.Sends, Address: conn.PolicyOptions.Address,
			Private: append([]string{}, conn.PolicyOptions.Private...), PublicScope: append([]string{}, st.publicScope[connection]...)},
	}
	d, err := st.policy.Decide(ctx, input)
	if err != nil {
		return r, cmp.Or(precondition(ctx.Err()), refuse(causeDenied, err.Error()))
	}
	r.Decision = &d
	return r, nil
}

func (st *settings) completeFacts(f *requestFacts, p facts.Principal, connection, kind string, label format.Label) {
	f.Version, f.Kind = config.FactsVersion, kind
	f.Service, f.Connection = st.Connections[connection].Preset, connection
	f.Principal, f.Context.Label = p, label
	if f.Parameters == nil {
		f.Parameters = map[string]any{}
	}
	if f.Scope == nil {
		f.Scope = f.Parameters
	}
}

func (st *settings) decideOnly(ctx context.Context, p facts.Principal, label format.Label, connection, kind string, f *requestFacts) (*config.Decision, *refusal) {
	r, refused := st.decide(ctx, p, connection, &request{kind: kind, known: f, label: label, approved: []string{}})
	if refused != nil {
		return nil, refused
	}
	return r.Decision, nil
}

func (st *settings) wouldAllow(p facts.Principal, label format.Label, c facts.Observation) *config.Decision {
	d, refused := st.decideOnly(context.Background(), p, label, config.PerimeterConnection, config.KindOperation, st.callFacts(c))
	if refused != nil || d.Outcome != config.OutcomeAllow {
		return nil
	}
	return d
}

func (s held) label(name string) format.Label {
	if l, ok := s.doc.Labels[name]; ok {
		return l
	}
	return config.InitialLabel
}

func (s held) decideRequest(ctx context.Context, a *stream, req *request) (*record, *refusal) {
	p, ok := s.identities.Lookup(a.fingerprint)
	if !ok || p.Name != a.name {
		return nil, errRemoved
	}
	if !a.valid() {
		return nil, errChanged
	}
	return s.settings.Load().decide(ctx, p, a.connection, req)
}

func (s held) authorize(ctx context.Context, a *stream, req *request) *refusal {
	r, refused := s.decideUntilAnswered(ctx, a, req)
	if r == nil {
		return refused
	}
	refused = cmp.Or(refused, precondition(s.setPending(s.life, r, false)))
	if refused == nil {
		refused = precondition(s.relabel(ctx, a.name, *r.Decision.Next, a))
	}
	s.settleRecord(r, refused)
	return refused
}

// The deadline runs from when the gaps last changed, so it holds while they do not.
func (s held) decideUntilAnswered(ctx context.Context, a *stream, req *request) (*record, *refusal) {
	req.approved = []string{}
	var r *record
	var asked []string
	for {
		if err := ctx.Err(); err != nil {
			return r, precondition(err)
		}
		if s.audit.Backlogged() {
			return r, errAuditBacklog
		}
		req.label = s.label(a.name)
		next, refused := s.decideRequest(ctx, a, req)
		if next == nil {
			return r, refused
		}
		if r == nil {
			r = s.addRecord(next)
		}
		r.Facts, r.Decision, r.Scope = next.Facts, next.Decision, next.Scope
		if refused != nil {
			return r, refused
		}
		switch r.Decision.Outcome {
		case config.OutcomeAllow:
			return r, nil
		case config.OutcomeDeny:
			return r, refuse(causeDenied, r.Decision.Reasons...)
		}
		gaps := gapIDs(r.Decision.Gaps)
		fresh := !slices.Equal(gaps, asked)
		if fresh {
			asked, r.Expires = gaps, time.Now().Add(approvalWait)
		}
		approved, refused := s.awaitAnswer(ctx, r, fresh)
		if refused != nil {
			return r, refused
		}
		// An answer waives exactly the gaps it was given; a later decision can still deny.
		if approved {
			req.approved = append(req.approved, gaps...)
		}
	}
}

func gapIDs(gaps []config.Requirement) []string {
	ids := make([]string, len(gaps))
	for i, gap := range gaps {
		ids[i] = gap.ID
	}
	slices.Sort(ids)
	return slices.Compact(ids)
}

func (s held) awaitAnswer(ctx context.Context, r *record, fresh bool) (bool, *refusal) {
	if err := s.setPending(ctx, r, true); err != nil {
		return false, precondition(err)
	}
	if fresh {
		s.announce(r)
	}
	answered := len(r.Reviews)
	expired := s.records.Wait(ctx, r.Expires)
	if err := ctx.Err(); err != nil {
		return false, precondition(err)
	}
	answers := r.Reviews[answered:]
	switch {
	case slices.ContainsFunc(answers, func(review Review) bool { return review.Choice == answerDeny }):
		return false, errRejected
	case len(answers) != 0:
		return true, nil
	case expired:
		return false, errExpired
	}
	return false, nil
}

// A record stays in the stored document while it awaits an answer, so the next unlock settles it.
func (s held) setPending(ctx context.Context, r *record, pending bool) error {
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

func (s *state) admit(ctx context.Context, p facts.Principal, opening core.Request) (core.Watch, error) {
	a := &stream{fingerprint: p.Key, name: p.Name, connection: opening.Connection, valid: opening.Valid}
	req := &request{kind: config.KindAdmission, known: &requestFacts{
		Title:      "Open " + opening.Connection,
		Parameters: map[string]any{"host": opening.Target.Host, "port": opening.Target.Port},
		Details:    map[string]any{opening.Target.Network: map[string]any{"host": opening.Target.Host, "port": opening.Target.Port}},
	}}
	var refused *refusal
	s.locked(func(h held) {
		if c := h.settings.Load().connections[opening.Connection]; c != nil {
			a.perMessage = c.PerMessage
		}
		refused = h.authorize(ctx, a, req)
		a.opened = req
	})
	if refused != nil {
		return nil, refused
	}
	return func(ctx context.Context, end func()) (gate connector.Gate, ok bool) {
		s.locked(func(h held) {
			if ok = h.recheck(a); !ok {
				return
			}
			h.admissions.Hold(ctx, a, end)
			gate = func(op context.Context, event facts.Event) error { return s.authorizeOperation(op, ctx, a, event) }
		})
		return gate, ok
	}, nil
}

func (s *state) authorizeOperation(ctx, connected context.Context, a *stream, event facts.Event) error {
	if err := connected.Err(); err != nil {
		return precondition(err)
	}
	ctx, cancel := netx.Bind(ctx, connected)
	defer cancel()
	var refused *refusal
	s.locked(func(h held) {
		req := &request{kind: config.KindOperation, event: event}
		if refused = h.authorize(ctx, a, req); refused == nil {
			a.remember(req)
		}
	})
	if refused != nil {
		return refused
	}
	return nil
}

// A repeated event is rechecked once, with every approval it was allowed with.
func (a *stream) remember(req *request) {
	if i := slices.IndexFunc(a.allowed, func(g *request) bool { return g.event == req.event }); i >= 0 {
		req.approved = slices.Compact(slices.Sorted(slices.Values(append(req.approved, a.allowed[i].approved...))))
		a.allowed = slices.Delete(a.allowed, i, i+1)
	}
	if a.allowed = append(a.allowed, req); len(a.allowed) > maxStreamEvents {
		a.allowed = slices.Delete(a.allowed, 0, 1)
	}
}

// Requests keep the label they were allowed under; a removed identity or connection ends the stream without a revoked record.
func (s held) recheck(a *stream) bool {
	for _, req := range slices.Concat([]*request{a.opened}, a.allowed) {
		r, refused := s.decideRequest(context.Background(), a, req)
		switch {
		case refused == nil && r.Decision.Outcome == config.OutcomeAllow:
			continue
		case r != nil && (refused == nil || refused.Cause != causePrecondition):
			s.revokeRecord(r, refused)
		}
		return false
	}
	return true
}

func (s held) relabel(ctx context.Context, name string, l format.Label, source *stream) error {
	if old := s.label(name); old.Trust == l.Trust && old.Audience == l.Audience {
		return nil
	}
	next := s.doc
	next.Labels = maps.Clone(next.Labels)
	next.Labels[name] = l
	if err := s.commit(ctx, next); err != nil {
		return err
	}
	s.records.Notify()
	if source != nil && !s.settings.Load().latticesOn() {
		return nil
	}
	s.admissions.Recheck(func(a *stream) bool {
		unaffected := a.name != name || a.connection == config.PerimeterConnection
		gated := source != nil && a.perMessage
		return unaffected || a == source || gated
	})
	return nil
}

// Rechecked like a stream's admission, so a settings change that refuses routes.publish ends the hold.
func (s *state) holdRoutes(ctx context.Context, fingerprint string) (context.Context, context.CancelFunc, bool) {
	routed, release, ok := s.identities.Hold(context.WithoutCancel(ctx), fingerprint)
	if !ok {
		return nil, nil, false
	}
	wait, stop := netx.Bind(ctx, routed)
	defer stop()
	var cancel context.CancelFunc
	s.locked(func(h held) {
		p, known := s.identities.Lookup(fingerprint)
		st := h.settings.Load()
		if ok = known && st != nil; !ok {
			return
		}
		a := apiStream(fingerprint, p.Name)
		a.opened = &request{kind: config.KindOperation, known: st.callFacts(perimeterCall(config.RoutesPublish, nil))}
		if ok = h.authorize(wait, a, a.opened) == nil; ok {
			routed, cancel = context.WithCancel(routed)
			h.admissions.Hold(routed, a, cancel)
		}
	})
	if !ok {
		release()
		return nil, nil, false
	}
	return routed, func() { cancel(); release() }, true
}

func (s held) recheckAll() {
	s.admissions.Recheck(s.recheck)
	s.records.Notify()
}
