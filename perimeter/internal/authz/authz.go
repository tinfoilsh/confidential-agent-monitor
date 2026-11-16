// Package authz decides admissions and operations under policy, waits for the owner's approval
// of what policy requires, and revokes what a later policy or label no longer allows.
package authz

import (
	"context"
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/identity"
	"github.com/tinfoilsh/confidential-agent-monitor/core/netx"
)

var (
	ErrRemoved      = errors.New("this agent's identity was removed")
	ErrChanged      = errors.New("configuration changed; retry the request")
	errAuditBacklog = errors.New("the Perimeter cannot write its audit log; requests are refused until storage recovers")
)

// Policy decides under one settings snapshot.
type Policy interface {
	// Decide fills a record with q's facts and grant and, unless they are invalid, policy's decision.
	Decide(ctx context.Context, q Query) (*Record, error)
	Capable(p facts.Principal, capability string) bool
	// Enforced reports whether policy enforces labels.
	Enforced() bool
}

type Query struct {
	Principal  facts.Principal
	Connection string
	Kind       facts.Kind
	Event      facts.Event
	Label      facts.Label
	// Approved names the requirements the owner answered for this request alone.
	Approved []string
}

// Store persists labels and settled records, and announces pending ones.
type Store interface {
	// Add assigns the record identity and retains it before it can wait or settle.
	Add(r *Record)
	Label(key string) (facts.Label, bool)
	Relabel(ctx context.Context, key string, l facts.Label) error
	Settled(r *Record)
	Announce(r *Record)
	Backlogged() bool
}

// An Admission is one key's stream to one connection, or its lease of a capability.
type Admission struct {
	Key, Connection string
	// capability makes the admission a lease of it, which a label change never revokes.
	capability string
	// PerMessage streams gate every operation, so they outlive a change to their key's label.
	PerMessage bool
	// Valid reports, under L, that the connection still serves this admission.
	Valid func() bool
	// The admission, then the latest operation.
	grants []*grant
}

// A grant is an allowed event a settings write re-decides, with the label it was
// decided under and the requirements the owner answered for it alone.
type grant struct {
	kind     facts.Kind
	event    facts.Event
	label    facts.Label
	approved []string
}

// Gatekeeper runs under L, the host's lock, as a sync.Cond does: Admit, Watch's gate and Hold
// take it, and the host holds it to call every other method.
type Gatekeeper struct {
	l          *sync.Mutex
	cond       sync.Cond
	identities *identity.Registry
	policy     func() Policy
	store      Store
	wait       time.Duration
	initial    facts.Label
	admitted   map[*Admission]func() // ends each live admission
}

// New decides under the policy that policy returns, nil while there is none.
func New(l *sync.Mutex, identities *identity.Registry, policy func() Policy, store Store, approvalWait time.Duration, initial facts.Label) *Gatekeeper {
	g := &Gatekeeper{l: l, identities: identities, policy: policy, store: store, wait: approvalWait, initial: initial,
		admitted: map[*Admission]func(){}}
	g.cond.L = l
	return g
}

// Admit decides a's admission, which event describes, waiting for any approval it requires.
func (g *Gatekeeper) Admit(ctx context.Context, a *Admission, event facts.Event) error {
	g.l.Lock()
	defer g.l.Unlock()
	gr := &grant{kind: facts.KindAdmission, event: event}
	r, err := g.authorize(ctx, a, gr)
	if r != nil {
		g.Settle(r, err)
	}
	a.grants = []*grant{gr}
	return err
}

// Watch gates a's operations until ctx ends and calls end once current settings would not admit it.
// It reports false when they already would not.
func (g *Gatekeeper) Watch(ctx context.Context, end func(), a *Admission) (func(context.Context, facts.Event) error, bool) {
	if !g.recheck(a) {
		return nil, false
	}
	g.admitted[a] = end
	context.AfterFunc(ctx, func() { g.l.Lock(); delete(g.admitted, a); g.l.Unlock() })
	return func(op context.Context, event facts.Event) error { return g.operation(op, ctx, a, event) }, true
}

// operation keeps the latest allowed operation with its stream.
func (g *Gatekeeper) operation(ctx, stream context.Context, a *Admission, event facts.Event) error {
	if err := stream.Err(); err != nil {
		return err
	}
	ctx, cancel := netx.Bind(ctx, stream)
	defer cancel()
	g.l.Lock()
	defer g.l.Unlock()
	gr := &grant{kind: facts.KindOperation, event: event}
	r, err := g.authorize(ctx, a, gr)
	if r != nil {
		if err == nil {
			err = g.Relabel(ctx, a.Key, r.Next, a)
		}
		g.Settle(r, err)
	}
	if err != nil {
		return err
	}
	a.grants = append(a.grants[:1], gr)
	return nil
}

// decide evaluates gr under current settings, without waiting or recording.
// An invalid event yields its record with the error.
func (g *Gatekeeper) decide(ctx context.Context, a *Admission, gr *grant) (*Record, error) {
	p, ok := g.identities.Lookup(a.Key)
	if !ok {
		return nil, ErrRemoved
	}
	if !a.Valid() {
		return nil, ErrChanged
	}
	return g.policy().Decide(ctx, Query{Principal: p, Connection: a.Connection, Kind: gr.kind, Event: gr.event, Label: gr.label, Approved: gr.approved})
}

// authorize releases L only around approval waits.
// Callers settle its record after any label persistence, before execution begins.
func (g *Gatekeeper) authorize(ctx context.Context, a *Admission, gr *grant) (*Record, error) {
	var r *Record
	gr.approved = []string{}
	for {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		if g.store.Backlogged() {
			return r, errAuditBacklog
		}
		gr.label = g.Label(a.Key)
		next, err := g.decide(ctx, a, gr)
		if next != nil && next.Invalid {
			g.store.Add(next)
			return next, err
		}
		if err != nil {
			return r, err
		}
		if r == nil {
			g.store.Add(next)
			r = next
		}
		r.Facts, r.Decision, r.Grant = next.Facts, next.Decision, next.Grant
		if len(r.Deny) != 0 {
			return r, errors.New(strings.Join(r.Deny, "; "))
		}
		if len(r.Requirements) == 0 {
			if r.State == StatePending {
				r.State = StateAllowed
			}
			return r, ctx.Err()
		}
		if err := g.awaitAnswer(ctx, r); err != nil {
			return r, err
		}
		if r.State == StateApproved {
			for _, requirement := range r.Requirements {
				gr.approved = append(gr.approved, requirement.ID)
			}
		}
	}
}

// recheck reports that a's key, access and connection remain, and that its admission
// and latest operation would be allowed outright under current settings.
func (g *Gatekeeper) recheck(a *Admission) bool {
	if a.capability != "" {
		return g.capable(a.Key, a.capability)
	}
	for _, gr := range a.grants {
		if d, err := g.decide(context.Background(), a, gr); err != nil || len(d.Deny) != 0 || len(d.Requirements) != 0 {
			return false
		}
	}
	return true
}

// Recheck revokes the admissions that the current settings no longer allow and wakes waiting requests.
func (g *Gatekeeper) Recheck() {
	for a, end := range g.admitted {
		if !g.recheck(a) {
			end()
		}
	}
	g.cond.Broadcast()
}

func (g *Gatekeeper) Label(key string) facts.Label {
	if l, ok := g.store.Label(key); ok {
		return l
	}
	return g.initial
}

// Relabel persists key's label; a failed write never publishes an observation.
// source is the admission whose operation produced l, or nil for an owner reset.
func (g *Gatekeeper) Relabel(ctx context.Context, key string, l facts.Label, source *Admission) error {
	if old := g.Label(key); old.Trust == l.Trust && old.Audience == l.Audience {
		return nil
	}
	if err := g.store.Relabel(ctx, key, l); err != nil {
		return err
	}
	// With both lattices off a label is recorded but never enforced, so a
	// change in it is no reason to cut anything.
	if source != nil && !g.policy().Enforced() {
		return nil
	}
	// An opaque source may finish the session it just admitted. Other opaque
	// sessions cannot recheck their bytes, so revoke them.
	for a, end := range g.admitted {
		// Close every connector stream so old deliveries cannot recontaminate a reset.
		if a.Key == key && a.capability == "" && a != source && (source == nil || !a.PerMessage) {
			end()
		}
	}
	return nil
}

func (g *Gatekeeper) capable(key, capability string) bool {
	p, known := g.identities.Lookup(key)
	policy := g.policy()
	return known && policy != nil && policy.Capable(p, capability)
}

// Hold leases capability while the identity ctx carries holds it. The context it returns
// ends when that identity is unregistered or a settings change takes the capability away.
func (g *Gatekeeper) Hold(ctx context.Context, capability string) (context.Context, context.CancelFunc, bool) {
	key, _ := identity.ID(ctx)
	ctx, release, ok := g.identities.Hold(ctx, key)
	if !ok {
		return nil, nil, false
	}
	g.l.Lock()
	defer g.l.Unlock()
	if !g.capable(key, capability) {
		release()
		return nil, nil, false
	}
	ctx, cancel := context.WithCancel(ctx)
	a := &Admission{Key: key, capability: capability}
	g.admitted[a] = cancel
	context.AfterFunc(ctx, func() { g.l.Lock(); delete(g.admitted, a); g.l.Unlock() })
	return ctx, func() { cancel(); release() }, true
}
