package authz

import (
	"context"
	"encoding/json"
	"errors"
	"time"
)

const (
	StatePending  = "pending"
	StateExpired  = "expired"
	StateOutdated = "outdated"
	StateAllowed  = "allowed"
	StateRefused  = "refused"
	StateApproved = "approved"
	StateDenied   = "denied"

	AnswerOnce = "once"
	AnswerSave = "save"
	AnswerDeny = "deny"
)

var errRuleSaved = errors.New("approval rule saved; retry the request")

type Answer struct {
	Choice string `json:"decision"`
	Reason string `json:"reason,omitempty"`
}

type Review struct {
	By string `json:"by"`
	Answer
	Time time.Time `json:"time"`
}

// A Record is one decision; requests are the pending and expired ones.
type Record struct {
	ID      string          `json:"id"`
	State   string          `json:"state"`
	Invalid bool            `json:"invalid,omitempty"`
	Time    time.Time       `json:"time"`
	Expires time.Time       `json:"expires,omitzero"`
	Facts   json.RawMessage `json:"facts"`
	Decision
	Grant   map[string]any `json:"grant"`
	Reviews []Review       `json:"reviews,omitempty"`
}

// Request announces an already retained record as pending without an execution deadline.
func (g *Gatekeeper) Request(r *Record) {
	r.State = StatePending
	g.store.Announce(r)
}

// awaitAnswer publishes a pending record and releases L until it is
// answered, expires or anything changes; a record still pending is checked again.
func (g *Gatekeeper) awaitAnswer(ctx context.Context, r *Record) error {
	if r.State != StatePending {
		r.State, r.Expires = StatePending, time.Now().Add(g.wait)
		g.store.Announce(r)
	}
	wait, cancel := context.WithDeadline(ctx, r.Expires)
	defer cancel()
	// Taking L keeps the wakeup from landing before Wait.
	stop := context.AfterFunc(wait, func() { g.l.Lock(); g.cond.Broadcast(); g.l.Unlock() })
	defer stop()
	g.cond.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.State == StateDenied {
		return errors.New("this request was denied")
	}
	if r.State == StateApproved || wait.Err() == nil {
		return nil
	}
	r.State = StateExpired
	return errors.New("waiting for approval in the Perimeter timed out")
}

// Settle marks a record refused when its request fails for a reason other than the owner's answer,
// then hands its final outcome to the store.
func (g *Gatekeeper) Settle(r *Record, err error) {
	r.Settle(err)
	g.store.Settled(r)
}

// Settle marks a failed execution without replacing an owner's answer or expiration.
func (r *Record) Settle(err error) {
	if err != nil && r.State != StateDenied && r.State != StateExpired {
		r.State = StateRefused
		if len(r.Deny) == 0 {
			r.Deny = []string{err.Error()}
		}
	}
}

// Answer records review and wakes the request waiting on r.
func (g *Gatekeeper) Answer(r *Record, review Review) {
	review.Time = time.Now()
	r.Reviews = append(r.Reviews, review)
	r.State = StateApproved
	if review.Choice == AnswerDeny {
		r.State = StateDenied
	}
	g.cond.Broadcast()
}

// Saved records review once its rule is durable: a pending request is approved, and an expired one must be retried.
func (g *Gatekeeper) Saved(r *Record, review Review) {
	if r.State == StatePending {
		r.State = StateApproved
	} else {
		r.State, r.Deny = StateRefused, []string{errRuleSaved.Error()}
	}
	review.Time = time.Now()
	r.Reviews = append(r.Reviews, review)
}
