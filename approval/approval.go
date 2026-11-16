// Package approval keeps reviewable records and lets requests wait, under their host's lock, for an answer.
package approval

import (
	"context"
	"iter"
	"slices"
	"sync"
	"time"
)

// Records is one bounded collection of caller-owned records. Every call needs the lock it was made with.
type Records[T any] struct {
	cond    sync.Cond
	items   []T
	max     int
	pending func(T) bool
}

// NewRecords keeps at most max records, evicting the oldest that pending does not protect.
func NewRecords[T any](l sync.Locker, max int, pending func(T) bool) *Records[T] {
	r := &Records[T]{max: max, pending: pending}
	r.cond.L = l
	return r
}

func (r *Records[T]) Add(item T) {
	for len(r.items) >= r.max {
		i := slices.IndexFunc(r.items, func(item T) bool { return !r.pending(item) })
		if i < 0 {
			break
		}
		r.items = slices.Delete(r.items, i, i+1)
	}
	r.items = append(r.items, item)
}

func (r *Records[T]) Find(match func(T) bool) (T, bool) {
	i := slices.IndexFunc(r.items, match)
	if i < 0 {
		var zero T
		return zero, false
	}
	return r.items[i], true
}

// All yields the records oldest first.
func (r *Records[T]) All() iter.Seq[T] { return slices.Values(r.items) }

// Wait releases the lock until Notify, the end of ctx or deadline, then retakes it.
// It reports whether deadline has passed.
func (r *Records[T]) Wait(ctx context.Context, deadline time.Time) (expired bool) {
	wait, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	// Taking the lock keeps the wakeup from landing before Wait.
	stop := context.AfterFunc(wait, func() { r.cond.L.Lock(); r.cond.Broadcast(); r.cond.L.Unlock() })
	defer stop()
	r.cond.Wait()
	return !time.Now().Before(deadline)
}

// Notify wakes every waiting request to check its record again.
func (r *Records[T]) Notify() { r.cond.Broadcast() }
