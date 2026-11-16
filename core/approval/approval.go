package approval

import (
	"context"
	"iter"
	"slices"
	"sync"
	"time"
)

type Records[T any] struct {
	cond    sync.Cond
	items   []T
	max     int
	pending func(T) bool
}

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

func (r *Records[T]) All() iter.Seq[T] { return slices.Values(r.items) }

func (r *Records[T]) Wait(ctx context.Context, deadline time.Time) (expired bool) {
	wait, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	stop := context.AfterFunc(wait, func() { r.cond.L.Lock(); r.cond.Broadcast(); r.cond.L.Unlock() })
	defer stop()
	r.cond.Wait()
	return !time.Now().Before(deadline)
}

func (r *Records[T]) Notify() { r.cond.Broadcast() }
