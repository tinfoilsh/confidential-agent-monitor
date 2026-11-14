package connector

import (
	"context"
	"io"
	"sync"
	"sync/atomic"

	"github.com/tinfoilsh/confidential-agent-monitor/connector/credential"
)

type binder interface {
	Bind(map[string]*credential.Value)
}

// Slot only publishes immutable data; it owns no execution or resource lifetime.
type Slot[T any] struct{ current atomic.Pointer[T] }

// Load returns a copy of the current setup with its credentials bound.
func (s *Slot[T]) Load() (T, bool) {
	if current := s.current.Load(); current != nil {
		return *current, true
	}
	var none T
	return none, false
}

func (s *Slot[T]) Update(ctx context.Context, prepared Prepared, secrets map[string]*credential.Value, _ *Env) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	value := *prepared.Value.(*T)
	if b, ok := any(&value).(binder); ok {
		b.Bind(secrets)
	}
	s.current.Store(&value)
	return nil
}

// Resource publishes a value that owns resources; readers load it without a lock.
type Resource[T io.Closer] struct {
	mu      sync.Mutex
	current atomic.Pointer[T]
}

func (r *Resource[T]) Load() T {
	if current := r.current.Load(); current != nil {
		return *current
	}
	var none T
	return none
}

// Replace closes the current value, then publishes the one open returns unless open fails.
func (r *Resource[T]) Replace(open func() (T, error)) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.close()
	next, err := open()
	if err == nil {
		r.current.Store(&next)
	}
	return err
}

func (r *Resource[T]) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.close()
}

func (r *Resource[T]) close() error {
	if current := r.current.Swap(nil); current != nil {
		return (*current).Close()
	}
	return nil
}
