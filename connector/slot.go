package connector

import (
	"context"
	"sync/atomic"

	"github.com/tinfoilsh/monitor/connector/credential"
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
