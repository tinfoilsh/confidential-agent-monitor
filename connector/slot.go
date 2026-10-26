package connector

import (
	"context"
	"maps"
	"sync/atomic"

	"github.com/tinfoilsh/monitor/connector/credential"
)

// bound is one compiled setup and the credential identities installed with it.
// Protocol code copies Value and binds Secrets for the admitted stream.
type bound[T any] struct {
	Value   T
	Secrets map[string]*credential.Value
}

// Slot only publishes immutable data; it owns no execution or resource lifetime.
type Slot[T any] struct{ current atomic.Pointer[bound[T]] }

func (s *Slot[T]) Load() *bound[T] { return s.current.Load() }

func (s *Slot[T]) Update(ctx context.Context, prepared Prepared, secrets map[string]*credential.Value, _ *Env) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	s.current.Store(&bound[T]{Value: *prepared.Value.(*T), Secrets: maps.Clone(secrets)})
	return nil
}
