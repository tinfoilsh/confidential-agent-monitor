// Package document holds a committed snapshot that changes only after its write succeeds.
package document

import "context"

// Value is the last committed snapshot. Its caller serializes every call.
type Value[T any] struct{ current T }

func (v *Value[T]) Get() T { return v.current }

// Commit publishes next only once write has persisted it.
func (v *Value[T]) Commit(ctx context.Context, next T, write func(context.Context, T) error) error {
	if err := write(ctx, next); err != nil {
		return err
	}
	v.current = next
	return nil
}
