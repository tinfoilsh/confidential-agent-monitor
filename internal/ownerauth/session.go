// Package ownerauth authenticates bearer, signed RPC and SSH owner requests and carries their session context.
package ownerauth

import (
	"context"
	"errors"
)

var ErrStaleGeneration = errors.New("Monitor state is older than the saved generation")

// Generation reports the live generation, and false while the Monitor is locked.
type Generation func() (uint64, bool)

// stale reports a live state older than a generation the owner has saved.
func (g Generation) stale(minimum uint64) bool {
	current, unlocked := g()
	return unlocked && current < minimum
}

type sessionKey struct{}

// Session is a request authenticated with the owner key, at the generation its owner has saved.
type Session struct {
	Minimum     uint64
	Acknowledge func() error
	ID          string
}

func NewContext(ctx context.Context, s Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, s)
}

func FromContext(ctx context.Context) (Session, bool) {
	s, ok := ctx.Value(sessionKey{}).(Session)
	return s, ok
}
