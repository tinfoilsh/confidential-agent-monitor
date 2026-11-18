package admission

import (
	"context"
	"sync"
)

type Set[T any] struct {
	// L is held by the caller of Hold and Recheck.
	L    sync.Locker
	live map[*member[T]]struct{}
}

type member[T any] struct {
	item T
	end  func()
}

func (s *Set[T]) Hold(ctx context.Context, item T, end func()) {
	if s.live == nil {
		s.live = map[*member[T]]struct{}{}
	}
	m := &member[T]{item, end}
	s.live[m] = struct{}{}
	context.AfterFunc(ctx, func() {
		s.L.Lock()
		defer s.L.Unlock()
		delete(s.live, m)
	})
}

func (s *Set[T]) Recheck(keep func(T) bool) {
	for m := range s.live {
		if !keep(m.item) {
			m.end()
		}
	}
}
