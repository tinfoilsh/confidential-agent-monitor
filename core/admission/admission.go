package admission

type Set[T any] struct {
	live map[*member[T]]struct{}
}

type member[T any] struct {
	item T
	end  func()
}

func (s *Set[T]) Add(item T, end func()) (remove func()) {
	if s.live == nil {
		s.live = map[*member[T]]struct{}{}
	}
	m := &member[T]{item, end}
	s.live[m] = struct{}{}
	return func() { delete(s.live, m) }
}

func (s *Set[T]) Recheck(keep func(T) bool) {
	for m := range s.live {
		if !keep(m.item) {
			m.end()
		}
	}
}
