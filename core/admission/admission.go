// Package admission keeps live admissions so a change can end those it no longer allows.
package admission

// Set holds live items with the function that ends each. The caller's lock guards every call.
type Set[T any] struct {
	live map[*member[T]]struct{}
}

type member[T any] struct {
	item T
	end  func()
}

// Add keeps item until remove; end is how Recheck ends it.
func (s *Set[T]) Add(item T, end func()) (remove func()) {
	if s.live == nil {
		s.live = map[*member[T]]struct{}{}
	}
	m := &member[T]{item, end}
	s.live[m] = struct{}{}
	return func() { delete(s.live, m) }
}

// Recheck ends every item keep rejects. An ended item stays until its remove runs.
func (s *Set[T]) Recheck(keep func(T) bool) {
	for m := range s.live {
		if !keep(m.item) {
			m.end()
		}
	}
}
