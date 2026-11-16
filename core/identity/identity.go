package identity

import (
	"context"
	"errors"
	"maps"
	"slices"
	"sync"

	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

var (
	errNameTaken = errors.New("identity name belongs to an exclusive registration")
	errKeyTaken  = errors.New("key is registered as another identity")
)

type Registry struct {
	mu   sync.Mutex
	keys map[string]*registration
}

type registration struct {
	facts.Principal
	exclusive bool
	lease     uint64
	ctx       context.Context
	end       context.CancelFunc
}

func (r *Registry) Register(id string, p facts.Principal, exclusive bool) (end func(), err error) {
	p.Key = id
	r.mu.Lock()
	defer r.mu.Unlock()
	maps.DeleteFunc(r.keys, func(key string, g *registration) bool {
		taken := exclusive && !g.exclusive && g.Name == p.Name && key != id
		if taken {
			g.end()
		}
		return taken
	})
	old := r.keys[id]
	if !exclusive {
		if old != nil && old.exclusive {
			return func() {}, nil
		}
		if old != nil && old.Name != p.Name {
			return nil, errKeyTaken
		}
		for _, g := range r.keys {
			if g.exclusive && g.Name == p.Name {
				return nil, errNameTaken
			}
		}
	}
	g := old
	if old == nil || old.Name != p.Name {
		if old != nil {
			old.end()
		}
		if r.keys == nil {
			r.keys = map[string]*registration{}
		}
		ctx, end := context.WithCancel(context.Background())
		g = &registration{ctx: ctx, end: end}
		r.keys[id] = g
	}
	g.Principal, g.exclusive = p, exclusive
	g.lease++
	lease := g.lease
	return func() {
		r.mu.Lock()
		defer r.mu.Unlock()
		if r.keys[id] == g && g.lease == lease {
			g.end()
			delete(r.keys, id)
		}
	}, nil
}

func (r *Registry) Unregister(id string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if g := r.keys[id]; g != nil {
		g.end()
		delete(r.keys, id)
	}
}

func (r *Registry) Lookup(id string) (facts.Principal, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if g := r.keys[id]; g != nil {
		return g.Principal, true
	}
	return facts.Principal{}, false
}

func (r *Registry) Keys(name string) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var keys []string
	for id, g := range r.keys {
		if g.Name == name {
			keys = append(keys, id)
		}
	}
	slices.Sort(keys)
	return keys
}

func (r *Registry) Hold(ctx context.Context, id string) (context.Context, context.CancelFunc, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	g := r.keys[id]
	if g == nil {
		return nil, nil, false
	}
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(g.ctx, cancel)
	return ctx, func() { stop(); cancel() }, true
}
