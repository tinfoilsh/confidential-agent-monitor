package browser

import (
	"context"
	"maps"
	"net/http"
	"slices"
	"sync"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
)

func Kind(extension string, sandboxed bool) connector.Kind {
	return connector.Kind{Settings: &extension, New: func() connector.Server { return new(Browser) }, Parse: func(source connector.Setup) (connector.Prepared, error) {
		c := &setup{Extension: extension, NoSandbox: sandboxed}
		if err := connector.ParseSetup(source, c, &c.Semantics, &c.Semantics); err != nil {
			return connector.Prepared{}, err
		}
		if err := c.Validate(true); err != nil {
			return connector.Prepared{}, err
		}
		names := []string{}
		for _, slot := range c.Slots {
			names = append(names, slot.Value)
		}
		slices.Sort(names)
		return connector.Prepared{Source: source, Value: c, SecretNames: slices.Compact(names)}, nil
	}}
}

// Browser owns one Chrome session. Its command/control synchronization remains
// inside that session; setup changes retire its network proxy and callbacks too.
type Browser struct {
	mu      sync.RWMutex
	current *session
}

func (b *Browser) Update(ctx context.Context, prepared connector.Prepared, secrets map[string]*credential.Value, env *connector.Env) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.close()
	c := *prepared.Value.(*setup)
	c.Secrets = maps.Clone(secrets)
	life, cancel := context.WithCancel(context.Background())
	next := &session{setup: c, cancel: cancel}
	stop := context.AfterFunc(ctx, cancel)
	err := next.start(life, env)
	stop()
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		next.close()
		return err
	}
	b.current = next
	return nil
}

func (b *Browser) close() {
	if b.current != nil {
		b.current.close()
		b.current = nil
	}
}

func (b *Browser) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.close()
	return nil
}

func (b *Browser) Serve(stream *connector.Stream, env *connector.Env) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if current := b.current; current != nil {
		current.serve(stream, env)
	}
}

func (b *Browser) Control() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.mu.RLock()
		defer b.mu.RUnlock()
		if b.current == nil {
			http.Error(w, "browser unavailable", http.StatusServiceUnavailable)
			return
		}
		b.current.control().ServeHTTP(w, r)
	})
}
