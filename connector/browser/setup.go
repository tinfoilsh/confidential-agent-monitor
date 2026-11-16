package browser

import (
	"context"
	"net/http"
	"slices"

	"github.com/tinfoilsh/confidential-agent-monitor/connector"
)

func Kind(extension string, sandboxed bool) connector.Kind {
	return connector.Kind{Settings: &extension, Open: open, Parse: func(source connector.Setup) (connector.Prepared, error) {
		c := &setup{Extension: extension, NoSandbox: sandboxed}
		if err := connector.ParseSetup(source, c, &c.Semantics); err != nil {
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
		return connector.Prepared{Value: c, SecretNames: slices.Compact(names)}, nil
	}}
}

// open starts one Chrome session. Its command/control synchronization remains
// inside that session; closing it retires its network proxy and callbacks too.
func open(ctx context.Context, prepared connector.Prepared, secrets map[string]connector.Secret, env *connector.Env) (connector.Handler, error) {
	c := *prepared.Value.(*setup)
	c.Bind(secrets)
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
		return nil, err
	}
	return next, nil
}

// Close waits for streams and controls to leave, since commands start workers that close joins.
func (b *session) Close() error {
	b.life.Lock()
	defer b.life.Unlock()
	return b.close()
}

func (b *session) ServeStream(stream *connector.Stream) {
	b.life.RLock()
	defer b.life.RUnlock()
	b.serve(stream)
}

func (b *session) Control() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.life.RLock()
		defer b.life.RUnlock()
		b.control().ServeHTTP(w, r)
	})
}
