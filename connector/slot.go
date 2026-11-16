package connector

import "context"

type binder interface {
	Bind(map[string]Secret)
}

// Stateless opens handlers that own no resources and serve each stream with their own copy of the *T in Prepared.Value.
func Stateless[T any](serve func(*T, *Stream, *Env)) Open {
	return func(ctx context.Context, prepared Prepared, secrets map[string]Secret, env *Env) (Handler, error) {
		setup := *prepared.Value.(*T)
		if b, ok := any(&setup).(binder); ok {
			b.Bind(secrets)
		}
		return HandlerFunc(func(s *Stream) {
			copy := setup
			serve(&copy, s, env)
		}), ctx.Err()
	}
}
