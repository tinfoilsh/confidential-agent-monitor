package web

import (
	"net/http"
	"slices"

	"github.com/tinfoilsh/monitor/connector"
)

// Parse owns configuration bytes and compiles all local matching before commit.
func Parse(source connector.Setup) (connector.Prepared, error) {
	h := new(Setup)
	preset := struct {
		*connector.Semantics
		HTTP *Preset `json:"http"`
	}{Semantics: &h.Semantics}
	if err := connector.ParseSetup(source, h, &preset, &h.Semantics); err != nil {
		return connector.Prepared{}, err
	}
	if err := h.Validate(false); err != nil {
		return connector.Prepared{}, err
	}
	names, err := h.Declarations()
	if err != nil {
		return connector.Prepared{}, err
	}
	for _, slot := range h.Slots {
		names = append(names, slot.Value)
		if slot.SigV4 != nil {
			names = append(names, slot.SigV4.Secret)
			if slot.SigV4.Session != "" {
				names = append(names, slot.SigV4.Session)
			}
		}
	}
	slices.Sort(names)
	h.Preset = preset.HTTP
	route := &Setup{Hosts: h.Hosts, Credentials: Credentials{Slots: h.Slots}}
	return connector.Prepared{Source: source, Value: h, Claim: route.Claim, SecretNames: slices.Compact(names),
		Discovery: connector.Discovery{Hosts: h.Hosts, Slots: h.Slots, Placeholders: map[string]string{}}}, nil
}

// Server is stable; every admitted stream pins one immutable protocol setup.
type Server struct{ connector.Slot[Setup] }

func (s *Server) Serve(stream *connector.Stream, env *connector.Env) {
	transport := env.Transport()
	defer transport.CloseIdleConnections()
	s.ServeWithTransport(stream, env, transport, nil)
}

func (s *Server) ServeWithTransport(stream *connector.Stream, env *connector.Env, transport http.RoundTripper, prepare PrepareRequest) {
	if captured := s.Load(); captured != nil {
		h := captured.Value
		h.Secrets = captured.Secrets
		h.ServeWithTransport(stream, env, transport, prepare)
	}
}
