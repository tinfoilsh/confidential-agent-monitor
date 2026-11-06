package web

import (
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
	if err := connector.ParseSetup(source, h, &preset); err != nil {
		return connector.Prepared{}, err
	}
	if err := h.Validate(false); err != nil {
		return connector.Prepared{}, err
	}
	names := []string{}
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
	return connector.Prepared{Value: h, Claim: h.Claim, SecretNames: slices.Compact(names),
		Discovery: connector.Discovery{Hosts: h.Hosts, Slots: h.Slots}}, nil
}

type Server struct{ connector.Slot[Setup] }

func (s *Server) Serve(stream *connector.Stream, env *connector.Env) {
	transport := env.Transport()
	defer transport.CloseIdleConnections()
	if h, ok := s.Load(); ok {
		h.ServeWithTransport(stream, env, transport, nil)
	}
}
