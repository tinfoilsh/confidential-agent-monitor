package web

import (
	"slices"

	"github.com/tinfoilsh/confidential-agent-monitor/connector"
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
	operations, err := preset.HTTP.Catalog(source.Vocabulary)
	if err != nil {
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
	return connector.Prepared{Value: h, Operations: operations, Claim: h.Claim, SecretNames: slices.Compact(names), Hosts: h.Hosts,
		Discovery: connector.Discovery{Hosts: h.Hosts, Slots: h.Slots}}, nil
}

func (h *Setup) serve(stream *connector.Stream, env *connector.Env) {
	transport := env.Transport()
	defer transport.CloseIdleConnections()
	h.ServeWithTransport(stream, env, transport, nil)
}
