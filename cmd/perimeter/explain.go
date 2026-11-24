package main

import (
	"context"
	"fmt"
	"net/http"

	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/config"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

type explanation struct {
	Resolved config.Resolved           `json:"resolved"`
	Modes    map[string]config.Setting `json:"modes,omitempty"`
	Decision *config.Decision          `json:"decision,omitempty"`
}

func (s held) explain(ctx context.Context, p facts.Principal, connection, action string) (explanation, error) {
	st := s.settings.Load()
	if _, ok := st.Connection(connection); !ok {
		return explanation{}, httpError{fmt.Errorf("no connection %s", connection), http.StatusNotFound}
	}
	e := explanation{Resolved: st.Resolve(p.Name, p.Groups, connection)}
	if action == "" {
		return e, nil
	}
	kind, f := config.KindOperation, &requestFacts{}
	switch action {
	case config.KindAdmission:
		kind = config.KindAdmission
	case config.EffectUnknown:
	default:
		if f.Operation = st.ResolveAction(connection, action); f.Operation == nil {
			return explanation{}, fmt.Errorf("action %s has no effects on connection %s", action, connection)
		}
	}
	d, refused := st.decideOnly(ctx, p, s.label(p.Name), connection, kind, f)
	if refused != nil {
		return explanation{}, refused
	}
	e.Modes, e.Decision = st.EffectModes(p.Name, p.Groups, connection, f.Operation, kind), d
	return e, nil
}

func (st *settings) declared(name string) facts.Principal {
	id := st.Identities[name]
	p := facts.Principal{Name: name, Groups: id.Groups, Attributes: id.Attributes}
	if id.Key != "" {
		p.Key, _ = config.KeyFingerprint(id.Key)
	}
	return p
}

func (s held) explainIdentity(r *http.Request, _ struct{}) (any, error) {
	query := r.URL.Query()
	name := query.Get("identity")
	if name == "" {
		return nil, fmt.Errorf("explain needs an identity")
	}
	if _, declared := s.settings.Load().Identities[name]; !declared {
		return nil, httpError{fmt.Errorf("no identity %s", name), http.StatusNotFound}
	}
	return s.explain(r.Context(), s.settings.Load().declared(name), query.Get("connection"), query.Get("action"))
}

// An identity explains only connections it reaches, as its policy view lists only those.
func (s held) explainSelf(r *http.Request, _ struct{}, p facts.Principal) (any, error) {
	query := r.URL.Query()
	connection := query.Get("connection")
	if !s.settings.Load().Reaches(p.Name, p.Groups, connection) {
		return nil, httpError{fmt.Errorf("no connection %s", connection), http.StatusNotFound}
	}
	return s.explain(r.Context(), p, connection, query.Get("action"))
}
