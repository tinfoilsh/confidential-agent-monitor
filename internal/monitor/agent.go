package monitor

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"strings"

	"github.com/tinfoilsh/monitor/connector/web"
	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/internal/config"
	"github.com/tinfoilsh/monitor/internal/policy"
)

const agentHost = config.AgentConnection + ".monitor"

// Discovery describes reachable connections, not the owner's configuration or credentials.
// HTTP connections add public routing and placeholder data, never credentials.
type agentConnection struct {
	Name         string            `json:"name"`
	Account      string            `json:"account"`
	Kind         string            `json:"kind"`
	Host         string            `json:"host"`
	State        string            `json:"state"`
	Access       config.Access     `json:"access"`
	Hosts        []string          `json:"hosts"`
	Slots        []web.Slot        `json:"slots"`
	Placeholders map[string]string `json:"placeholders"`
}

func (m *monitor) agentHandler(key string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /connections", agentJSON(m, key, func(r *http.Request, _ struct{}, p config.Principal) (any, error) {
		st := m.live.Load()
		result := struct {
			Identity    string            `json:"identity"`
			CA          string            `json:"ca"`
			Connections []agentConnection `json:"connections"`
		}{p.Name, m.store.Doc.Keys.CACert, []agentConnection{}}
		for _, name := range slices.Sorted(maps.Keys(st.connections)) {
			c := st.connections[name]
			if !p.Reaches(c.Account) {
				continue
			}
			ac := agentConnection{Name: name, Account: c.Account, Kind: c.Protocol, Host: name + ".monitor",
				State: c.status().State, Access: p.Accounts[c.Account]}
			if provider, ok := c.Server.(interface{ HTTPConfig() *web.HTTP }); ok {
				h := provider.HTTPConfig()
				ac.Hosts, ac.Slots, ac.Placeholders = h.Hosts, h.Slots, map[string]string{}
				for secret := range h.Names() {
					ac.Placeholders[secret] = h.Placeholder(secret)
				}
			}
			result.Connections = append(result.Connections, ac)
		}
		return result, nil
	}))
	show := func() (any, error) {
		st := m.live.Load()
		p := st.Principals[key]
		visible, _, err := st.Config.AgentView(p)
		if err != nil {
			return nil, err
		}
		source, err := config.RenderTOML(visible)
		return map[string]any{"identity": p.Name, "source": source}, err
	}
	mux.HandleFunc("GET /policy", agentJSON(m, key, func(*http.Request, struct{}, config.Principal) (any, error) {
		return show()
	}))
	mux.HandleFunc("POST /policy/proposals", agentJSON(m, key, func(r *http.Request, input proposalInput, p config.Principal) (any, error) {
		if err := m.proposePolicy(r.Context(), p, input); err != nil {
			return nil, err
		}
		return show()
	}))
	return mux
}

const (
	agentPort     = 80
	maxAgentBytes = 96 << 10
)

func agentJSON[T any](m *monitor, key string, fn func(*http.Request, T, config.Principal) (any, error)) http.HandlerFunc {
	return jsonHandler(maxAgentBytes, func(r *http.Request, input T) (any, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		p, ok := m.live.Load().Principals[key]
		if !ok {
			return nil, errNoAgent
		}
		return fn(r, input, p)
	})
}

const (
	maxProposalBytes   = 64 << 10
	maxProposalReason  = 4096
	maxProposalDeletes = 64
)

type proposalInput struct {
	Source string     `json:"source"`
	Reason string     `json:"reason"`
	Delete [][]string `json:"delete,omitempty"`
}

// proposePolicy holds an agent's change as an approval card and applies it once the owner allows it.
func (m *monitor) proposePolicy(ctx context.Context, p config.Principal, input proposalInput) (err error) {
	if len(input.Source) > maxProposalBytes || len(input.Reason) > maxProposalReason || strings.TrimSpace(input.Reason) == "" || len(input.Delete) > maxProposalDeletes {
		return fmt.Errorf("proposal needs a reason of 1-%d bytes, at most %d bytes of TOML, and at most %d deletions", maxProposalReason, maxProposalBytes, maxProposalDeletes)
	}
	patch, err := config.ReadSource(input.Source)
	if err != nil {
		return err
	}
	changes := config.FragmentChanges(patch, nil)
	for _, path := range input.Delete {
		changes = append(changes, config.Change{Path: path, Delete: true})
	}
	base := m.store.Doc.Policy
	source, err := config.EditSource(base, changes)
	if err != nil {
		return err
	}
	if source == base {
		return errors.New("proposal does not change policy")
	}
	next, st, err := m.prepareCandidate(ctx, source, nil)
	if err != nil {
		return err
	}
	_, before, err := m.live.Load().Config.AgentView(p)
	if err != nil {
		return err
	}
	_, after, err := st.Config.AgentView(p)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(before, after) {
		return errors.New("proposal may edit only your permissions, reachable accounts' policy settings, or lattice switches")
	}
	diff, err := m.policyPreview(next, st)
	if err != nil {
		return err
	}
	r := m.addRecord(&record{Facts: &facts.Facts{Version: facts.Version, Principal: facts.Principal{Key: p.Key, Name: p.Name},
		Title: "Change policy", Parameters: map[string]any{}, Details: facts.Details{Policy: diff}},
		Decision: policy.Decision{Requirements: []policy.Requirement{{ID: "policy", Message: input.Reason}}}})
	defer func() { m.settleRecord(r, err) }()
	if err = m.awaitApproval(ctx, r); err != nil {
		return err
	}
	if m.store.Doc.Policy != base {
		return errPolicyConflict
	}
	if next, st, err = m.prepareCandidate(ctx, next.Policy, nil); err != nil {
		return err
	}
	return m.activate(ctx, next, st)
}
