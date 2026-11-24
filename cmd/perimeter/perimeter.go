package main

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/config"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/connections"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/format"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/tomledit"
)

func perimeterCall(action string, parameters map[string]any) facts.Observation {
	return facts.Observation{Operation: &facts.Operation{Action: action}, Parameters: parameters}
}

// A single scoping parameter lets a saved rule grant a call for one subject, identity, or connection.
func ruleScope(parameters map[string]any) map[string]any {
	for _, key := range []string{"subject", "identity", "connection"} {
		if value, named := parameters[key]; named {
			return map[string]any{key: value}
		}
	}
	return map[string]any{}
}

func (st *settings) callFacts(c facts.Observation) *requestFacts {
	c.Scope = ruleScope(c.Parameters)
	if c.Operation != nil {
		c.Title = st.Preset(config.PerimeterConnection).Catalog.Actions[c.Operation.Action].Title
	}
	f, _ := st.observationFacts(config.PerimeterConnection, c, connections.PerimeterFlow)
	return &f
}

func (st *settings) mutates(c facts.Observation) bool {
	op := st.callFacts(c).Operation
	return op != nil && slices.ContainsFunc(op.Effects, func(e string) bool { return config.Vocabulary[e].Integrity })
}

// The owner's mount runs every route as root; an identity's mount decides each call a route makes.
type adminMount struct {
	*state
	owner bool
}

type routeActions func(m adminMount, r *http.Request, input any) ([]facts.Observation, error)

func pathAction(action string, parameters ...string) routeActions {
	return func(_ adminMount, r *http.Request, _ any) ([]facts.Observation, error) {
		c := perimeterCall(action, map[string]any{})
		for _, name := range parameters {
			c.Parameters[name] = cmp.Or(r.PathValue(name), r.URL.Query().Get(name))
		}
		return []facts.Observation{c}, nil
	}
}

func bodyAction(action string, parameters ...string) routeActions {
	base := pathAction(action, parameters...)
	return func(m adminMount, r *http.Request, input any) ([]facts.Observation, error) {
		calls, err := base(m, r, input)
		calls[0].Details = input
		return calls, err
	}
}

var errUnreviewed = httpError{errors.New("an identity writes the policy only with the revision it reviewed"), http.StatusBadRequest}

func policyCall(m adminMount, revision *uint64, credentials format.Secrets, edit func(before string) string) ([]facts.Observation, error) {
	if !m.owner && revision == nil {
		return nil, errUnreviewed
	}
	c := perimeterCall("policy.write", nil)
	m.locked(func(h held) {
		c.Details = map[string]any{"policy": policyDiff{SourceDiff: sourceDiff(h.doc.Policy, edit(h.doc.Policy))}, "credentials": slices.Sorted(maps.Keys(credentials))}
	})
	return []facts.Observation{c}, nil
}

func policyWriteActions(m adminMount, _ *http.Request, input any) ([]facts.Observation, error) {
	in := input.(sourceInput)
	return policyCall(m, in.Revision, nil, func(string) string { return in.Source })
}

// One call per action, so an identity needs each of them allowed.
func policyEditActions(m adminMount, _ *http.Request, input any) (calls []facts.Observation, err error) {
	in := input.(editsInput)
	if len(in.Changes) != 0 || len(in.Credentials) == 0 {
		calls, err = policyCall(m, in.Revision, in.Credentials, func(before string) string {
			if edited, err := tomledit.Edit(before, in.Changes); err == nil {
				return edited
			}
			return before
		})
	}
	for _, connection := range slices.Sorted(maps.Keys(in.Credentials)) {
		calls = append(calls, perimeterCall("credentials.write", map[string]any{"connection": connection}))
	}
	return calls, err
}

// The identities its entries resolve to and their keys let the policy refuse an identity that enrolls itself.
func enrollActions(m adminMount, _ *http.Request, input any) ([]facts.Observation, error) {
	st := m.settings.Load()
	names, keys := []string{}, []string{}
	for name, e := range input.(map[string]config.Enrollment) {
		fingerprint, err := config.KeyFingerprint(e.Key)
		if err != nil {
			return nil, err
		}
		if p, enrolled := st.Principal(fingerprint); enrolled {
			name = p.Name
		}
		names, keys = append(names, name), append(keys, fingerprint)
	}
	slices.Sort(names)
	slices.Sort(keys)
	return []facts.Observation{{Operation: &facts.Operation{Action: "enroll"}, Parameters: map[string]any{"identities": names, "keys": keys}, Details: input}}, nil
}

// Access does not depend on the scope, so an action it turns off is refused before any record is read.
func (m adminMount) accessOff(r *http.Request, action string) bool {
	if m.owner {
		return false
	}
	c, _ := callerFrom(r.Context())
	p, known := m.identities.Lookup(c.Key)
	if !known || p.Name != c.Name {
		return true
	}
	return m.settings.Load().ActionOff(p, action)
}

var answerChoices = []string{answerOnce, answerSave, answerDeny}

// Saving an answer changes the policy, and so does answering a proposal or any call on the Perimeter's own API.
func answerActions(m adminMount, r *http.Request, input any) ([]facts.Observation, error) {
	a, id := input.(answerInput).Answer, r.PathValue("id")
	if !slices.Contains(answerChoices, a.Choice) {
		return nil, fmt.Errorf("decision must be one of %s", strings.Join(answerChoices, ", "))
	}
	const proposal = "proposals.answer"
	c := facts.Observation{Operation: &facts.Operation{Action: "requests.answer"}, Details: a}
	if a.Choice == answerSave {
		c.Operation.Action = "requests.save"
	}
	if m.accessOff(r, c.Operation.Action) && m.accessOff(r, proposal) {
		return []facts.Observation{c}, nil
	}
	found := false
	m.locked(func(h held) {
		record := h.findRecord(id)
		if found = record != nil; !found {
			return
		}
		f := record.subject()
		c.Parameters = map[string]any{"subject": f.Principal.Name, "request": id, "choice": a.Choice, "connection": f.Connection}
		if record.Changes != nil || f.Connection == config.PerimeterConnection {
			c.Operation.Action = proposal
		}
	})
	if !found {
		return nil, m.missingRecordError()
	}
	return []facts.Observation{c}, nil
}

var errUndescribed = httpError{errors.New("this route performs no action on the perimeter connection"), http.StatusForbidden}

// The owner is root and never decided; any other caller runs only once every call is allowed.
func (m adminMount) perform(r *http.Request, actions routeActions, input any, run func() error) error {
	if m.owner && r.Method == http.MethodGet {
		return run()
	}
	calls, err := actions(m, r, input)
	if err != nil {
		return err
	}
	if !m.owner {
		if len(calls) == 0 {
			return errUndescribed
		}
		c, _ := callerFrom(r.Context())
		for _, call := range calls {
			var refused *refusal
			m.locked(func(h held) {
				refused = h.authorize(r.Context(), apiStream(c.Key, c.Name), &request{kind: config.KindOperation, known: h.settings.Load().callFacts(call)})
			})
			if refused != nil {
				return refused
			}
		}
		return run()
	}
	err = run()
	m.locked(func(h held) {
		for _, call := range calls {
			if h.settings.Load().mutates(call) {
				h.auditOwnerCall(call, err)
			}
		}
	})
	return err
}

func authorizedHandler[T any](m adminMount, limit int64, actions routeActions, fn func(*http.Request, T) (any, error)) http.HandlerFunc {
	return m.requireUnlocked(jsonHandler(limit, func(r *http.Request, input T) (value any, err error) {
		err = m.perform(r, actions, input, func() (err error) {
			value, err = fn(r, input)
			return err
		})
		return value, err
	}))
}

func authorizedLockedHandler[T any](m adminMount, actions routeActions, fn func(held, *http.Request, T) (any, error)) http.HandlerFunc {
	return authorizedHandler(m, maxDocumentBytes, actions, func(r *http.Request, input T) (value any, err error) {
		m.locked(func(h held) { value, err = fn(h, r, input) })
		return value, err
	})
}

// An identity sees only the records whose subjects it may read, and its label falls for those it saw.
func authorizedList(m adminMount, action string, list func(r *http.Request, shows func(subject string) bool) (any, error)) http.HandlerFunc {
	return m.requireUnlocked(jsonHandler(0, func(r *http.Request, _ struct{}) (any, error) {
		var d *disclosure
		var err error
		if !m.owner {
			m.locked(func(h held) { d, err = m.newDisclosure(h, r, action) })
		}
		if err != nil {
			return nil, err
		}
		value, err := list(r, d.shows)
		if err == nil {
			m.locked(func(h held) { err = d.audit(r.Context(), h) })
		}
		return value, err
	}))
}

func (s *state) requireUnlocked(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, err := requestCaller(r)
		if err == nil && s.settings.Load() == nil {
			err = errLocked
		}
		if err != nil {
			fail(w, err)
			return
		}
		next(w, r)
	}
}

func (s held) auditOwnerCall(c facts.Observation, err error) {
	st := s.settings.Load()
	f := st.callFacts(c)
	st.completeFacts(f, facts.Principal{Name: config.OwnerName}, config.PerimeterConnection, config.KindOperation, format.Label{})
	raw, encodeErr := json.Marshal(f)
	if encodeErr != nil {
		log.Printf("audit %s: %v", f.Title, encodeErr)
		return
	}
	s.settleRecord(s.addRecord(&record{Facts: raw, Scope: f.Scope}), precondition(err))
}
