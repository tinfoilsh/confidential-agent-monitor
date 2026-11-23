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

func call(action string, parameters map[string]any) facts.Observation {
	return facts.Observation{Operation: &facts.Operation{Action: action}, Parameters: parameters}
}

// A single scoping parameter lets a saved rule grant a call for one subject, identity, or connection.
func scope(parameters map[string]any) map[string]any {
	for _, key := range []string{"subject", "identity", "connection"} {
		if value, named := parameters[key]; named {
			return map[string]any{key: value}
		}
	}
	return map[string]any{}
}

func (st *settings) callFacts(c facts.Observation) *requestFacts {
	c.Scope = scope(c.Parameters)
	if c.Operation != nil {
		c.Title = st.Presets[config.PerimeterConnection].Catalog.Actions[c.Operation.Action].Title
	}
	f, _ := st.describe(config.PerimeterConnection, c, connections.Perimeter)
	return &f
}

func (st *settings) changes(c facts.Observation) bool {
	op := st.callFacts(c).Operation
	return op != nil && slices.ContainsFunc(op.Effects, func(e string) bool { return config.Vocabulary[e].Change })
}

type describe func(s *state, r *http.Request, input any) ([]facts.Observation, error)

func named(action string, parameters ...string) describe {
	return func(_ *state, r *http.Request, _ any) ([]facts.Observation, error) {
		c := call(action, map[string]any{})
		for _, name := range parameters {
			c.Parameters[name] = cmp.Or(r.PathValue(name), r.URL.Query().Get(name))
		}
		return []facts.Observation{c}, nil
	}
}

func detailed(action string, parameters ...string) describe {
	base := named(action, parameters...)
	return func(s *state, r *http.Request, input any) ([]facts.Observation, error) {
		calls, err := base(s, r, input)
		calls[0].Details = input
		return calls, err
	}
}

var errUnreviewed = httpError{errors.New("an identity writes the policy only with the revision it reviewed"), http.StatusBadRequest}

func policyCall(s *state, r *http.Request, revision *uint64, credentials format.Secrets, edit func(before string) string) ([]facts.Observation, error) {
	if c, _ := callerFrom(r.Context()); !c.Owner && revision == nil {
		return nil, errUnreviewed
	}
	c := call("policy.write", nil)
	s.locked(func(h held) {
		c.Details = map[string]any{"policy": policyDiff{SourceDiff: sourceDiff(h.doc.Policy, edit(h.doc.Policy))}, "credentials": slices.Sorted(maps.Keys(credentials))}
	})
	return []facts.Observation{c}, nil
}

func policyWrite(s *state, r *http.Request, input any) ([]facts.Observation, error) {
	in := input.(sourceInput)
	return policyCall(s, r, in.Revision, nil, func(string) string { return in.Source })
}

// One call per action, so an identity needs each of them allowed.
func edits(s *state, r *http.Request, input any) (calls []facts.Observation, err error) {
	in := input.(editsInput)
	if len(in.Changes) != 0 || len(in.Credentials) == 0 {
		calls, err = policyCall(s, r, in.Revision, in.Credentials, func(before string) string {
			if edited, err := tomledit.Edit(before, in.Changes); err == nil {
				return edited
			}
			return before
		})
	}
	for _, connection := range slices.Sorted(maps.Keys(in.Credentials)) {
		calls = append(calls, call("credentials.write", map[string]any{"connection": connection}))
	}
	return calls, err
}

// The identities its entries resolve to and their keys let the policy refuse an identity that enrolls itself.
func enrollment(s *state, _ *http.Request, input any) ([]facts.Observation, error) {
	st := s.settings.Load()
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

// Grants and limits do not depend on the scope, so an action they turn off is refused before any record is read.
func (s *state) offFor(c caller, action string) bool {
	if c.Owner {
		return false
	}
	p, known := s.identities.Lookup(c.Key)
	if !known || p.Name != c.Name {
		return true
	}
	return s.settings.Load().PerimeterOff(p, action)
}

var answerChoices = []string{answerOnce, answerSave, answerDeny}

// Saving an answer changes the policy, and so does answering a proposal or any call on the Perimeter's own API.
func answer(s *state, r *http.Request, input any) ([]facts.Observation, error) {
	a, id := input.(answerInput).Answer, r.PathValue("id")
	if !slices.Contains(answerChoices, a.Choice) {
		return nil, fmt.Errorf("decision must be one of %s", strings.Join(answerChoices, ", "))
	}
	const proposal = "proposals.answer"
	c := facts.Observation{Operation: &facts.Operation{Action: "requests.answer"}, Details: a}
	if a.Choice == answerSave {
		c.Operation.Action = "requests.save"
	}
	from, _ := callerFrom(r.Context())
	if s.offFor(from, c.Operation.Action) && s.offFor(from, proposal) {
		return []facts.Observation{c}, nil
	}
	found := false
	s.locked(func(h held) {
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
		return nil, missingRecord(from)
	}
	return []facts.Observation{c}, nil
}

var errUndescribed = httpError{errors.New("this route performs no action on the perimeter connection"), http.StatusForbidden}

// The owner is root and never decided; any other caller runs only once every call is allowed.
func (s *state) perform(r *http.Request, describe describe, input any, run func() error) error {
	c, _ := callerFrom(r.Context())
	if c.Owner && r.Method == http.MethodGet {
		return run()
	}
	calls, err := describe(s, r, input)
	if err != nil {
		return err
	}
	if !c.Owner {
		if len(calls) == 0 {
			return errUndescribed
		}
		for _, call := range calls {
			var refused *refusal
			s.locked(func(h held) {
				refused = h.authorize(r.Context(), perimeterCaller(c.Key, c.Name), &grant{kind: config.KindOperation, known: h.settings.Load().callFacts(call)})
			})
			if refused != nil {
				return refused
			}
		}
		return run()
	}
	err = run()
	s.locked(func(h held) {
		for _, call := range calls {
			if h.settings.Load().changes(call) {
				h.recordOwner(call, err)
			}
		}
	})
	return err
}

func perimeterJSON[T any](s *state, limit int64, describe describe, fn func(*http.Request, T) (any, error)) http.HandlerFunc {
	return s.unlocked(jsonHandler(limit, func(r *http.Request, input T) (value any, err error) {
		err = s.perform(r, describe, input, func() (err error) {
			value, err = fn(r, input)
			return err
		})
		return value, err
	}))
}

func perimeterHeld[T any](s *state, describe describe, fn func(held, *http.Request, T) (any, error)) http.HandlerFunc {
	return perimeterJSON(s, maxDocumentBytes, describe, func(r *http.Request, input T) (value any, err error) {
		s.locked(func(h held) { value, err = fn(h, r, input) })
		return value, err
	})
}

func (s *state) unlocked(next http.HandlerFunc) http.HandlerFunc {
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

func (s held) recordOwner(c facts.Observation, err error) {
	st := s.settings.Load()
	f := st.callFacts(c)
	st.complete(f, facts.Principal{Name: config.OwnerName}, config.PerimeterConnection, config.KindOperation, format.Label{})
	raw, encodeErr := json.Marshal(f)
	if encodeErr != nil {
		log.Printf("audit %s: %v", f.Title, encodeErr)
		return
	}
	s.settleRecord(s.addRecord(&record{Facts: raw, Scope: f.Scope}), precondition(err))
}
