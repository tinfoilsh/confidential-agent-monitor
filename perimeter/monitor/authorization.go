package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/internal/authz"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/internal/config"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/policy"
)

const (
	maxReason   = 4096
	auditPrefix = "audit/"
)

var (
	errRecordGone = httpError{errors.New("this request is no longer in the activity log"), http.StatusNotFound}
	errNoAgent    = httpError{authz.ErrRemoved, http.StatusForbidden}
)

// savedAnswer carries the answer to publish with its durable settings change.
type savedAnswer struct {
	record *record
	answer authz.Review
}

const maxSummaryTitle = 512

// Activity never needs request bodies, policy parameters or saved-rule grants.
// Keep those in the existing audit record and load one through /requests/{id}.
type recordSummary struct {
	ID      string         `json:"id"`
	State   string         `json:"state"`
	Invalid bool           `json:"invalid,omitempty"`
	Time    time.Time      `json:"time"`
	Expires time.Time      `json:"expires,omitzero"`
	Summary bool           `json:"summary"`
	Reviews []authz.Review `json:"reviews,omitempty"`
	Segment string         `json:"segment,omitempty"`
	Facts   struct {
		Principal  facts.Principal  `json:"principal"`
		Connection string           `json:"connection"`
		Service    string           `json:"service"`
		Operation  *facts.Operation `json:"operation"`
		Title      string           `json:"title"`
	} `json:"facts"`
}

func summarize(r *authz.Record) recordSummary {
	v := recordSummary{ID: r.ID, State: r.State, Invalid: r.Invalid, Time: r.Time, Expires: r.Expires, Summary: true}
	for _, review := range r.Reviews {
		review.Reason = ""
		v.Reviews = append(v.Reviews, review)
	}
	_ = json.Unmarshal(r.Facts, &v.Facts)
	// SQL and other protocol titles can contain the entire request.
	if len(v.Facts.Title) > maxSummaryTitle {
		v.Facts.Title = strings.ToValidUTF8(v.Facts.Title[:maxSummaryTitle], "") + "…"
	}
	return v
}

func (m *Monitor) currentPolicy() authz.Policy {
	if st := m.settings.Load(); st != nil {
		return st
	}
	return nil
}

func (st *settings) Decide(ctx context.Context, q authz.Query) (*authz.Record, error) {
	f, describeErr := st.bindFacts(q)
	if describeErr != nil {
		f.Operation = nil
		raw, err := json.Marshal(f)
		if err != nil {
			return nil, err
		}
		return &authz.Record{Facts: raw, Invalid: true}, describeErr
	}
	input, next, err := st.policyInput(q, f)
	if err != nil {
		return nil, err
	}
	next.Decision, err = policy.Eval[authz.Decision](ctx, st.Engine, "decision", input)
	return next, err
}

func (st *settings) Enforced() bool { return st.Lattices.Confidentiality || st.Lattices.Integrity }

func (st *settings) bindFacts(q authz.Query) (facts.Facts, error) {
	f, err := q.Event.Facts()
	f.Version, f.Kind = facts.Version, q.Kind
	f.Service, f.Connection = st.Connections[q.Connection].Preset, q.Connection
	f.Principal, f.Context.Label = q.Principal, q.Label
	if f.Parameters == nil {
		f.Parameters = map[string]any{}
	}
	if f.Scope == nil {
		f.Scope = f.Parameters
	}
	return f, err
}

// policyInput builds the engine input and the record its decision will fill.
func (st *settings) policyInput(q authz.Query, f facts.Facts) (decisionInput, *authz.Record, error) {
	grant := f.Scope
	encoded, err := json.Marshal(f)
	if err != nil {
		return decisionInput{}, nil, err
	}
	p, name := q.Principal, q.Connection
	access, connection := st.Access(p.Name, name), st.Connections[name]
	// Policy reads unset scopes as {} and unset lists as [], never null.
	effects := []map[string]string{st.Effects, connection.Effects, st.Identities[p.Name].Effects, access.Effects}
	for i, scope := range effects {
		if scope == nil {
			effects[i] = map[string]string{}
		}
	}
	return decisionInput{
		Facts: encoded,
		Authorization: authorizationInput{Access: access, Reaches: st.Reaches(p.Name, name), Effects: effects, AllowPaidInference: st.AllowPaidInference,
			Rules: slices.Collect(maps.Values(st.Identities[p.Name].Rules)), Approved: q.Approved, Grant: grant},
		Connection: connectionInput{Contents: connection.Contents, Strangers: connection.Strangers, Sends: connection.Sends,
			Private: append([]string{}, connection.PolicyOptions.Private...), PublicScope: append([]string{}, st.publicScope[name]...)},
	}, &authz.Record{Facts: encoded, Grant: grant}, nil
}

// gateStore keeps labels in the sealed document and settled records in the audit log, under mu.
type gateStore struct{ m *Monitor }

func (s gateStore) Label(key string) (facts.Label, bool) {
	l, ok := s.m.store.Doc.Labels[key]
	return l, ok
}

func (s gateStore) Relabel(ctx context.Context, key string, l facts.Label) error {
	next := s.m.store.Doc
	next.Labels = maps.Clone(next.Labels)
	next.Labels[key] = l
	return s.m.store.Commit(ctx, next)
}

func (s gateStore) Settled(r *authz.Record) { s.m.recordSettled(&record{Record: r}) }

func (s gateStore) Announce(r *authz.Record) {
	s.m.events.Info("record", "record", summarize(r), "generation", s.m.store.Doc.Generation)
}

// recordSettled writes the application envelope even if retention has evicted it.
func (m *Monitor) recordSettled(r *record) {
	if err := m.audit.Append(r); err != nil {
		log.Printf("audit record %s: %v", r.ID, err)
	}
	gateStore{m}.Announce(r.Record)
}

func (m *Monitor) settleRecord(r *record, err error) {
	r.Settle(err)
	m.recordSettled(r)
}

func (m *Monitor) outdateRecord(r *record) {
	r.State = authz.StateOutdated
	m.settleRecord(r, nil)
}

func (s gateStore) Backlogged() bool { return s.m.audit.Backlogged() }

// ruleChange derives a saved rule only from frozen audit/grant data under mu.
func (m *Monitor) ruleChange(r *record) (config.Change, error) {
	f := summarize(r.Record).Facts
	if f.Operation == nil || f.Operation.ID == "" {
		return config.Change{}, errors.New("a request without a known operation cannot be saved")
	}
	p, exists := m.identities.Lookup(f.Principal.Key)
	if !exists || p.Name != f.Principal.Name {
		return config.Change{}, errors.New("the requesting identity was revoked or replaced")
	}
	if _, declared := m.settings.Load().Identities[p.Name]; !declared {
		return config.Change{}, errors.New("an approval for a certified identity cannot be saved as a rule")
	}
	return config.Change{Path: []string{"identities", p.Name, "rules", r.ID}, Value: config.Rule{Version: facts.Version, Connection: f.Connection, Action: f.Operation.Action, Operation: f.Operation.ID,
		Scope: r.Grant, Requirements: slices.Clone(r.Requirements)}}, nil
}

const adminService = "admin"

// recordAdmin audits an admin action and its outcome; the caller holds mu.
func (m *Monitor) recordAdmin(ctx context.Context, title string, details any, err error) {
	caller, _ := CallerFrom(ctx)
	raw, encodeErr := json.Marshal(facts.Facts{Version: facts.Version, Principal: facts.Principal{Name: caller.Name}, Service: adminService,
		Title: title, Parameters: map[string]any{}, Details: details})
	if encodeErr != nil {
		log.Printf("audit admin action %s: %v", title, encodeErr)
		return
	}
	m.settleRecord(m.addRecord(&record{Record: &authz.Record{Facts: raw}}), err)
}

// answerable validates an answer under mu; callers recheck it after pure
// preparation so a concurrent answer cannot be overwritten by a saved rule.
func (m *Monitor) answerable(id string, input authz.Answer, revision uint64) (*record, error) {
	if revision != m.store.Doc.Revision {
		return nil, errPolicyConflict
	}
	choices := []string{authz.AnswerOnce, authz.AnswerSave, authz.AnswerDeny}
	if !slices.Contains(choices, input.Choice) {
		return nil, fmt.Errorf("decision must be one of %s", strings.Join(choices, ", "))
	}
	if len(input.Reason) > maxReason {
		return nil, fmt.Errorf("a reason must be at most %d bytes", maxReason)
	}
	r := m.findRecord(id)
	if r == nil {
		return nil, fmt.Errorf("no request %s", id)
	}
	if r.State != authz.StatePending && !(r.State == authz.StateExpired && input.Choice == authz.AnswerSave) {
		return nil, fmt.Errorf("request %s is %s", id, r.State)
	}
	return r, nil
}

func (m *Monitor) answerRequest(ctx context.Context, id string, input authz.Answer, revision uint64) error {
	input.Reason = strings.TrimSpace(input.Reason)
	caller, _ := CallerFrom(ctx)
	m.mu.Lock()
	r := m.findRecord(id)
	applies := input.Choice == authz.AnswerSave || input.Choice == authz.AnswerOnce && r != nil && r.Changes != nil
	var refusal error
	if r != nil {
		refusal = m.admit(ctx, m.settings.Load().Engine, adminCall{Answer: input, Record: r})
	}
	m.mu.Unlock()
	if refusal != nil {
		return refusal
	}
	review := authz.Review{By: caller.Name, Answer: input}
	if applies {
		m.writes.Lock()
		defer m.writes.Unlock()
		m.mu.Lock()
		r, err := m.answerable(id, input, revision)
		var change config.Change
		if err == nil && input.Choice == authz.AnswerSave {
			change, err = m.ruleChange(r)
		}
		m.mu.Unlock()
		if err != nil {
			return err
		}
		changes := r.Changes
		if input.Choice == authz.AnswerSave {
			changes = []config.Change{change}
		}
		err = m.writeSettings(ctx, settingsWrite{changes: changes, check: func() error {
			current, err := m.answerable(id, input, revision)
			if err == nil && current != r {
				return errRecordGone
			}
			return err
		}, saved: &savedAnswer{record: r, answer: review}})
		if err == nil && r.Changes != nil {
			m.mu.Lock()
			m.settleRecord(r, nil)
			m.mu.Unlock()
		}
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := m.answerable(id, input, revision)
	if err != nil {
		return err
	}
	m.gate.Answer(r.Record, review)
	if r.Changes != nil {
		m.settleRecord(r, nil)
	}
	return nil
}

// RunAudit flushes on an interval until ctx ends, then once more.
func (m *Monitor) RunAudit(ctx context.Context) { m.audit.Run(ctx) }

// auditPage is one page of settled records, newest first.
type auditPage struct {
	Records []recordSummary `json:"records"`
	Next    string          `json:"next,omitempty"`
}

// readAuditPage returns settled records older than the segment named by before, newest first.
// Records still in the live log are skipped, so the page continues where the live log ends.
func (m *Monitor) readAuditPage(ctx context.Context, before string) (auditPage, error) {
	m.mu.Lock()
	live := map[string]bool{}
	for _, record := range m.records {
		live[record.ID] = true
	}
	m.mu.Unlock()
	page := auditPage{Records: []recordSummary{}}
	var err error
	page.Next, err = m.audit.Page(ctx, before, func(segment string, r *record) bool {
		if live[r.ID] {
			return false
		}
		summary := summarize(r.Record)
		summary.Segment = segment
		page.Records = append(page.Records, summary)
		return true
	})
	return page, err
}

func (m *Monitor) readAuditRecord(ctx context.Context, segment, id string) (*record, error) {
	records, err := m.audit.Read(ctx, segment)
	if err != nil {
		return nil, err
	}
	for _, record := range records {
		if record.ID == id {
			return record, nil
		}
	}
	return nil, errRecordGone
}
