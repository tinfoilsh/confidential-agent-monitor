package monitor

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/internal/config"
	"github.com/tinfoilsh/monitor/internal/frontdoor"
	"github.com/tinfoilsh/monitor/internal/policy"
)

const (
	approvalWait    = 2 * time.Minute
	maxRecords      = 1000
	maxReason       = 4096
	maxSummaryTitle = 512

	statePending  = "pending"
	stateExpired  = "expired"
	stateOutdated = "outdated"
	stateAllowed  = "allowed"
	stateRefused  = "refused"
	stateApproved = "approved"
	stateDenied   = "denied"

	answerOnce = "once"
	answerSave = "save"
	answerDeny = "deny"
)

var (
	errRecordGone = errors.New("this request is no longer in the activity log")
	errRuleSaved  = errors.New("approval rule saved; retry the request")
)

type reviewAnswer struct {
	By string `json:"by"`
	answerInput
	Time time.Time `json:"time"`
}

type answerInput struct {
	Choice string `json:"decision"`
	Reason string `json:"reason,omitempty"`
}

// savedAnswer carries the answer to publish with its durable settings change.
type savedAnswer struct {
	record *record
	answer reviewAnswer
}

// A record is one decision; requests are the pending and expired ones.
type record struct {
	ID      string          `json:"id"`
	State   string          `json:"state"`
	Invalid bool            `json:"invalid,omitempty"`
	Time    time.Time       `json:"time"`
	Expires time.Time       `json:"expires,omitzero"`
	Facts   json.RawMessage `json:"facts"`
	policy.Decision
	ApprovalKey string         `json:"definition"`
	Grant       map[string]any `json:"grant"`
	Reviews     []reviewAnswer `json:"reviews,omitempty"`
	// Changes makes the record a policy proposal; scope is what it was reviewed against.
	Changes []config.Change `json:"changes,omitempty"`
	scope   string
}

// Activity never needs request bodies, policy parameters or saved-rule grants.
// Keep those in the existing audit record and load one through /requests/{id}.
type recordSummary struct {
	ID      string         `json:"id"`
	State   string         `json:"state"`
	Invalid bool           `json:"invalid,omitempty"`
	Time    time.Time      `json:"time"`
	Expires time.Time      `json:"expires,omitzero"`
	Summary bool           `json:"summary"`
	Reviews []reviewAnswer `json:"reviews,omitempty"`
	Segment string         `json:"segment,omitempty"`
	Facts   struct {
		Principal  facts.Principal  `json:"principal"`
		Connection string           `json:"connection"`
		Service    string           `json:"service"`
		Operation  *facts.Operation `json:"operation"`
		Title      string           `json:"title"`
	} `json:"facts"`
}

var (
	errChanged = errors.New("configuration changed; retry the request")
	errNoAgent = errors.New("this agent's identity was removed")
)

func (m *monitor) authorizeAdmission(ctx context.Context, admitted admission, target frontdoor.Target) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if admitted.connection == nil {
		return errors.New("service removed")
	}
	f := facts.Facts{
		Operation:  &facts.Operation{Action: "session.admit", Effects: []string{"session"}},
		Title:      "Open " + admitted.connection.Name,
		Parameters: map[string]any{"host": target.Host, "port": target.Port},
		Details:    map[string]any{"tcp": map[string]any{"host": target.Host, "port": target.Port}},
		Context:    facts.Context{Observes: cleanLabel},
	}
	r, err := m.authorizeLocked(ctx, admitted, facts.KindAdmission, facts.Capture(f, nil))
	if r != nil {
		m.settleRecord(r, err)
	}
	return err
}

func (m *monitor) authorizeOperation(ctx context.Context, stream *connector.Stream, admitted admission, event facts.Event) error {
	if stream == nil {
		return errors.New("operation authorization requires a stream")
	}
	if err := stream.Context.Err(); err != nil {
		return err
	}
	ctx, cancel := connector.Bind(ctx, stream.Context)
	defer cancel()
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := m.authorizeLocked(ctx, admitted, facts.KindOperation, event)
	if r != nil {
		if err == nil {
			err = m.relabel(ctx, admitted.fingerprint, r.Next, stream)
		}
		m.settleRecord(r, err)
	}
	return err
}

// authorizeLocked runs under mu, releasing it only around approval waits.
// Callers settle its record after any label persistence, before execution begins.
func (m *monitor) authorizeLocked(ctx context.Context, admitted admission, kind facts.Kind, event facts.Event) (*record, error) {
	var r *record
	var approvals []config.Rule
	for {
		if err := ctx.Err(); err != nil {
			return r, err
		}
		if m.audit.Backlogged() {
			return r, errAuditBacklog
		}
		st := m.settings.Load()
		p, ok := st.Principal(admitted.fingerprint)
		if !ok {
			return r, errNoAgent
		}
		c := admitted.connection
		if !m.usable(c, admitted.prepared) {
			return r, errChanged
		}
		f, describeErr := st.bindFacts(c, p, m.currentLabel(p.Key), kind, event)
		if describeErr != nil {
			f.Operation = nil
			raw, _, err := facts.Encode(f)
			if err != nil {
				return nil, err
			}
			return m.addRecord(&record{Facts: raw, Invalid: true}), describeErr
		}
		input, next, err := st.policyInput(c, p, f, approvals)
		if err != nil {
			return r, err
		}
		if next.Decision, err = st.Engine.Decide(ctx, input); err != nil {
			return r, err
		}
		if r == nil {
			r = m.addRecord(next)
		}
		r.Facts, r.Decision, r.ApprovalKey, r.Grant = next.Facts, next.Decision, next.ApprovalKey, next.Grant
		if len(r.Deny) != 0 {
			return r, errors.New(strings.Join(r.Deny, "; "))
		}
		if len(r.Requirements) == 0 {
			if r.State == statePending {
				r.State = stateAllowed
			}
			return r, ctx.Err()
		}
		if err := m.awaitAnswer(ctx, r); err != nil {
			return r, err
		}
		if r.State == stateApproved {
			approvals = append(approvals, config.Rule{Connection: c.Name, ApprovalKey: r.ApprovalKey, Scope: r.Grant, Requirements: r.Requirements})
		}
	}
}

func (st *settings) bindFacts(c *connection, p config.Principal, label facts.Label, kind facts.Kind, event facts.Event) (facts.Facts, error) {
	f, err := event.Facts()
	f.Version, f.Kind = facts.Version, kind
	f.Service, f.Connection = st.Connections[c.Name].Preset, c.Name
	f.Principal, f.Context.Label = p, label
	if f.Parameters == nil {
		f.Parameters = map[string]any{}
	}
	if f.Scope == nil {
		f.Scope = f.Parameters
	}
	return f, err
}

// policyInput builds the engine input and the record its decision will fill.
func (st *settings) policyInput(c *connection, p config.Principal, f facts.Facts, approvals []config.Rule) (map[string]any, *record, error) {
	modes := st.Config.EffectModes(p.Name, c.Name, f.Operation)
	key, err := approvalKey(st, c, f, modes)
	if err != nil {
		return nil, nil, err
	}
	grant := f.Scope
	encoded, policyFacts, err := facts.Encode(f)
	if err != nil {
		return nil, nil, err
	}
	access, err := facts.JSON[map[string]any](st.Access(p.Name, c.Name))
	if err != nil {
		return nil, nil, err
	}
	authorization := map[string]any{
		"access":     access,
		"effects":    modes,
		"rules":      append(slices.Collect(maps.Values(st.Identities[p.Name].Rules)), approvals...),
		"definition": key,
		"grant":      grant,
	}
	connection := st.Connections[c.Name]
	connectionInput := map[string]any{
		"contents":     connection.Contents,
		"strangers":    connection.Strangers,
		"sends":        connection.Sends,
		"private":      connection.PolicyOptions.Private,
		"public_scope": c.PublicScope,
	}
	return map[string]any{
		"facts":         policyFacts,
		"authorization": authorization,
		"connection":    connectionInput,
	}, &record{Facts: encoded, Grant: grant, ApprovalKey: key}, nil
}

// approvalKey binds saved grants to semantics and configuration, excluding
// display fields and current labels. The positional encoding is persisted in
// existing grants: preserve its order and representation when refactoring.
func approvalKey(st *settings, c *connection, f facts.Facts, modes map[string]string) (string, error) {
	connection := st.Connections[c.Name]
	raw, err := json.Marshal([]any{
		st.Engine.Program,
		st.Lattices,
		modes,
		f.Kind,
		connection.Preset,
		c.Name,
		c.Config,
		connection.PolicyOptions,
		connection.Contents,
		connection.Strangers,
		connection.Sends,
		c.PublicScope,
		f.Definition,
		f.Operation,
		f.Context.Sends,
		f.Context.Observes,
	})
	if err != nil {
		return "", fmt.Errorf("encode approval definition: %w", err)
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// ruleChange derives a saved rule only from frozen audit/grant data under mu.
func (m *monitor) ruleChange(r *record) (config.Change, error) {
	f := r.summary().Facts
	if f.Operation == nil || f.Operation.ID == "" {
		return config.Change{}, errors.New("a request without a known operation cannot be saved")
	}
	p, exists := m.settings.Load().Principal(f.Principal.Key)
	if !exists || p.Name != f.Principal.Name {
		return config.Change{}, errors.New("the requesting identity was revoked or replaced")
	}
	return config.Change{Path: []string{"identities", p.Name, "rules", r.ID}, Value: config.Rule{Connection: f.Connection, Action: f.Operation.Action, Operation: f.Operation.ID,
		ApprovalKey: r.ApprovalKey, Scope: r.Grant, Requirements: slices.Clone(r.Requirements)}}, nil
}

var cleanLabel = facts.Label{Trust: "trusted", Audience: "anyone"}

func (m *monitor) currentLabel(fingerprint string) facts.Label {
	if l, ok := m.store.Doc.Labels[fingerprint]; ok {
		return l
	}
	return cleanLabel
}

// relabel runs under mu; a failed write never publishes an observation.
// source is the stream whose operation produced l, or nil for an owner reset.
func (m *monitor) relabel(ctx context.Context, fingerprint string, l facts.Label, source *connector.Stream) error {
	if old := m.currentLabel(fingerprint); old.Trust == l.Trust && old.Audience == l.Audience {
		return nil
	}
	next := m.store.Doc
	next.Labels = maps.Clone(m.store.Doc.Labels)
	next.Labels[fingerprint] = l
	if err := m.store.Commit(ctx, next); err != nil {
		return err
	}
	// With both lattices off a label is recorded but never enforced, so a
	// change in it is no reason to cut anything.
	lattices := m.settings.Load().Config.Lattices
	if source != nil && !lattices.Confidentiality && !lattices.Integrity {
		return nil
	}
	// An opaque source may finish the session it just admitted. Other opaque
	// sessions cannot recheck their bytes, so revoke them. Sandbox routes carry
	// end-to-end traffic under Operator alone.
	for s, a := range m.streams {
		if a.fingerprint == fingerprint && s != source && !a.route {
			c := a.connection
			// Close every connector stream so old deliveries cannot recontaminate a reset.
			if source == nil || c == nil || !m.kinds[c.Protocol].PerMessage {
				s.Close()
			}
		}
	}
	return nil
}

func (r *record) summary() recordSummary {
	v := recordSummary{ID: r.ID, State: r.State, Invalid: r.Invalid, Time: r.Time, Expires: r.Expires, Summary: true}
	for _, answer := range r.Reviews {
		answer.Reason = ""
		v.Reviews = append(v.Reviews, answer)
	}
	_ = json.Unmarshal(r.Facts, &v.Facts)
	// SQL and other protocol titles can contain the entire request.
	if len(v.Facts.Title) > maxSummaryTitle {
		v.Facts.Title = strings.ToValidUTF8(v.Facts.Title[:maxSummaryTitle], "") + "…"
	}
	return v
}

// addRecord and the other decision transitions run under the authorization lock.
func (m *monitor) addRecord(r *record) *record {
	r.ID, r.Time, r.State = rand.Text(), time.Now(), stateAllowed
	for len(m.records) >= maxRecords {
		// Nothing else holds a pending proposal.
		i := slices.IndexFunc(m.records, func(r *record) bool { return r.State != statePending })
		if i < 0 {
			break
		}
		m.records = slices.Delete(m.records, i, i+1)
	}
	m.records = append(m.records, r)
	return r
}

func (m *monitor) findRecord(id string) *record {
	i := slices.IndexFunc(m.records, func(r *record) bool { return r.ID == id })
	if i < 0 {
		return nil
	}
	return m.records[i]
}

// awaitAnswer publishes a pending record under mu and releases mu until it is
// answered, expires or anything changes; a record still pending is checked again.
func (m *monitor) awaitAnswer(ctx context.Context, r *record) error {
	if r.State != statePending {
		r.State, r.Expires = statePending, time.Now().Add(approvalWait)
	}
	wait, cancel := context.WithDeadline(ctx, r.Expires)
	defer cancel()
	// Taking mu keeps the wakeup from landing before Wait.
	stop := context.AfterFunc(wait, func() { m.mu.Lock(); m.cond.Broadcast(); m.mu.Unlock() })
	defer stop()
	m.cond.Wait()
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.State == stateDenied {
		return errors.New("this request was denied")
	}
	if r.State == stateApproved || wait.Err() == nil {
		return nil
	}
	r.State = stateExpired
	return errors.New("waiting for approval in the Perimeter timed out")
}

// settleRecord marks a record refused when its request fails for a reason other than the owner's answer,
// then queues its final outcome for the audit log.
func (m *monitor) settleRecord(r *record, err error) {
	if err != nil && r.State != stateDenied && r.State != stateExpired {
		r.State = stateRefused
		if len(r.Deny) == 0 {
			r.Deny = []string{err.Error()}
		}
	}
	if err := m.audit.Append(r); err != nil {
		log.Printf("audit record %s: %v", r.ID, err)
	}
}

// answerable validates an answer under mu; callers recheck it after pure
// preparation so a concurrent answer cannot be overwritten by a saved rule.
func (m *monitor) answerable(id string, input answerInput) (*record, error) {
	choices := []string{answerOnce, answerSave, answerDeny}
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
	if r.State != statePending && !(r.State == stateExpired && input.Choice == answerSave) {
		return nil, fmt.Errorf("request %s is %s", id, r.State)
	}
	return r, nil
}

func (m *monitor) answerRequest(ctx context.Context, id string, input answerInput) error {
	input.Reason = strings.TrimSpace(input.Reason)
	m.mu.Lock()
	r := m.findRecord(id)
	applies := input.Choice == answerSave || input.Choice == answerOnce && r != nil && r.Changes != nil
	m.mu.Unlock()
	if applies {
		m.writes.Lock()
		defer m.writes.Unlock()
		m.mu.Lock()
		r, err := m.answerable(id, input)
		var change config.Change
		if err == nil && input.Choice == answerSave {
			change, err = m.ruleChange(r)
		}
		m.mu.Unlock()
		if err != nil {
			return err
		}
		changes := r.Changes
		if input.Choice == answerSave {
			changes = []config.Change{change}
		}
		err = m.writeSettings(ctx, settingsWrite{changes: changes, check: func() error {
			current, err := m.answerable(id, input)
			if err == nil && current != r {
				return errRecordGone
			}
			return err
		}, saved: &savedAnswer{
			record: r,
			answer: reviewAnswer{By: "owner", answerInput: input},
		}})
		if err == nil && r.Changes != nil {
			m.mu.Lock()
			m.settleRecord(r, nil)
			m.mu.Unlock()
		}
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := m.answerable(id, input)
	if err != nil {
		return err
	}
	r.Reviews = append(r.Reviews, reviewAnswer{By: "owner", answerInput: input, Time: time.Now()})
	r.State = stateApproved
	if input.Choice == answerDeny {
		r.State = stateDenied
	}
	m.cond.Broadcast()
	if r.Changes != nil {
		m.settleRecord(r, nil)
	}
	return nil
}

func (r *record) committed(answer reviewAnswer) {
	if r.State == statePending {
		r.State = stateApproved
	} else {
		r.State, r.Deny = stateRefused, []string{errRuleSaved.Error()}
	}
	answer.Time = time.Now()
	r.Reviews = append(r.Reviews, answer)
}

var errAuditBacklog = errors.New("the Perimeter cannot write its audit log; requests are refused until storage recovers")

// RunAudit flushes on an interval until ctx ends, then once more.
func (m *monitor) RunAudit(ctx context.Context) { m.audit.Run(ctx) }

// auditPage is one page of settled records, newest first.
type auditPage struct {
	Records []recordSummary `json:"records"`
	Next    string          `json:"next,omitempty"`
}

// readAuditPage returns settled records older than the segment named by before, newest first.
// Records still in the live log are skipped, so the page continues where the live log ends.
func (m *monitor) readAuditPage(ctx context.Context, before string) (auditPage, error) {
	m.mu.Lock()
	live := make(map[string]bool, len(m.records))
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
		summary := r.summary()
		summary.Segment = segment
		page.Records = append(page.Records, summary)
		return true
	})
	return page, err
}

func (m *monitor) readAuditRecord(ctx context.Context, segment, id string) (*record, error) {
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
