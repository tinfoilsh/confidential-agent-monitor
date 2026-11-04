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
	approvalWait = 2 * time.Minute
	maxRecords   = 1000

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

// A review answer records who resolved one pending request.
type reviewAnswer struct {
	By string `json:"by"`
	answerInput
	Time time.Time `json:"time"`
}

type answerInput struct {
	Choice string `json:"decision"`
	Reason string `json:"reason,omitempty"`
}

// savedAnswer carries the answer to publish with its durable policy rule.
type savedAnswer struct {
	record *record
	answer reviewAnswer
}

// A record is one decision; requests are the pending and expired ones.
type record struct {
	developmentRecordFields
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
	answered    chan struct{}
}

// Activity never needs request bodies, policy parameters or saved-rule grants.
// Keep those in the existing audit record and load one through /requests/{id}.
type recordSummary struct {
	developmentRecordSummaryFields
	ID      string         `json:"id"`
	State   string         `json:"state"`
	Invalid bool           `json:"invalid,omitempty"`
	Time    time.Time      `json:"time"`
	Expires time.Time      `json:"expires,omitzero"`
	Summary bool           `json:"summary"`
	Reviews []reviewAnswer `json:"reviews,omitempty"`
	Segment string         `json:"segment,omitempty"`
	Facts   struct {
		Principal facts.Principal  `json:"principal"`
		Account   string           `json:"account"`
		Service   string           `json:"service"`
		Operation *facts.Operation `json:"operation"`
		Title     string           `json:"title"`
	} `json:"facts"`
}

var (
	errChanged      = errors.New("configuration changed; retry the request")
	errLabelChanged = errors.New("the agent's security label changed while waiting for approval; retry the request")
	errNoAgent      = errors.New("this agent's identity was removed")
)

func (m *monitor) authorizeAdmission(ctx context.Context, admitted admission, target frontdoor.Target) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if admitted.connection == nil {
		return errors.New("connection removed")
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

// authorizeLocked runs under mu, releasing it only around the approval wait.
// Callers settle its record after any label persistence, before execution begins.
func (m *monitor) authorizeLocked(ctx context.Context, admitted admission, kind facts.Kind, event facts.Event) (*record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Refuse work without audit capacity.
	if m.audit.Backlogged() {
		return nil, errAuditBacklog
	}
	st := m.settings.Load()
	p, ok := st.Principal(admitted.fingerprint)
	if !ok {
		return nil, errNoAgent
	}
	c := admitted.connection
	if !m.usable(c, admitted.prepared) {
		return nil, errChanged
	}
	f, describeErr := st.bindFacts(c, p, m.currentLabel(p.Fingerprint), kind, event)
	if describeErr != nil {
		f.Operation = nil
		raw, _, err := facts.Encode(f)
		if err != nil {
			return nil, err
		}
		return m.addRecord(&record{Facts: raw, Invalid: true}), describeErr
	}
	input, r, err := st.policyInput(c, p, f)
	if err != nil {
		return nil, err
	}
	if r.Decision, err = st.Engine.Decide(ctx, input); err != nil {
		return nil, err
	}
	m.addRecord(r)
	if len(r.Deny) != 0 {
		return r, errors.New(strings.Join(r.Deny, "; "))
	}
	if len(r.Requirements) != 0 {
		assignDevelopmentReviewer(st, r, p.Name)
		if err := m.awaitAnswer(ctx, r); err != nil {
			return r, err
		}
		if m.settings.Load() != st || !m.usable(c, admitted.prepared) {
			return r, errChanged
		}
		label := m.currentLabel(p.Fingerprint)
		if label.Audience != f.Context.Label.Audience || label.Trust != f.Context.Label.Trust {
			return r, errLabelChanged
		}
	}
	return r, ctx.Err()
}

func (st *settings) bindFacts(c *connection, p config.Principal, label facts.Label, kind facts.Kind, event facts.Event) (facts.Facts, error) {
	f, err := event.Facts()
	f.Version, f.Kind = facts.Version, kind
	f.Account, f.Service, f.Connection = c.Account, st.Accounts[c.Account].Preset, c.Name
	f.Principal, f.Context.Label = facts.Principal{Key: p.Fingerprint, Name: p.Name}, label
	if f.Parameters == nil {
		f.Parameters = map[string]any{}
	}
	if f.Scope == nil {
		f.Scope = f.Parameters
	}
	return f, err
}

// policyInput builds the engine input and the record its decision will fill.
func (st *settings) policyInput(c *connection, p config.Principal, f facts.Facts) (map[string]any, *record, error) {
	// Bind saved approvals to the operation's meaning under these settings.
	modes := st.Config.EffectModes(p.Name, c.Account, f.Operation)
	key, err := approvalKey(st, c, f, modes)
	if err != nil {
		return nil, nil, err
	}
	grant := f.Scope
	// Policy and audit share one snapshot, independent of connector buffers.
	encoded, policyFacts, err := facts.Encode(f)
	if err != nil {
		return nil, nil, err
	}
	access, err := facts.JSON[map[string]any](st.Access(p.Name, c.Account))
	if err != nil {
		return nil, nil, err
	}
	authorization := map[string]any{
		"access":     access,
		"effects":    modes,
		"rules":      st.Identities[p.Name].Rules,
		"definition": key,
		"grant":      grant,
	}
	account := st.Accounts[c.Account]
	accountInput := map[string]any{
		"contents":     account.Contents,
		"strangers":    account.Strangers,
		"sends":        account.Sends,
		"private":      account.PolicyOptions.Private,
		"public_scope": c.PublicScope,
	}
	return map[string]any{
		"facts":         policyFacts,
		"authorization": authorization,
		"account":       accountInput,
	}, &record{Facts: encoded, Grant: grant, ApprovalKey: key}, nil
}

// approvalKey binds saved grants to semantics and configuration, excluding
// display fields and current labels. The positional encoding is persisted in
// existing grants: preserve its order and representation when refactoring.
func approvalKey(st *settings, c *connection, f facts.Facts, modes map[string]string) (string, error) {
	account := st.Accounts[c.Account]
	raw, err := json.Marshal([]any{
		st.Engine.Program,
		st.Lattices,
		modes,
		f.Kind,
		account.Preset,
		c.Name,
		c.Config,
		account.PolicyOptions,
		account.Contents,
		account.Strangers,
		account.Sends,
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
	return config.Change{Path: []string{"identities", p.Name, "rules", r.ID}, Value: config.Rule{Account: f.Account, Action: f.Operation.Action, Operation: f.Operation.ID,
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
	// end-to-end traffic under Routes alone.
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
	copyDevelopmentReviewSummary(r, &v)
	for _, answer := range r.Reviews {
		answer.Reason = ""
		v.Reviews = append(v.Reviews, answer)
	}
	_ = json.Unmarshal(r.Facts, &v.Facts)
	// SQL and other protocol titles can contain the entire request.
	if len(v.Facts.Title) > 512 {
		v.Facts.Title = strings.ToValidUTF8(v.Facts.Title[:512], "") + "…"
	}
	return v
}

// addRecord and the other decision transitions run under the authorization lock.
func (m *monitor) addRecord(r *record) *record {
	r.ID, r.Time, r.State = rand.Text(), time.Now(), stateAllowed
	m.records = append(m.records, r)
	if len(m.records) > maxRecords {
		m.records = m.records[1:]
	}
	return r
}

func (m *monitor) findRecord(id string) *record {
	i := slices.IndexFunc(m.records, func(r *record) bool { return r.ID == id })
	if i < 0 {
		return nil
	}
	return m.records[i]
}

// refusePending refuses every record still waiting for an answer; the caller holds mu.
func (m *monitor) refusePending(err error) {
	for _, r := range m.records {
		if r.State == statePending {
			r.State, r.Deny = stateRefused, []string{err.Error()}
			close(r.answered)
		}
	}
}

// awaitAnswer publishes a pending record under mu and releases mu until it is
// answered or expires, then examines the answer under mu.
func (m *monitor) awaitAnswer(ctx context.Context, r *record) error {
	r.State, r.Expires, r.answered = statePending, r.Time.Add(approvalWait), make(chan struct{})
	wait, cancel := context.WithDeadline(ctx, r.Expires)
	m.startDevelopmentReview(wait, r)
	m.mu.Unlock()
	select {
	case <-r.answered:
	case <-wait.Done():
	}
	cancel()
	m.mu.Lock()
	if err := ctx.Err(); err != nil {
		return err
	}
	switch r.State {
	case statePending, stateExpired:
		r.State = stateExpired
		return errors.New("waiting for approval in the monitor timed out")
	case stateDenied:
		return errors.New("this request was denied")
	case stateRefused:
		return errors.New(strings.Join(r.Deny, "; "))
	}
	return nil
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
func (m *monitor) answerable(id string, input answerInput, choices []string, reasonRequired bool) (*record, error) {
	if !slices.Contains(choices, input.Choice) {
		return nil, fmt.Errorf("decision must be one of %s", strings.Join(choices, ", "))
	}
	if len(input.Reason) > 4096 || (reasonRequired && input.Reason == "") {
		return nil, errors.New("a reason of 1-4096 bytes is required")
	}
	r := m.findRecord(id)
	if r == nil {
		return nil, fmt.Errorf("no request %s", id)
	}
	if r.State == statePending && !time.Now().Before(r.Expires) {
		r.State = stateExpired
		close(r.answered)
	}
	// Expired requests can save rules.
	if r.State != statePending && !(r.State == stateExpired && input.Choice == answerSave) {
		return nil, fmt.Errorf("request %s is %s", id, r.State)
	}
	return r, nil
}

func (m *monitor) answerRequest(ctx context.Context, id string, input answerInput) error {
	input.Reason = strings.TrimSpace(input.Reason)
	choices := []string{answerOnce, answerSave, answerDeny}
	if input.Choice == answerSave {
		m.writes.Lock()
		defer m.writes.Unlock()
		m.mu.Lock()
		r, err := m.answerable(id, input, choices, false)
		var change config.Change
		if err == nil {
			change, err = m.ruleChange(r)
		}
		m.mu.Unlock()
		if err != nil {
			return err
		}
		return m.writeSettings(ctx, nil, []config.Change{change}, func() error {
			current, err := m.answerable(id, input, choices, false)
			if err == nil && current != r {
				return errRecordGone
			}
			return err
		}, &savedAnswer{
			record: r,
			answer: reviewAnswer{By: "owner", answerInput: input},
		}, "")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := m.answerable(id, input, choices, false)
	if err != nil {
		return err
	}
	r.Reviews = append(r.Reviews, reviewAnswer{By: "owner", answerInput: input, Time: time.Now()})
	r.State = stateApproved
	if input.Choice == answerDeny {
		r.State = stateDenied
	}
	close(r.answered)
	return nil
}

func (r *record) ruleSaved(answer reviewAnswer) {
	if r.State == statePending {
		close(r.answered)
	}
	// Retry evaluates the operation under the newly committed rule.
	r.State, r.Deny = stateRefused, []string{errRuleSaved.Error()}
	answer.Time = time.Now()
	r.Reviews = append(r.Reviews, answer)
}

var errAuditBacklog = errors.New("the monitor cannot write its audit log; requests are refused until storage recovers")

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

// readAuditRecord reads one record from a segment.
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
