package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/config"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/format"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/migrate"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/catalog"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/tomledit"
	"gocloud.dev/gcerrors"
)

const (
	statePending  = "pending"
	stateExpired  = "expired"
	stateOutdated = "outdated"
	stateAllowed  = "allowed"
	stateRefused  = "refused"
	stateDenied   = "denied"
	stateRevoked  = "revoked"

	answerOnce = "once"
	answerSave = "save"
	answerDeny = "deny"

	maxRecords      = 1000
	maxReason       = 4096
	maxSummaryTitle = 512
	auditPrefix     = "audit/"
)

var (
	errRecordGone  = httpError{errors.New("this request is no longer in the activity log"), http.StatusNotFound}
	errNoAgent     = httpError{errRemoved, http.StatusForbidden}
	errAnswerStale = httpError{errors.New("the request changed; review it again"), http.StatusConflict}
)

type Answer struct {
	Choice string   `json:"decision"`
	Reason string   `json:"reason,omitempty"`
	Gaps   []string `json:"gaps,omitempty"`
}

type Review struct {
	By string `json:"by"`
	Answer
	Time time.Time `json:"time"`
}

type record struct {
	ID       string            `json:"id"`
	State    string            `json:"state"`
	Time     time.Time         `json:"time"`
	Expires  time.Time         `json:"expires,omitzero"`
	Facts    json.RawMessage   `json:"facts"`
	Decision *config.Decision  `json:"decision,omitempty"`
	Refusal  *refusal          `json:"refusal,omitempty"`
	Scope    map[string]any    `json:"scope"`
	Reviews  []Review          `json:"reviews,omitempty"`
	Changes  []tomledit.Change `json:"changes,omitempty"`
}

type savedAnswer struct {
	record *record
	answer Review
}

type recordSummary struct {
	ID      string    `json:"id"`
	State   string    `json:"state"`
	Time    time.Time `json:"time"`
	Expires time.Time `json:"expires,omitzero"`
	Summary bool      `json:"summary"`
	Reviews []Review  `json:"reviews,omitempty"`
	Segment string    `json:"segment,omitempty"`
	Facts   subject   `json:"facts"`
}

type subject struct {
	Kind       string             `json:"kind"`
	Principal  facts.Principal    `json:"principal"`
	Connection string             `json:"connection"`
	Service    string             `json:"service"`
	Operation  *catalog.Operation `json:"operation"`
	Title      string             `json:"title"`
}

func (r *record) subject() (f subject) {
	_ = json.Unmarshal(r.Facts, &f)
	return f
}

func summarize(r *record) recordSummary {
	v := recordSummary{ID: r.ID, State: r.State, Time: r.Time, Expires: r.Expires, Summary: true, Facts: r.subject()}
	for _, review := range r.Reviews {
		review.Reason = ""
		v.Reviews = append(v.Reviews, review)
	}
	if len(v.Facts.Title) > maxSummaryTitle {
		v.Facts.Title = strings.ToValidUTF8(v.Facts.Title[:maxSummaryTitle], "") + "…"
	}
	return v
}

func (s held) addRecord(r *record) *record {
	r.ID, r.Time, r.State = rand.Text(), time.Now(), statePending
	s.records.Add(r)
	return r
}

func (s held) findRecord(id string) *record {
	r, _ := s.records.Find(func(r *record) bool { return r.ID == id })
	return r
}

func (s held) announce(r *record) {
	events.Info("record", "record", summarize(r), "generation", s.doc.Generation)
}

func (s held) settleRecord(r *record, refused *refusal) {
	r.State = stateAllowed
	if refused != nil {
		r.State = refused.state()
	}
	switch {
	case r.State != stateRefused:
	case r.Decision != nil && r.Decision.Outcome == config.OutcomeDeny:
		r.Refusal = refuse(refused.Cause)
	default:
		r.Refusal = refused
	}
	s.auditRecord(r)
}

func (s held) revokeRecord(r *record, refused *refusal) {
	s.addRecord(r)
	r.State, r.Refusal = stateRevoked, refused
	s.auditRecord(r)
}

func (s held) outdateRecord(r *record) {
	r.State = stateOutdated
	s.auditRecord(r)
}

func (s held) auditRecord(r *record) {
	if line, err := json.Marshal(r); err != nil {
		log.Printf("audit record %s: %v", r.ID, err)
	} else {
		s.audit.Append(line)
	}
	s.announce(r)
}

func (s held) ruleChange(r *record) (tomledit.Change, error) {
	f := r.subject()
	if f.Kind == config.KindAdmission {
		return tomledit.Change{}, errors.New("an admission cannot be saved as a rule; grant sessions with effects.session")
	}
	if f.Operation == nil || f.Operation.ID == "" {
		return tomledit.Change{}, errors.New("a request without a known operation cannot be saved")
	}
	p, exists := s.identities.Lookup(f.Principal.Key)
	if !exists || p.Name != f.Principal.Name {
		return tomledit.Change{}, errors.New("the requesting identity was revoked or replaced")
	}
	if _, declared := s.settings.Load().Identities[p.Name]; !declared {
		return tomledit.Change{}, errors.New("an approval for a certificate that binds to no declared identity cannot be saved as a rule")
	}
	return tomledit.Change{Path: []string{"identities", p.Name, "rules", r.ID}, Value: config.Rule{Version: config.FactsVersion, Connection: f.Connection, Action: f.Operation.Action, Operation: f.Operation.ID,
		Scope: r.Scope, Requirements: slices.Clone(r.Decision.Gaps)}}, nil
}

func (s held) findAnswerable(id string, input Answer, revision uint64) (*record, error) {
	if revision != s.doc.Revision {
		return nil, errPolicyConflict
	}
	if len(input.Reason) > maxReason {
		return nil, fmt.Errorf("a reason must be at most %d bytes", maxReason)
	}
	r := s.findRecord(id)
	if r == nil {
		return nil, fmt.Errorf("no request %s", id)
	}
	if r.State != statePending && !(r.State == stateExpired && input.Choice == answerSave) {
		return nil, fmt.Errorf("request %s is %s", id, r.State)
	}
	// An approval waives exactly the gaps its answerer saw, never ones a re-decision added since.
	seen := slices.Compact(slices.Sorted(slices.Values(input.Gaps)))
	if input.Choice != answerDeny && r.Decision != nil && r.Decision.Outcome == config.OutcomeAsk && !slices.Equal(seen, gapIDs(r.Decision.Gaps)) {
		return nil, errAnswerStale
	}
	return r, nil
}

func (s held) appendReview(r *record, review Review) {
	review.Time = time.Now()
	r.Reviews = append(r.Reviews, review)
	s.records.Notify()
}

// A proposal leaves pending at once, before the settings it applied could outdate it.
func (s held) appendSavedReview(r *record, review Review) {
	if r.Changes != nil {
		r.State = stateAllowed
	}
	s.appendReview(r, review)
}

func (s *state) answerRequest(ctx context.Context, id string, input Answer, revision uint64) error {
	input.Reason = strings.TrimSpace(input.Reason)
	c, _ := callerFrom(ctx)
	var applies bool
	s.locked(func(h held) {
		r := h.findRecord(id)
		applies = input.Choice == answerSave || input.Choice == answerOnce && r != nil && r.Changes != nil
	})
	review := Review{By: c.Name, Answer: input}
	if applies {
		saved := &savedAnswer{answer: review}
		err := s.writeSettings(ctx, settingsWrite{derive: func(h held) ([]tomledit.Change, error) {
			r, err := h.findAnswerable(id, input, revision)
			if err != nil {
				return nil, err
			}
			saved.record = r
			if input.Choice != answerSave {
				return r.Changes, nil
			}
			change, err := h.ruleChange(r)
			return []tomledit.Change{change}, err
		}, check: func(h held) error {
			current, err := h.findAnswerable(id, input, revision)
			if err == nil && current != saved.record {
				return errRecordGone
			}
			return err
		}, saved: saved})
		if err == nil && saved.record.Changes != nil {
			s.locked(func(h held) { h.settleRecord(saved.record, nil) })
		}
		return err
	}
	var err error
	s.locked(func(h held) {
		var r *record
		if r, err = h.findAnswerable(id, input, revision); err != nil {
			return
		}
		h.appendReview(r, review)
		if r.Changes != nil {
			h.settleRecord(r, errRejected)
		}
	})
	return err
}

type auditPage struct {
	Records []recordSummary `json:"records"`
	Next    string          `json:"next,omitempty"`
}

func (s *state) readAuditPage(ctx context.Context, before string, shows func(subject string) bool) (auditPage, error) {
	live := map[string]bool{}
	s.locked(func(h held) {
		for r := range h.records.All() {
			live[r.ID] = true
		}
	})
	page := auditPage{Records: []recordSummary{}}
	var err, malformed error
	page.Next, err = s.audit.Page(ctx, before, func(segment string, line []byte) bool {
		r, err := decodeRecord(line)
		malformed = cmp.Or(malformed, err)
		if err != nil || live[r.ID] || !shows(r.subject().Principal.Name) {
			return false
		}
		summary := summarize(r)
		summary.Segment = segment
		page.Records = append(page.Records, summary)
		return true
	})
	return page, cmp.Or(err, malformed)
}

func (s *state) readAuditRecord(ctx context.Context, segment, id string) (*record, error) {
	lines, err := s.audit.Read(ctx, segment)
	if gcerrors.Code(err) == gcerrors.NotFound {
		return nil, errRecordGone
	}
	if err != nil {
		return nil, err
	}
	for _, line := range lines {
		r, err := decodeRecord(line)
		if err != nil {
			return nil, err
		}
		if r.ID == id {
			return r, nil
		}
	}
	return nil, errRecordGone
}

func decodeRecord(line []byte) (*record, error) {
	line, err := migrate.Record(line)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.UseNumber()
	r := new(record)
	return r, decoder.Decode(r)
}

const maxPolicyProposals = 32

// An identity cannot tell a missing record from one it may not see.
var errRecordHidden = httpError{errors.New("this identity may not see this request"), http.StatusForbidden}

func (m adminMount) missingRecordError() error {
	if m.owner {
		return errRecordGone
	}
	return errRecordHidden
}

func subjectReadActions(action string, find func(*state, *http.Request) (string, error)) routeActions {
	return func(m adminMount, r *http.Request, _ any) ([]facts.Observation, error) {
		if m.accessOff(r, action) {
			return []facts.Observation{perimeterCall(action, nil)}, nil
		}
		subject, err := find(m.state, r)
		if errors.Is(err, errRecordGone) {
			err = m.missingRecordError()
		}
		if err != nil {
			return nil, err
		}
		return []facts.Observation{perimeterCall(action, map[string]any{"subject": subject})}, nil
	}
}

func pendingRecordSubject(s *state, r *http.Request) (subject string, err error) {
	err = errRecordGone
	s.locked(func(h held) {
		if record := h.findRecord(r.PathValue("id")); record != nil {
			subject, err = record.subject().Principal.Name, nil
		}
	})
	return subject, err
}

func auditRecordSubject(s *state, r *http.Request) (string, error) {
	record, err := s.readAuditRecord(r.Context(), r.PathValue("segment"), r.PathValue("id"))
	if err != nil {
		return "", err
	}
	return record.subject().Principal.Name, nil
}

type disclosure struct {
	st    *settings
	p     facts.Principal
	label format.Label
	read  string
	reads map[string]*config.Decision
}

func (m adminMount) newDisclosure(s held, r *http.Request, action string) (*disclosure, error) {
	c, _ := callerFrom(r.Context())
	// Decided only so that the refusal is recorded; any other identity is filtered per subject.
	if m.accessOff(r, action) {
		if refused := s.authorize(r.Context(), apiStream(c.Key, c.Name), &request{kind: config.KindOperation, known: s.settings.Load().callFacts(perimeterCall(action, nil))}); refused != nil {
			return nil, refused
		}
	}
	p, known := s.identities.Lookup(c.Key)
	if !known || p.Name != c.Name {
		return nil, errNoAgent
	}
	if s.audit.Backlogged() {
		return nil, errAuditBacklog
	}
	return &disclosure{st: s.settings.Load(), p: p, label: s.label(p.Name), read: action, reads: map[string]*config.Decision{}}, nil
}

func (d *disclosure) shows(subject string) bool {
	if d == nil {
		return true
	}
	read, decided := d.reads[subject]
	if !decided {
		read = d.st.wouldAllow(d.p, d.label, perimeterCall(d.read, map[string]any{"subject": subject}))
		d.reads[subject] = read
	}
	return read != nil
}

func (d *disclosure) audit(ctx context.Context, h held) error {
	if d == nil {
		return nil
	}
	disclosed, next := []string{}, h.label(d.p.Name)
	var decision *config.Decision
	for _, subject := range slices.Sorted(maps.Keys(d.reads)) {
		if read := d.reads[subject]; read != nil {
			disclosed, next = append(disclosed, subject), config.Meet(next, *read.Next)
			decision = &config.Decision{Outcome: config.OutcomeAllow, Sends: read.Sends}
		}
	}
	if decision == nil {
		return nil
	}
	decision.Next = &next
	f := d.st.callFacts(perimeterCall(d.read, map[string]any{"subjects": disclosed}))
	d.st.completeFacts(f, d.p, config.PerimeterConnection, config.KindOperation, d.label)
	raw, err := json.Marshal(f)
	if err != nil {
		return err
	}
	r := h.addRecord(&record{Facts: raw, Decision: decision, Scope: f.Scope})
	refused := precondition(h.relabel(ctx, d.p.Name, next, apiStream(d.p.Key, d.p.Name)))
	h.settleRecord(r, refused)
	if refused != nil {
		return refused
	}
	return nil
}

type proposalReceipt struct {
	ID         string `json:"id"`
	State      string `json:"state"`
	Connection string `json:"connection"`
}

func receipt(r *record) proposalReceipt {
	return proposalReceipt{ID: r.ID, State: r.State, Connection: r.subject().Connection}
}

func (s *state) draftProposal(st *settings, source string, p facts.Principal, target, reason string, changes []tomledit.Change, others bool) (string, json.RawMessage, error) {
	if current, ok := s.identities.Lookup(p.Key); !ok || !current.Same(p) {
		return "", nil, errNoAgent
	}
	if _, err := config.ProposalChanges(p, changes, others); err != nil {
		return "", nil, err
	}
	candidate, _, _, err := st.Edit(source, changes, s.presetLibrary(s.life, s.sealer))
	if err == nil && candidate == source {
		err = errors.New("proposal does not change policy")
	}
	if err != nil {
		return "", nil, err
	}
	raw, err := json.Marshal(requestFacts{Version: config.FactsVersion, Principal: p, Connection: target,
		Service: "policy-proposal", Title: reason, Parameters: map[string]any{},
		Details: map[string]any{"policy": policyDiff{SourceDiff: sourceDiff(source, candidate)}}})
	return candidate, raw, err
}

func (s held) mayProposeOthers(st *settings, p facts.Principal) bool {
	return st.wouldAllow(p, s.label(p.Name), perimeterCall(config.ProposalsOthers, nil)) != nil
}

func (s *state) proposePolicy(ctx context.Context, fingerprint string, input config.Proposal) ([]proposalReceipt, error) {
	reason := strings.TrimSpace(input.Reason)
	if reason == "" || len(reason) > maxReason {
		return nil, fmt.Errorf("proposal needs a reason of 1-%d bytes", maxReason)
	}
	changes, err := input.Edits()
	if err != nil {
		return nil, err
	}
	if policyFile != "" {
		return nil, errPolicyFile
	}
	return withWriteLock(s, func(base format.Document, before *settings) ([]proposalReceipt, error) {
		p, known := s.identities.Lookup(fingerprint)
		if !known {
			return nil, errNoAgent
		}
		var others bool
		s.locked(func(h held) { others = h.mayProposeOthers(before, p) })
		groups, err := config.ProposalChanges(p, changes, others)
		if err != nil {
			return nil, err
		}
		var proposals []*record
		for _, target := range slices.Sorted(maps.Keys(groups)) {
			candidate, raw, err := s.draftProposal(before, base.Policy, p, target, reason, groups[target], others)
			if err == nil {
				_, err = s.prepareSettings(ctx, s.presetLibrary(ctx, s.sealer), candidate, rebuildAll, nil, before.authority, before.hostKey)
			}
			if err != nil {
				return nil, fmt.Errorf("connection %s: %w", target, err)
			}
			proposals = append(proposals, &record{Changes: groups[target], Facts: raw})
		}

		var receipts []proposalReceipt
		var tooMany error
		s.locked(func(h held) {
			var replaced []*record
			pending := len(proposals)
			for r := range h.records.All() {
				if r.State != statePending || r.Changes == nil {
					continue
				}
				f := r.subject()
				if _, again := groups[f.Connection]; again && f.Principal.Same(p) {
					replaced = append(replaced, r)
				} else {
					pending++
				}
			}
			if pending > maxPolicyProposals {
				tooMany = errors.New("too many pending policy proposals")
				return
			}
			for _, r := range replaced {
				h.outdateRecord(r)
			}
			receipts = make([]proposalReceipt, 0, len(proposals))
			for _, proposal := range proposals {
				h.announce(h.addRecord(proposal))
				receipts = append(receipts, receipt(proposal))
			}
		})
		return receipts, tooMany
	})
}
