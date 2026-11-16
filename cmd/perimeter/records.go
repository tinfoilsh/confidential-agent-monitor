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
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/config"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/format"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

const (
	maxReason       = 4096
	maxSummaryTitle = 512
	auditPrefix     = "audit/"
	adminService    = "admin"
)

var (
	errRecordGone = httpError{errors.New("this request is no longer in the activity log"), http.StatusNotFound}
	errNoAgent    = httpError{errRemoved, http.StatusForbidden}
)

type savedAnswer struct {
	record *record
	answer Review
}

type recordSummary struct {
	ID      string    `json:"id"`
	State   string    `json:"state"`
	Invalid bool      `json:"invalid,omitempty"`
	Time    time.Time `json:"time"`
	Expires time.Time `json:"expires,omitzero"`
	Summary bool      `json:"summary"`
	Reviews []Review  `json:"reviews,omitempty"`
	Segment string    `json:"segment,omitempty"`
	Facts   struct {
		Principal  facts.Principal `json:"principal"`
		Connection string          `json:"connection"`
		Service    string          `json:"service"`
		Operation  *operation      `json:"operation"`
		Title      string          `json:"title"`
	} `json:"facts"`
}

func summarize(r *record) recordSummary {
	v := recordSummary{ID: r.ID, State: r.State, Invalid: r.Invalid, Time: r.Time, Expires: r.Expires, Summary: true}
	for _, review := range r.Reviews {
		review.Reason = ""
		v.Reviews = append(v.Reviews, review)
	}
	_ = json.Unmarshal(r.Facts, &v.Facts)
	if len(v.Facts.Title) > maxSummaryTitle {
		v.Facts.Title = strings.ToValidUTF8(v.Facts.Title[:maxSummaryTitle], "") + "…"
	}
	return v
}

func (s *state) addRecord(r *record) *record {
	r.ID, r.Time, r.State = rand.Text(), time.Now(), stateAllowed
	s.records.Add(r)
	return r
}

func (s *state) findRecord(id string) *record {
	r, _ := s.records.Find(func(r *record) bool { return r.ID == id })
	return r
}

func (s *state) announce(r *record) {
	events.Info("record", "record", summarize(r), "generation", s.doc.Generation)
}

func (s *state) settleRecord(r *record, err error) {
	r.settle(err)
	if line, err := json.Marshal(r); err != nil {
		log.Printf("audit record %s: %v", r.ID, err)
	} else {
		s.audit.Append(line)
	}
	s.announce(r)
}

func (s *state) outdateRecord(r *record) {
	r.State = stateOutdated
	s.settleRecord(r, nil)
}

func (s *state) recordAdmin(ctx context.Context, title string, details any, err error) {
	c, _ := callerFrom(ctx)
	raw, encodeErr := json.Marshal(requestFacts{Version: config.FactsVersion, Principal: facts.Principal{Name: c.Name}, Service: adminService,
		Title: title, Parameters: map[string]any{}, Details: details})
	if encodeErr != nil {
		log.Printf("audit admin action %s: %v", title, encodeErr)
		return
	}
	s.settleRecord(s.addRecord(&record{Facts: raw}), err)
}

func (s *state) ruleChange(r *record) (format.Change, error) {
	f := summarize(r).Facts
	if f.Operation == nil || f.Operation.ID == "" {
		return format.Change{}, errors.New("a request without a known operation cannot be saved")
	}
	p, exists := s.identities.Lookup(f.Principal.Key)
	if !exists || p.Name != f.Principal.Name {
		return format.Change{}, errors.New("the requesting identity was revoked or replaced")
	}
	if _, declared := s.settings.Load().Identities[p.Name]; !declared {
		return format.Change{}, errors.New("an approval for a certified identity cannot be saved as a rule")
	}
	return format.Change{Path: []string{"identities", p.Name, "rules", r.ID}, Value: config.Rule{Version: config.FactsVersion, Connection: f.Connection, Action: f.Operation.Action, Operation: f.Operation.ID,
		Scope: r.Grant, Requirements: slices.Clone(r.Requirements)}}, nil
}

func (s *state) answerable(id string, input Answer, revision uint64) (*record, error) {
	if revision != s.doc.Revision {
		return nil, errPolicyConflict
	}
	choices := []string{answerOnce, answerSave, answerDeny}
	if !slices.Contains(choices, input.Choice) {
		return nil, fmt.Errorf("decision must be one of %s", strings.Join(choices, ", "))
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
	return r, nil
}

func (s *state) answer(r *record, review Review) {
	review.Time = time.Now()
	r.Reviews = append(r.Reviews, review)
	r.State = stateApproved
	if review.Choice == answerDeny {
		r.State = stateDenied
	}
	s.records.Notify()
}

func (s *state) saved(r *record, review Review) {
	if r.State == statePending {
		r.State = stateApproved
	} else {
		r.State, r.Deny = stateRefused, []string{errRuleSaved.Error()}
	}
	review.Time = time.Now()
	r.Reviews = append(r.Reviews, review)
}

func (s *state) answerRequest(ctx context.Context, id string, input Answer, revision uint64) error {
	input.Reason = strings.TrimSpace(input.Reason)
	c, _ := callerFrom(ctx)
	var applies bool
	var refusal error
	s.locked(func() {
		r := s.findRecord(id)
		applies = input.Choice == answerSave || input.Choice == answerOnce && r != nil && r.Changes != nil
		if r != nil {
			refusal = s.admitCall(ctx, s.settings.Load(), adminCall{Answer: input, Record: r})
		}
	})
	if refusal != nil {
		return refusal
	}
	review := Review{By: c.Name, Answer: input}
	if applies {
		saved := &savedAnswer{answer: review}
		err := s.writeSettings(ctx, settingsWrite{derive: func() ([]format.Change, error) {
			r, err := s.answerable(id, input, revision)
			if err != nil {
				return nil, err
			}
			saved.record = r
			if input.Choice != answerSave {
				return r.Changes, nil
			}
			change, err := s.ruleChange(r)
			return []format.Change{change}, err
		}, check: func() error {
			current, err := s.answerable(id, input, revision)
			if err == nil && current != saved.record {
				return errRecordGone
			}
			return err
		}, saved: saved})
		if err == nil && saved.record.Changes != nil {
			s.locked(func() { s.settleRecord(saved.record, nil) })
		}
		return err
	}
	var err error
	s.locked(func() {
		var r *record
		if r, err = s.answerable(id, input, revision); err != nil {
			return
		}
		s.answer(r, review)
		if r.Changes != nil {
			s.settleRecord(r, nil)
		}
	})
	return err
}

type auditPage struct {
	Records []recordSummary `json:"records"`
	Next    string          `json:"next,omitempty"`
}

func (s *state) readAuditPage(ctx context.Context, before string) (auditPage, error) {
	live := map[string]bool{}
	s.locked(func() {
		for r := range s.records.All() {
			live[r.ID] = true
		}
	})
	page := auditPage{Records: []recordSummary{}}
	var err, malformed error
	page.Next, err = s.audit.Page(ctx, before, func(segment string, line []byte) bool {
		r, err := decodeRecord(line)
		malformed = cmp.Or(malformed, err)
		if err != nil || live[r.ID] {
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
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.UseNumber()
	r := new(record)
	return r, decoder.Decode(r)
}
