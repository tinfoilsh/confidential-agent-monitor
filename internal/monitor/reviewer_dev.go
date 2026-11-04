//go:build monitor_dev

package monitor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"time"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/facts"
)

type developmentRecordFields struct {
	Reviewer string `json:"reviewer,omitempty"`
}

type developmentRecordSummaryFields struct {
	Reviewer string `json:"reviewer,omitempty"`
}

func assignDevelopmentReviewer(st *settings, r *record, identity string) {
	r.Reviewer = st.Identities[identity].Reviewer
}

func copyDevelopmentReviewSummary(r *record, summary *recordSummary) {
	summary.Reviewer = r.Reviewer
}

const answerEscalate = "escalate"

// Leave time for the owner to respond after a failed or slow development review.
const reviewWait = 45 * time.Second

func (m *monitor) startDevelopmentReview(wait context.Context, r *record) {
	if r.Reviewer != "" {
		m.reviewApproval(wait, r)
	}
}

func (m *monitor) answerDevelopmentRequest(id string, input answerInput) error {
	input.Reason = strings.TrimSpace(input.Reason)
	m.mu.Lock()
	defer m.mu.Unlock()
	r, err := m.answerable(id, input, []string{answerOnce, answerDeny, answerEscalate}, true)
	if err != nil {
		return err
	}
	if r.Reviewer != "tinfoil" {
		return errors.New("the request is not assigned to the Tinfoil reviewer")
	}
	r.Reviews = append(r.Reviews, reviewAnswer{By: "tinfoil", answerInput: input, Time: time.Now()})
	if input.Choice == answerEscalate {
		r.Reviewer = ""
		return nil
	}
	r.State = stateApproved
	if input.Choice == answerDeny {
		r.State = stateDenied
	}
	close(r.answered)
	return nil
}

// reviewApproval starts under mu and answers the same pending record;
// unavailable or invalid responses return it to the owner. The connector owns
// the model protocol and prompt.
func (m *monitor) reviewApproval(wait context.Context, r *record) {
	cfg, id := m.settings.Load().Reviewer, r.ID
	c := m.connections[cfg.Connection]
	var release func()
	var setupCtx context.Context
	if c != nil {
		if release, _ = m.acquire(c, c.prepared); release != nil {
			setupCtx = c.setupCtx
		}
	}
	body, _ := json.Marshal(map[string]any{"model": cfg.Model, "instructions": cfg.Instructions, "facts": r.Facts, "requirements": r.Requirements, "sends": r.Sends, "grant": r.Grant})
	go func() {
		ctx, cancel := context.WithTimeout(wait, reviewWait)
		defer cancel()
		var answer answerInput
		if release != nil {
			defer release()
			ctx, cancel := connector.Bind(ctx, setupCtx)
			defer cancel()
			req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://connector/review", bytes.NewReader(body))
			response := httptest.NewRecorder()
			connector.Control(c.Server).ServeHTTP(response, req)
			if response.Code != http.StatusOK || facts.DecodeNumbers(response.Body.Bytes(), &answer) != nil {
				answer = answerInput{}
			}
		}
		if wait.Err() == nil && m.answerDevelopmentRequest(id, answer) != nil {
			_ = m.answerDevelopmentRequest(id, answerInput{Choice: answerEscalate, Reason: "Tinfoil could not complete this review. Please review the request yourself."})
		}
	}()
}
