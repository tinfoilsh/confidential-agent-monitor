package main

import (
	"encoding/json"
	"errors"
	"maps"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/facts"
)

type approvalRequest struct{ facts.Facts }

func (r approvalRequest) Describe(connector.Context) (facts.Facts, error) {
	return r.Facts, nil
}

func approvalInput() fixtureInput {
	return fixtureInput{
		Account: fixtureAccount(namedAccount{Name: "payments", account: account{Contents: "anyone", Sends: "me"}}),
		Access:  access{Level: "allow"}, Label: facts.Label{Audience: "anyone", Trust: "trusted"},
		Request: approvalRequest{facts.Facts{
			Operation:  &facts.Operation{ID: "transfer", Action: "transfer", Effects: []string{"write"}},
			Parameters: map[string]any{"amount": 501},
		}},
	}
}

func approvalProgram(t *testing.T, source string) *state {
	t.Helper()
	q, err := compileTestPolicy(t.Context(), &config{Lattices: latticeOptions{true, true},
		Policies: map[string]string{"approval.rego": "package sentinel\n" + source}})
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func approvalDecision(t *testing.T, q *state, in fixtureInput) *decision {
	t.Helper()
	d, err := q.decideFixture(t.Context(), in)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range d.Requirements {
		if r.ID == "" || strings.TrimSpace(r.Message) == "" {
			t.Fatalf("invalid requirement: %+v", r)
		}
	}
	return d
}

func approvalWaiver(d *decision) rule {
	return rule{Account: d.Facts.Account, Action: d.Facts.Operation.Action, Operation: d.operationID(),
		Definition: d.Definition, Scope: d.Grant, Requirements: slices.Clone(d.Requirements)}
}

func TestOwnerApprovalThresholdAndWaiverBinding(t *testing.T) {
	q := approvalProgram(t, `approvals contains {"id": "owner.payment_limit", "message": "Payments above $500 need approval."} if {
		input.facts.parameters.amount > 500
	}`)
	in := approvalInput()
	d := approvalDecision(t, q, in)
	if len(d.Deny) != 0 || !reflect.DeepEqual(d.Requirements, requirements{{"owner.payment_limit", "Payments above $500 need approval."}}) {
		t.Fatalf("custom requirement was not returned: %+v", d)
	}
	raw, err := json.Marshal(d)
	if err != nil || !strings.Contains(string(raw), `"requirements":[{"id":"owner.payment_limit","message":`) {
		t.Fatalf("audit response lost the explanation: %s, %v", raw, err)
	}
	for _, field := range []string{"none", "account", "action", "operation", "definition", "scope", "requirement ID", "messages"} {
		t.Run(field, func(t *testing.T) {
			r := approvalWaiver(d)
			switch field {
			case "account":
				r.Account = "other"
			case "action":
				r.Action = "other"
			case "operation":
				r.Operation = "other"
			case "definition":
				r.Definition = "other"
			case "scope":
				r.Scope = map[string]any{"amount": 999}
			case "requirement ID":
				r.Requirements[0].ID = "owner.other"
			case "messages":
				r.Requirements[0].Message = "Display text cannot select a waiver."
			}
			in.Rules = map[string]rule{"0": r}
			got := approvalDecision(t, q, in)
			waived := field == "none" || field == "messages" || field == "action" || field == "operation"
			if len(got.Deny) != 0 || (len(got.Requirements.IDs()) == 0) != waived {
				t.Fatalf("incorrect waiver binding for %s: %+v", field, got)
			}
		})
	}
	in = approvalInput()
	in.Request.(approvalRequest).Parameters["amount"] = 500
	if got := approvalDecision(t, q, in); len(got.Requirements.IDs()) != 0 || len(got.Deny) != 0 {
		t.Fatalf("nonmatching requirement changed authorization: %+v", got)
	}
}

func TestOwnerApprovalPreservesOtherRequirementsAndDenials(t *testing.T) {
	q := approvalProgram(t, `approvals contains {"id": "owner.review", "message": "Review this transfer."}
		deny contains "owner denial" if input.facts.parameters.blocked`)
	in := approvalInput()
	in.Access.Level = "ask"
	in.Label = facts.Label{Audience: "me", Trust: "untrusted", Because: map[string]string{"audience": "payroll", "trust": "web"}}
	in.Account.Sends = "anyone"
	d := approvalDecision(t, q, in)
	if !slices.Equal(d.Requirements.IDs(), []string{"ask", "audience", "owner.review", "trust"}) || len(d.Deny) != 0 {
		t.Fatalf("custom approval replaced built-in requirements: %+v", d)
	}
	if !strings.Contains(d.Requirements[1].Message, "payroll") || !strings.Contains(d.Requirements[3].Message, "web") {
		t.Fatalf("built-in reasons lost their provenance: %+v", d.Requirements)
	}
	r := approvalWaiver(d)
	r.Requirements = requirements{d.Requirements[0], d.Requirements[2]}
	in.Rules = map[string]rule{"0": r}
	if got := approvalDecision(t, q, in); !slices.Equal(got.Requirements.IDs(), []string{"audience", "trust"}) {
		t.Fatalf("partial waiver removed another requirement: %+v", got)
	}
	in.Rules = map[string]rule{"0": approvalWaiver(d)}
	in.Access.Level = "off"
	if got := approvalDecision(t, q, in); len(got.Deny) == 0 {
		t.Fatal("saved approval bypassed disabled access")
	}
	in.Access.Level = "allow"
	in.Request.(approvalRequest).Parameters["blocked"] = true
	if got := approvalDecision(t, q, in); !slices.Contains(got.Deny, "owner denial") {
		t.Fatal("saved approval bypassed owner denial")
	}
}

func TestOwnerApprovalOutputValidation(t *testing.T) {
	valid := map[string]any{"id": "owner.review", "message": "Review it."}
	for _, value := range []any{
		nil, true, "review", valid, []any{nil}, []any{"review"},
		[]any{map[string]any{"id": "ask", "message": "Override a built-in."}},
		[]any{map[string]any{"id": "owner.", "message": "Missing name."}},
		[]any{map[string]any{"id": "owner.bad id", "message": "Invalid ID."}},
		[]any{map[string]any{"id": 1, "message": "Invalid ID."}},
		[]any{map[string]any{"id": "owner.review"}},
		[]any{map[string]any{"id": "owner.review", "message": 1}},
		[]any{map[string]any{"id": "owner.review", "message": " \n\t"}},
		[]any{map[string]any{"id": "owner.review", "message": "Review.", "waives": []string{"trust"}}},
		[]any{valid, map[string]any{"id": "owner.review", "message": "Different meaning."}},
	} {
		raw, _ := json.Marshal(value)
		t.Run(string(raw), func(t *testing.T) {
			q, err := compileTestPolicy(t.Context(), &config{Data: map[string]any{"sentinel": map[string]any{"approvals": value}}})
			if err != nil {
				t.Fatal(err)
			}
			d, err := q.decideFixture(t.Context(), approvalInput())
			if err == nil && len(d.Deny) == 0 {
				t.Fatalf("malformed requirement was accepted: %+v", d)
			}
		})
	}
	for _, source := range []string{
		`approvals := []`,
		`approvals := [{"id": "owner.review", "message": "Review."}, {"id": "owner.review", "message": "Review."}]`,
		`approvals contains {"id": "owner.review", "message": "Review."}`,
	} {
		d := approvalDecision(t, approvalProgram(t, source), approvalInput())
		if len(d.Deny) != 0 || len(d.Requirements.IDs()) > 1 {
			t.Fatalf("valid collection was rejected: %+v", d)
		}
	}
	q := approvalProgram(t, `approvals contains {"id": "owner.review", "message": "Review."} if to_number(input.facts.parameters.bad) > 0`)
	in := approvalInput()
	in.Request.(approvalRequest).Parameters["bad"] = "not a number"
	if _, err := q.decideFixture(t.Context(), in); err == nil {
		t.Fatal("approval evaluation error was ignored")
	}
}

func TestOwnerApprovalGapDependencies(t *testing.T) {
	q := approvalProgram(t, `approvals contains {"id": "owner.review", "message": "Review this disclosure."} if "audience" in data.monitor.base_gaps
		deny contains "review prohibited" if "owner.review" in data.monitor.gaps`)
	in := approvalInput()
	in.Label.Audience, in.Account.Sends = "me", "anyone"
	d := approvalDecision(t, q, in)
	if !slices.Equal(d.Requirements.IDs(), []string{"audience", "owner.review"}) || !slices.Contains(d.Deny, "review prohibited") {
		t.Fatalf("gap dependencies were not evaluated: %+v", d)
	}
	_, err := compileTestPolicy(t.Context(), &config{Policies: map[string]string{"cycle.rego": `package sentinel
		approvals contains {"id": "owner.review", "message": "Review."} if "ask" in data.monitor.gaps`}})
	if err == nil || !strings.Contains(err.Error(), "recursion") {
		t.Fatalf("recursive requirement was accepted: %v", err)
	}
}

func TestOwnerApprovalRecheck(t *testing.T) {
	q := approvalProgram(t, `approvals contains {"id": "owner.review", "message": object.get(object.get(input.facts.context.label, "because", {}), "audience", "Initial review.")}
		approvals contains {"id": "owner.private", "message": "Review private data."} if input.facts.context.label.audience == "me"`)
	in := approvalInput()
	p := principal{Key: "key", Name: "agent", identity: identity{Accounts: map[string]access{"payments": in.Access}}}
	in.Principal = p
	cfg := &config{Accounts: map[string]account{"payments": in.Account.account}}
	m := &monitor{streams: map[*connector.Stream]string{}, running: map[string]*connection{}, doc: sealed{Labels: map[string]facts.Label{}}}
	m.live.Store(&state{cfg: fixtureConfig(cfg), connections: map[string]*connection{"payments": {name: "payments", account: "payments"}}, query: q.query, program: q.program, principals: map[string]principal{p.Key: p}})
	d, err := m.refreshAndEvaluate(t.Context(), &in, "payments")
	if err != nil {
		t.Fatal(err)
	}
	r := &record{State: stateApproved, decision: d}
	if _, err := m.recheckFixture(t.Context(), r, &in, "payments"); err != nil {
		t.Fatalf("unchanged request did not resume: %v", err)
	}
	m.doc.Labels[p.Key] = facts.Label{Audience: "anyone", Trust: "trusted", Because: map[string]string{"audience": "Updated explanation."}}
	got, err := m.recheckFixture(t.Context(), r, &in, "payments")
	if err != nil || got.Requirements[0].Message != "Updated explanation." {
		t.Fatalf("message changed authority: %+v, %v", got, err)
	}
	m.doc.Labels[p.Key] = facts.Label{Audience: "me", Trust: "trusted"}
	if _, err := m.recheckFixture(t.Context(), r, &in, "payments"); !errors.Is(err, errChanged) {
		t.Fatalf("new requirement resumed under an earlier approval: %v", err)
	}
}

func TestOwnerApprovalAdmission(t *testing.T) {
	q := approvalProgram(t, `approvals contains {"id": "owner.review", "message": "Owner review required."}`)
	in := approvalInput()
	f := in.Request.(approvalRequest)
	f.Kind = facts.KindAdmission
	in.Request = f
	d := approvalDecision(t, q, in)
	if !slices.Equal(d.Requirements.IDs(), []string{"owner.review"}) || len(d.Deny) != 0 || d.Next.Audience != in.Label.Audience {
		t.Fatalf("admission did not require approval: %+v", d)
	}

}

func TestOwnerApprovalSavedReasonSnapshot(t *testing.T) {
	f := newMonitorFixture(t)
	source := "package sentinel\napprovals contains {\"id\": \"owner.review\", \"message\": \"Review this request.\"}"
	raw, _ := json.Marshal(map[string]any{"policies": map[string]string{"review.rego": source}})
	if err := f.patch(t, string(raw)); err != nil {
		t.Fatal(err)
	}
	in := approvalInput()
	in.Principal, in.Account = f.principals["bob"], fixtureAccount(namedAccount{Name: "web", account: f.m.live.Load().cfg.Accounts["web"]})
	d := approvalDecision(t, f.m.live.Load(), in)
	err := f.m.saveApproval(t.Context(), &record{ID: "saved", decision: d})
	if err != nil {
		t.Fatal(err)
	}
	rules := f.m.live.Load().cfg.Identities["bob"].Rules
	if len(rules) != 1 || !reflect.DeepEqual(rules["saved"].Requirements, d.Requirements) {
		t.Fatalf("saved rule lost its explanation or IDs: %+v", rules)
	}
	in.Rules = rules
	if got := approvalDecision(t, f.m.live.Load(), in); len(got.Requirements.IDs()) != 0 || len(got.Deny) != 0 {
		t.Fatalf("persisted approval did not waive the requirement: %+v", got)
	}
	changed := *f.m.live.Load().cfg
	changed.Policies = maps.Clone(changed.Policies)
	changed.Policies["review.rego"] = strings.ReplaceAll(source, "Review this request.", "New policy explanation.")
	q, err := compileTestPolicy(t.Context(), &changed)
	if err != nil {
		t.Fatal(err)
	}
	if got := approvalDecision(t, q, in); len(got.Requirements.IDs()) == 0 || got.Definition == d.Definition {
		t.Fatal("policy edit retained an old approval")
	}
}

func TestDisabledNamedApprovalDoesNotWaiveRequirements(t *testing.T) {
	_, q := policyFixture(t, "")
	in := factInput(facts.Facts{Operation: &facts.Operation{Action: "write", Effects: []string{"write"}}})
	in.Access.Level = "ask"
	d := approvalDecision(t, q, in)
	waiver := approvalWaiver(d)
	disabled := false
	waiver.Enabled = &disabled
	in.Rules = map[string]rule{"disabled": waiver}
	if got := approvalDecision(t, q, in); len(got.Requirements) == 0 {
		t.Fatal("disabled named rule waived approval")
	}
}
