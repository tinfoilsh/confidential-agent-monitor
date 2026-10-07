package main

import (
	"encoding/json"
	"net/http"
	"slices"
	"testing"

	"github.com/tinfoilsh/monitor/connector"
)

func TestLatticeDefaults(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want latticeOptions
	}{
		{`{}`, latticeOptions{true, false}},
		{`{"lattices":{}}`, latticeOptions{true, false}},
		{`{"lattices":null}`, latticeOptions{true, false}},
		{`{"lattices":{"confidentiality":null,"integrity":null}}`, latticeOptions{true, false}},
		{`{"lattices":{"integrity":true}}`, latticeOptions{true, true}},
		{`{"lattices":{"confidentiality":false}}`, latticeOptions{false, false}},
		{`{"lattices":{"confidentiality":false,"integrity":true}}`, latticeOptions{false, true}},
	} {
		t.Run(tc.raw, func(t *testing.T) {
			cfg, _, err := parse([]byte(tc.raw))
			if err != nil {
				t.Fatal(err)
			}
			if cfg.Lattices != tc.want {
				t.Fatalf("lattices = %+v, want %+v", cfg.Lattices, tc.want)
			}
		})
	}
	for _, raw := range []string{
		`{"lattices":{"integrity":"off"}}`,
		`{"lattices":{"confidentiality":1}}`,
		`{"lattices":{"typo":true}}`,
		`{"data":{"lattices":{}}}`,
	} {
		if _, _, err := parse([]byte(raw)); err == nil {
			t.Fatalf("invalid lattice config accepted: %s", raw)
		}
	}
}

func TestLatticeEnforcement(t *testing.T) {
	for _, tc := range []struct {
		name  string
		patch string
		want  latticeOptions
	}{
		{"defaults", `{"lattices":null}`, latticeOptions{true, false}},
		{"both", `{"lattices":{"confidentiality":true,"integrity":true}}`, latticeOptions{true, true}},
		{"integrity", `{"lattices":{"confidentiality":false,"integrity":true}}`, latticeOptions{false, true}},
		{"neither", `{"lattices":{"confidentiality":false,"integrity":false}}`, latticeOptions{false, false}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := newMessageFixture(t, messageLimit{Audience: "anyone", Trust: "trusted"})
			if err := f.patch(t, tc.patch); err != nil {
				t.Fatal(err)
			}
			st := f.m.live.Load()
			in := input{Account: &namedAccount{"web", st.cfg.Accounts["web"]}, Access: access{Level: "allow"},
				Label: label{Audience: "me", Trust: "untrusted"}, Event: &connector.Event{
					HTTP: &connector.HTTPLayer{Method: "POST", Host: "example.com", Path: "/"},
				}}
			d, err := st.decide(t.Context(), in)
			if err != nil {
				t.Fatal(err)
			}
			if slices.Contains(d.Gaps, "audience") != tc.want.Confidentiality || slices.Contains(d.Gaps, "trust") != tc.want.Integrity || len(d.Deny) != 0 {
				t.Fatalf("wrong lattice enforcement: %+v", d)
			}
			// Independent access controls still apply with either lattice disabled.
			for _, level := range []string{"ask", "off"} {
				in.Access.Level = level
				d, err := st.decide(t.Context(), in)
				if err != nil || level == "ask" && !slices.Contains(d.Gaps, "ask") || level == "off" && len(d.Deny) == 0 {
					t.Fatalf("lost %s access control: %+v, %v", level, d, err)
				}
			}
			for _, sample := range []struct {
				label label
				deny  bool
			}{
				{label{Audience: "me", Trust: "trusted"}, tc.want.Confidentiality},
				{label{Audience: "anyone", Trust: "untrusted"}, tc.want.Integrity},
			} {
				f.m.doc.Labels[f.principals["alice"].Key] = sample.label
				want := http.StatusCreated
				if sample.deny {
					want = http.StatusForbidden
				}
				expectMessageStatus(t, f.request("alice", "POST", "/messages", `{"to":"bob","body":"test"}`), want)
			}
		})
	}
}

func TestLatticeSwitchPreservesHistoryAndRetiresStreams(t *testing.T) {
	f := newMessageFixture(t, messageLimit{Audience: "anyone", Trust: "trusted"})
	if err := f.patch(t, `{"lattices":null}`); err != nil {
		t.Fatal(err)
	}
	source, other := trackedTestStream(t, f, "bob"), trackedTestStream(t, f, "bob")
	in := input{stream: source, Principal: f.principals["bob"], Event: &connector.Event{
		HTTP: &connector.HTTPLayer{Method: "GET", Host: "example.com", Path: "/"},
	}}
	if err := f.m.gate(t.Context(), in, "web"); err != nil {
		t.Fatal(err)
	}
	if source.Context.Err() != nil || other.Context.Err() != nil {
		t.Fatal("a disabled integrity lattice retired a stream")
	}
	if f.disk(t).Labels[in.Principal.Key].Trust != "untrusted" {
		t.Fatal("disabled integrity lost label history")
	}
	in.HTTP.Method = "POST"
	if err := f.m.gate(t.Context(), in, "web"); err != nil {
		t.Fatal(err)
	}
	if err := f.patch(t, `{"lattices":{"integrity":true}}`); err != nil {
		t.Fatal(err)
	}
	if source.Context.Err() == nil || other.Context.Err() == nil {
		t.Fatal("enabling integrity retained an old authorization")
	}
	doc := f.disk(t)
	st, err := f.m.build(t.Context(), doc, f.m.live.Load().Env, nil)
	if err != nil {
		t.Fatal(err)
	}
	if st.cfg.Lattices != (latticeOptions{true, true}) {
		t.Fatalf("restart lost lattice settings: %+v", st.cfg.Lattices)
	}
	in.Label, in.Account, in.Access = doc.Labels[in.Principal.Key], &namedAccount{"web", st.cfg.Accounts["web"]}, access{Level: "allow"}
	d, err := st.decide(t.Context(), in)
	if err != nil || !slices.Contains(d.Gaps, "trust") {
		t.Fatalf("reenabling integrity ignored history: %+v, %v", d, err)
	}
}

func TestDisabledLatticesPreserveMessageHistory(t *testing.T) {
	f := newMessageFixture(t, messageLimit{Audience: "anyone", Trust: "trusted"})
	if err := f.patch(t, `{"lattices":{"confidentiality":false,"integrity":false}}`); err != nil {
		t.Fatal(err)
	}
	f.m.doc.Labels[f.principals["alice"].Key] = label{Audience: "me", Trust: "untrusted"}
	id := f.send(t, "alice", "bob", `"private untrusted data"`)
	if err := f.patch(t, `{"lattices":{"confidentiality":true,"integrity":true}}`); err != nil {
		t.Fatal(err)
	}
	w := f.request("bob", "GET", "/messages?from=alice", "")
	expectMessageStatus(t, w, http.StatusOK)
	var msg agentMessage
	if err := json.Unmarshal(w.Body.Bytes(), &msg); err != nil {
		t.Fatal(err)
	}
	l := f.m.label(f.principals["bob"].Key)
	if l.Audience != "me" || l.Trust != "untrusted" || msg.Label.Audience != "me" || msg.Label.Trust != "untrusted" {
		t.Fatalf("disabled lattice laundered a message: label=%+v, message=%+v", l, msg)
	}
	expectMessageStatus(t, f.request("bob", "POST", "/messages", `{"to":"carol","body":"forward"}`), http.StatusForbidden)
	if err := f.patch(t, `{"lattices":{"confidentiality":false,"integrity":false}}`); err != nil {
		t.Fatal(err)
	}
	expectMessageStatus(t, f.request("bob", "DELETE", "/messages/"+id+"?from=alice", ""), http.StatusNoContent)
	// An empty queue still reveals whether a restricted sender has written to it.
	f.m.doc.Labels[f.principals["bob"].Key] = cleanLabel
	expectMessageStatus(t, f.request("bob", "GET", "/messages?from=alice", ""), http.StatusNoContent)
	l = f.disk(t).Labels[f.principals["bob"].Key]
	if l.Audience != "me" || l.Trust != "untrusted" {
		t.Fatalf("draining the queue erased its history: %+v", l)
	}
}
