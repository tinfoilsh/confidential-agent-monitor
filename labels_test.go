package main

import (
	"context"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tinfoilsh/monitor/connector"
	"gocloud.dev/blob/memblob"
)

func trackedTestStream(t *testing.T, f *messageFixture, name string) *connector.Stream {
	t.Helper()
	server, client := net.Pipe()
	s := connector.NewStream(context.Background())
	s.Conn = server
	t.Cleanup(func() { s.Close(); client.Close() })
	if err := f.m.trackStream(f.principals[name].Key, s); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestConnectorLabelChangeRetiresOtherStreams(t *testing.T) {
	f := newMessageFixture(t, messageLimit{Audience: "me", Trust: "untrusted"})
	if err := f.patch(t, `{"accounts":{"web":{"contents":"team"}}}`); err != nil {
		t.Fatal(err)
	}
	source := trackedTestStream(t, f, "bob")
	old := trackedTestStream(t, f, "bob")
	otherAgent := trackedTestStream(t, f, "alice")
	in := input{stream: source, Principal: f.principals["bob"], Event: &connector.Event{
		HTTP: &connector.HTTPLayer{Method: "GET", Host: "example.com", Path: "/"},
	}}
	if err := f.m.gate(source.Context, in, "web"); err != nil {
		t.Fatal(err)
	}
	if old.Context.Err() == nil {
		t.Fatal("connector read left the agent's previous stream authorized")
	}
	if source.Context.Err() != nil || otherAgent.Context.Err() != nil {
		t.Fatal("label change canceled the observing stream or another agent's stream")
	}
	l := f.disk(t).Labels[f.principals["bob"].Key]
	if l.Audience != "team" || l.Trust != "untrusted" || l.Because["audience"] != "web" || l.Because["trust"] != "web" {
		t.Fatalf("connector read did not persist its label and provenance: %+v", l)
	}
	if err := f.m.gate(old.Context, in, "web"); !errors.Is(err, context.Canceled) {
		t.Fatalf("retired stream was readmitted: %v", err)
	}
	// The observing stream stays registered for a later, more restrictive read.
	expectMessageStatus(t, f.request("bob", "GET", "/messages?from=alice", ""), http.StatusNoContent)
	if source.Context.Err() == nil {
		t.Fatal("the observing stream escaped the next label change")
	}
}

func TestConnectorRetriesFailedLabelPersistence(t *testing.T) {
	f := newMessageFixture(t, messageLimit{Audience: "anyone", Trust: "trusted"})
	working := f.m.store
	failed := memblob.OpenBucket(nil)
	failed.Close()
	f.m.store = failed
	defer func() { f.m.store = working }()
	in := input{Principal: f.principals["bob"], Event: &connector.Event{
		HTTP: &connector.HTTPLayer{Method: "GET", Host: "example.com", Path: "/"},
	}}
	for range 2 {
		if err := f.m.gate(context.Background(), in, "web"); err == nil {
			t.Fatal("connector admitted a read without persisting its restrictive label")
		}
	}
	if f.m.label(in.Principal.Key).Trust != "untrusted" {
		t.Fatal("failed persistence restored trust")
	}
	f.m.store = working
	if err := f.m.gate(context.Background(), in, "web"); err != nil {
		t.Fatal(err)
	}
	if f.disk(t).Labels[in.Principal.Key].Trust != "untrusted" {
		t.Fatal("retry did not persist the label")
	}
}

func TestOwnerLabelChangeRetiresStreams(t *testing.T) {
	f := newMessageFixture(t, messageLimit{Audience: "me", Trust: "untrusted"})
	s := trackedTestStream(t, f, "bob")
	r := httptest.NewRequest("POST", "/labels/bob", strings.NewReader(`{"audience":"me","trust":"untrusted"}`))
	r.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(f.m.owner))
	w := httptest.NewRecorder()
	f.m.handler().ServeHTTP(w, r)
	expectMessageStatus(t, w, http.StatusOK)
	if s.Context.Err() == nil || f.disk(t).Labels[f.principals["bob"].Key].Audience != "me" {
		t.Fatal("owner label change did not retire streams and persist")
	}
}
