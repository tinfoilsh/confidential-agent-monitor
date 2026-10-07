package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tinfoilsh/monitor/connector"
	"gocloud.dev/blob"
	"gocloud.dev/blob/driver"
	"gocloud.dev/blob/memblob"
	"golang.org/x/crypto/ssh"
)

type messageFixture struct {
	m          *monitor
	keys       map[string]ssh.Signer
	principals map[string]principal
}

func newMessageFixture(t *testing.T, limit messageLimit) *messageFixture {
	t.Helper()
	f := &messageFixture{keys: map[string]ssh.Signer{}, principals: map[string]principal{}}
	ids := map[string]identity{}
	for _, name := range []string{"alice", "bob", "carol"} {
		_, key, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := ssh.NewSignerFromKey(key)
		if err != nil {
			t.Fatal(err)
		}
		f.keys[name] = signer
		ids[name] = identity{Key: string(ssh.MarshalAuthorizedKey(signer.PublicKey())),
			Accounts: map[string]access{"web": {Level: "allow"}},
			Messages: &messageAccess{Send: []string{}, Receive: map[string]messageLimit{}}}
	}
	ids["alice"].Messages.Send = []string{"bob"}
	ids["bob"].Messages.Receive["alice"] = limit
	ids["bob"].Messages.Send = []string{"carol"}
	ids["carol"].Messages.Receive["bob"] = limit
	cfg := config{Lattices: latticeOptions{Confidentiality: true, Integrity: true}, Identities: ids, Accounts: map[string]account{"web": {
		Preset: "web", Contents: "anyone", Strangers: true, Sends: "anyone",
	}}}
	raw, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	f.m = &monitor{store: memblob.OpenBucket(nil), object: "monitor.enc", owner: make([]byte, ownerKeyBytes),
		doc: sealed{Config: raw, Labels: map[string]label{}}}
	rand.Read(f.m.owner)
	var env connector.Env
	if env.HostKey, err = loadHostKey(&f.m.doc.Keys); err != nil {
		t.Fatal(err)
	}
	if env.TLS, err = loadCA(&f.m.doc.Keys); err != nil {
		t.Fatal(err)
	}
	st, err := f.m.build(context.Background(), f.m.doc, env, nil)
	if err != nil {
		t.Fatal(err)
	}
	f.m.live.Store(st)
	for _, p := range st.principals {
		f.principals[p.Name] = p
	}
	if err := f.m.persist(context.Background(), f.m.doc, f.m.owner); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.m.store.Close() })
	return f
}

func (f *messageFixture) request(name, method, path, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	w := httptest.NewRecorder()
	f.m.messageHandler(f.principals[name].Key).ServeHTTP(w, r)
	return w
}

func expectMessageStatus(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("HTTP %d, want %d: %s", w.Code, want, w.Body.String())
	}
}

func (f *messageFixture) send(t *testing.T, from, to, body string) string {
	t.Helper()
	w := f.request(from, "POST", "/messages", fmt.Sprintf(`{"to":%q,"body":%s}`, to, body))
	expectMessageStatus(t, w, http.StatusCreated)
	var result struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil || result.ID == "" {
		t.Fatalf("send result: %s", w.Body.String())
	}
	return result.ID
}

func (f *messageFixture) patch(t *testing.T, patch string) error {
	t.Helper()
	f.m.flow.Lock()
	defer f.m.flow.Unlock()
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	_, err := f.m.patch(context.Background(), []byte(patch))
	return err
}

func (f *messageFixture) disk(t *testing.T) sealed {
	t.Helper()
	raw, err := f.m.store.ReadAll(context.Background(), f.m.object)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := newAEAD(f.m.owner)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := aead.Open(nil, nil, raw, nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc sealed
	if err := json.Unmarshal(plain, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

func TestMessagesPropagateAndPersist(t *testing.T) {
	f := newMessageFixture(t, messageLimit{Audience: "me", Trust: "untrusted"})
	f.m.doc.Labels[f.principals["alice"].Key] = label{Audience: "me", Trust: "untrusted", Because: map[string]string{"trust": "web"}}
	id := f.send(t, "alice", "bob", `{"secret":"original"}`)
	// Changing the sender afterward cannot clean an already queued message.
	f.m.doc.Labels[f.principals["alice"].Key] = cleanLabel
	w := f.request("bob", "GET", "/messages?from=alice", "")
	expectMessageStatus(t, w, http.StatusOK)
	var msg agentMessage
	if err := json.Unmarshal(w.Body.Bytes(), &msg); err != nil {
		t.Fatal(err)
	}
	if msg.ID != id || msg.FromKey != f.principals["alice"].Key || msg.Label.Trust != "untrusted" || msg.Label.Audience != "me" {
		t.Fatalf("lost sender provenance: %+v", msg)
	}
	if !strings.Contains(f.m.label(f.principals["bob"].Key).Because["trust"], id) {
		t.Fatal("missing message provenance")
	}
	f.send(t, "bob", "carol", `"forwarded summary"`)
	w = f.request("carol", "GET", "/messages?from=bob", "")
	expectMessageStatus(t, w, http.StatusOK)
	for _, name := range []string{"bob", "carol"} {
		l := f.m.label(f.principals[name].Key)
		if l.Audience != "me" || l.Trust != "untrusted" {
			t.Fatalf("%s escaped the label: %+v", name, l)
		}
	}
	// Both confidentiality and integrity now reach the existing connector policy.
	f.m.flow.Lock()
	in := input{Principal: f.principals["carol"], Event: &connector.Event{HTTP: &connector.HTTPLayer{Method: "POST", Host: "example.com", Path: "/"}}}
	d, err := f.m.evaluate(context.Background(), &in, "web")
	f.m.flow.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(d.Gaps, "audience") || !slices.Contains(d.Gaps, "trust") {
		t.Fatalf("connector ignored message label: %+v", d)
	}
	// Reload the encrypted document and rebuild the policy, as on restart.
	doc := f.disk(t)
	restarted := &monitor{doc: doc, owner: f.m.owner, store: f.m.store, object: f.m.object}
	st, err := restarted.build(context.Background(), doc, f.m.live.Load().Env, nil)
	if err != nil {
		t.Fatal(err)
	}
	restarted.live.Store(st)
	f.m = restarted
	w = f.request("bob", "GET", "/messages?from=alice", "")
	expectMessageStatus(t, w, http.StatusOK)
	if !strings.Contains(w.Body.String(), id) {
		t.Fatal("restart lost unacknowledged message")
	}
	for range 2 {
		expectMessageStatus(t, f.request("bob", "DELETE", "/messages/"+id+"?from=alice", ""), http.StatusNoContent)
	}
	expectMessageStatus(t, f.request("bob", "GET", "/messages?from=alice", ""), http.StatusNoContent)
}

func TestMessagesEmptyReadAndSendStatusAcquireChannelLabel(t *testing.T) {
	f := newMessageFixture(t, messageLimit{Audience: "team", Trust: "untrusted"})
	expectMessageStatus(t, f.request("bob", "GET", "/messages?from=alice", ""), http.StatusNoContent)
	l := f.disk(t).Labels[f.principals["bob"].Key]
	if l.Audience != "team" || l.Trust != "untrusted" {
		t.Fatalf("empty poll leaked without labeling: %+v", l)
	}
	f.send(t, "alice", "bob", `"hello"`)
	l = f.disk(t).Labels[f.principals["alice"].Key]
	if l.Audience != "team" || l.Trust != "untrusted" {
		t.Fatalf("send status leaked without labeling: %+v", l)
	}
	var msg agentMessage
	w := f.request("bob", "GET", "/messages?from=alice", "")
	expectMessageStatus(t, w, http.StatusOK)
	if err := json.Unmarshal(w.Body.Bytes(), &msg); err != nil {
		t.Fatal(err)
	}
	if msg.Label.Audience != l.Audience || msg.Label.Trust != l.Trust {
		t.Fatal("envelope does not carry the sender's label at enqueue time")
	}
}

type checkedMessageResponse struct {
	*httptest.ResponseRecorder
	beforeHeader func()
}

func (w *checkedMessageResponse) WriteHeader(status int) {
	w.beforeHeader()
	w.ResponseRecorder.WriteHeader(status)
}

func TestMessageLabelPersistedBeforeResponse(t *testing.T) {
	f := newMessageFixture(t, messageLimit{Audience: "me", Trust: "untrusted"})
	f.send(t, "alice", "bob", `"persist before releasing"`)
	checked := false
	w := &checkedMessageResponse{ResponseRecorder: httptest.NewRecorder(), beforeHeader: func() {
		checked = true
		l := f.disk(t).Labels[f.principals["bob"].Key]
		if l.Audience != "me" || l.Trust != "untrusted" {
			t.Fatalf("response started before label persistence: %+v", l)
		}
	}}
	f.m.messageHandler(f.principals["bob"].Key).ServeHTTP(w, httptest.NewRequest("GET", "/messages?from=alice", nil))
	expectMessageStatus(t, w.ResponseRecorder, http.StatusOK)
	if !checked || !strings.Contains(w.Body.String(), "persist before releasing") {
		t.Fatal("response did not pass the persistence check")
	}
}

func TestMessageKeyRotationInvalidatesOldMailboxAndStreams(t *testing.T) {
	f := newMessageFixture(t, messageLimit{Audience: "me", Trust: "untrusted"})
	f.send(t, "alice", "bob", `"old key only"`)
	server, client := net.Pipe()
	defer client.Close()
	s := connector.NewStream(context.Background())
	s.Conn = server
	defer s.Close()
	if err := f.m.trackStream(f.principals["bob"].Key, s); err != nil {
		t.Fatal(err)
	}
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	newKey, err := ssh.NewSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	patch, _ := json.Marshal(map[string]any{"identities": map[string]any{"bob": map[string]string{"key": string(ssh.MarshalAuthorizedKey(newKey.PublicKey()))}}})
	if err := f.patch(t, string(patch)); err != nil {
		t.Fatal(err)
	}
	if s.Context.Err() == nil || len(f.disk(t).Mailboxes) != 0 {
		t.Fatal("key rotation retained an old stream or mailbox")
	}
	expectMessageStatus(t, f.request("bob", "GET", "/messages?from=alice", ""), http.StatusForbidden)
	f.principals["bob"], _ = f.m.live.Load().namedPrincipal("bob")
	expectMessageStatus(t, f.request("bob", "GET", "/messages?from=alice", ""), http.StatusNoContent)
}

func TestMessagesRejectSpoofingAndUnauthorizedPeers(t *testing.T) {
	f := newMessageFixture(t, messageLimit{Audience: "anyone", Trust: "trusted"})
	for _, body := range []string{
		`{"to":"bob","body":"x","from":"carol"}`,
		`{"to":"bob","body":"x","label":{"audience":"anyone","trust":"trusted"}}`,
		`{"to":"bob","body":"x"} {"body":"y"}`,
		`{"to":"bob","to":"carol","body":"x"}`,
		`{"to":"bob"}`,
	} {
		expectMessageStatus(t, f.request("alice", "POST", "/messages", body), http.StatusBadRequest)
	}
	for _, req := range []struct{ who, method, path, body string }{
		{"alice", "POST", "/messages", `{"to":"carol","body":"x"}`},
		{"alice", "POST", "/messages", `{"to":"missing","body":"x"}`},
		{"carol", "GET", "/messages?from=alice", ""},
		{"alice", "GET", "/messages?from=alice", ""},
	} {
		expectMessageStatus(t, f.request(req.who, req.method, req.path, req.body), http.StatusForbidden)
	}
	for _, l := range []label{{Audience: "me", Trust: "trusted"}, {Audience: "anyone", Trust: "untrusted"}} {
		f.m.doc.Labels[f.principals["alice"].Key] = l
		expectMessageStatus(t, f.request("alice", "POST", "/messages", `{"to":"bob","body":"x"}`), http.StatusForbidden)
	}
	if len(f.m.doc.Mailboxes) != 0 {
		t.Fatal("a refused send changed a queue")
	}
}

func TestMessagesRevocationAndLabelChangesDiscardOnlyAffectedQueue(t *testing.T) {
	f := newMessageFixture(t, messageLimit{Audience: "anyone", Trust: "trusted"})
	f.send(t, "alice", "bob", `"a"`)
	f.send(t, "bob", "carol", `"b"`)
	if err := f.patch(t, `{"data":{"unrelated":true}}`); err != nil {
		t.Fatal(err)
	}
	if len(f.m.doc.Mailboxes) != 2 {
		t.Fatal("unrelated patch discarded mail")
	}
	if err := f.patch(t, `{"identities":{"alice":{"messages":{"send":[]}}}}`); err != nil {
		t.Fatal(err)
	}
	expectMessageStatus(t, f.request("bob", "GET", "/messages?from=alice", ""), http.StatusForbidden)
	if len(f.m.doc.Mailboxes) != 1 {
		t.Fatal("revocation did not discard just the revoked channel")
	}
	if err := f.patch(t, `{"identities":{"carol":{"messages":{"receive":{"bob":{"audience":"me"}}}}}}`); err != nil {
		t.Fatal(err)
	}
	if len(f.m.doc.Mailboxes) != 0 {
		t.Fatal("changed label retained old channel contents")
	}
}

func TestMessagePersistenceFailureNeverReleasesContent(t *testing.T) {
	f := newMessageFixture(t, messageLimit{Audience: "me", Trust: "untrusted"})
	f.send(t, "alice", "bob", `"do not release"`)
	working := f.m.store
	failed := memblob.OpenBucket(nil)
	failed.Close()
	f.m.store = failed
	for range 2 {
		w := f.request("bob", "GET", "/messages?from=alice", "")
		expectMessageStatus(t, w, http.StatusServiceUnavailable)
		if strings.Contains(w.Body.String(), "do not release") {
			t.Fatal("content released after persistence failure")
		}
	}
	if l := f.m.label(f.principals["bob"].Key); l.Audience != "me" || l.Trust != "untrusted" {
		t.Fatal("failed write cleaned the in-memory label")
	}
	f.m.store = working
	expectMessageStatus(t, f.request("bob", "GET", "/messages?from=alice", ""), http.StatusOK)
	if l := f.disk(t).Labels[f.principals["bob"].Key]; l.Audience != "me" || l.Trust != "untrusted" {
		t.Fatal("retry did not persist the label")
	}
}

func TestMessageQueueChangesRollBackOnPersistenceFailure(t *testing.T) {
	f := newMessageFixture(t, messageLimit{Audience: "me", Trust: "untrusted"})
	working := f.m.store
	failed := memblob.OpenBucket(nil)
	failed.Close()
	defer func() { f.m.store = working }()
	f.m.store = failed
	expectMessageStatus(t, f.request("alice", "POST", "/messages", `{"to":"bob","body":"retry me"}`), http.StatusServiceUnavailable)
	if len(f.m.doc.Mailboxes) != 0 || f.m.label(f.principals["alice"].Key).Audience != "me" {
		t.Fatal("failed send must retain the label but leave the queue unchanged")
	}
	f.m.store = working
	id := f.send(t, "alice", "bob", `"retry me"`)
	f.m.store = failed
	expectMessageStatus(t, f.request("bob", "DELETE", "/messages/"+id+"?from=alice", ""), http.StatusServiceUnavailable)
	key := f.principals["alice"].Key + " " + f.principals["bob"].Key
	if len(f.m.doc.Mailboxes[key].Messages) != 1 || f.m.label(f.principals["bob"].Key).Audience != "me" {
		t.Fatal("failed acknowledgement must retain both the label and the message")
	}
	f.m.store = working
	expectMessageStatus(t, f.request("bob", "DELETE", "/messages/"+id+"?from=alice", ""), http.StatusNoContent)
	if doc := f.disk(t); len(doc.Mailboxes) != 0 || doc.Labels[f.principals["bob"].Key].Audience != "me" {
		t.Fatal("retry did not commit the label and acknowledgement together")
	}
}

// A write-only test driver captures each encrypted storage commit.
type messageWriteLog struct {
	driver.Bucket
	documents [][]byte
}

type messageLogWriter struct {
	bytes.Buffer
	log *messageWriteLog
}

func (l *messageWriteLog) NewTypedWriter(context.Context, string, string, *driver.WriterOptions) (driver.Writer, error) {
	return &messageLogWriter{log: l}, nil
}

func (*messageWriteLog) Close() error { return nil }

func (w *messageLogWriter) Close() error {
	w.log.documents = append(w.log.documents, bytes.Clone(w.Bytes()))
	return nil
}

func TestMessagesCommitLabelAndQueueOnce(t *testing.T) {
	f := newMessageFixture(t, messageLimit{Audience: "me", Trust: "untrusted"})
	working := f.m.store
	writes := &messageWriteLog{}
	f.m.store = blob.NewBucket(writes)
	defer func() { f.m.store.Close(); f.m.store = working }()
	id := f.send(t, "alice", "bob", `"one commit"`)
	expectMessageStatus(t, f.request("bob", "DELETE", "/messages/"+id+"?from=alice", ""), http.StatusNoContent)
	if len(writes.documents) != 2 {
		t.Fatalf("send and acknowledgement made %d writes, want one each", len(writes.documents))
	}
	aead, err := newAEAD(f.m.owner)
	if err != nil {
		t.Fatal(err)
	}
	for i, name := range []string{"alice", "bob"} {
		plain, err := aead.Open(nil, nil, writes.documents[i], nil)
		if err != nil {
			t.Fatal(err)
		}
		var doc sealed
		if err := json.Unmarshal(plain, &doc); err != nil {
			t.Fatal(err)
		}
		l := doc.Labels[f.principals[name].Key]
		if l.Audience != "me" || l.Trust != "untrusted" || len(doc.Mailboxes) != 1-i {
			t.Fatalf("commit %d did not contain both the label and queue mutation", i)
		}
	}
}

func TestMessageFullResponsePersistsLabel(t *testing.T) {
	f := newMessageFixture(t, messageLimit{Audience: "me", Trust: "untrusted"})
	for range maxMailboxMessages {
		f.send(t, "alice", "bob", `0`)
	}
	f.m.doc.Labels[f.principals["alice"].Key] = cleanLabel
	expectMessageStatus(t, f.request("alice", "POST", "/messages", `{"to":"bob","body":0}`), http.StatusConflict)
	l := f.disk(t).Labels[f.principals["alice"].Key]
	if l.Audience != "me" || l.Trust != "untrusted" {
		t.Fatal("full queue response escaped without persisting the channel label")
	}
	working := f.m.store
	failed := memblob.OpenBucket(nil)
	failed.Close()
	f.m.store = failed
	defer func() { f.m.store = working }()
	expectMessageStatus(t, f.request("alice", "POST", "/messages", `{"to":"bob","body":0}`), http.StatusServiceUnavailable)
}

func TestMessageAckCannotWriteDown(t *testing.T) {
	f := newMessageFixture(t, messageLimit{Audience: "anyone", Trust: "trusted"})
	id := f.send(t, "alice", "bob", `"public"`)
	expectMessageStatus(t, f.request("bob", "GET", "/messages?from=alice", ""), http.StatusOK)
	f.m.doc.Labels[f.principals["bob"].Key] = label{Audience: "me", Trust: "untrusted"}
	expectMessageStatus(t, f.request("bob", "DELETE", "/messages/"+id+"?from=alice", ""), http.StatusForbidden)
	if len(f.m.doc.Mailboxes) != 1 {
		t.Fatal("private recipient signaled through a public acknowledgement")
	}
}

func TestMessagesBoundQueuesAndPayloads(t *testing.T) {
	f := newMessageFixture(t, messageLimit{Audience: "anyone", Trust: "trusted"})
	for range maxMailboxMessages {
		f.send(t, "alice", "bob", `0`)
	}
	expectMessageStatus(t, f.request("alice", "POST", "/messages", `{"to":"bob","body":0}`), http.StatusConflict)
	tooBig := `{"to":"carol","body":"` + strings.Repeat("x", maxMessageBytes) + `"}`
	expectMessageStatus(t, f.request("bob", "POST", "/messages", tooBig), http.StatusBadRequest)
	largeBody := `"` + strings.Repeat("x", maxMessageBytes-2) + `"`
	for range maxMailboxBytes / maxMessageBytes {
		f.send(t, "bob", "carol", largeBody)
	}
	expectMessageStatus(t, f.request("bob", "POST", "/messages", `{"to":"carol","body":0}`), http.StatusConflict)
}

func TestMessagesOwnerDenyPolicy(t *testing.T) {
	f := newMessageFixture(t, messageLimit{Audience: "anyone", Trust: "trusted"})
	patch, _ := json.Marshal(map[string]any{"policies": map[string]string{"messages.rego": `package sentinel
deny contains "blocked message" if { input.protocol == "messages"; input.action == "message.send"; input.message.body.blocked == true }
deny contains "blocked receive" if { input.action == "message.receive"; input.principal.name == "carol" }
`}})
	if err := f.patch(t, string(patch)); err != nil {
		t.Fatal(err)
	}
	expectMessageStatus(t, f.request("alice", "POST", "/messages", `{"to":"bob","body":{"blocked":true}}`), http.StatusForbidden)
	f.send(t, "alice", "bob", `{"blocked":false}`)
	expectMessageStatus(t, f.request("carol", "GET", "/messages?from=bob", ""), http.StatusForbidden)
}

func TestMessagesRetireConnectorStreams(t *testing.T) {
	f := newMessageFixture(t, messageLimit{Audience: "me", Trust: "untrusted"})
	server, client := net.Pipe()
	defer client.Close()
	s := connector.NewStream(context.Background())
	s.Conn = server
	defer s.Close()
	if err := f.m.trackStream(f.principals["bob"].Key, s); err != nil {
		t.Fatal(err)
	}
	expectMessageStatus(t, f.request("bob", "GET", "/messages?from=alice", ""), http.StatusNoContent)
	if s.Context.Err() == nil {
		t.Fatal("old stream remained authorized")
	}
	client.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Fatalf("old stream is still readable: %v", err)
	}
	if err := f.m.gate(s.Context, input{Principal: f.principals["bob"]}, "web"); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled stream could be reauthorized: %v", err)
	}
}

func TestMessagesConcurrentReceiveAndSend(t *testing.T) {
	f := newMessageFixture(t, messageLimit{Audience: "me", Trust: "untrusted"})
	if err := f.patch(t, `{"identities":{"carol":{"messages":{"receive":{"bob":{"audience":"anyone","trust":"trusted"}}}}}}`); err != nil {
		t.Fatal(err)
	}
	f.send(t, "alice", "bob", `"private"`)
	var wg sync.WaitGroup
	start := make(chan struct{})
	var received, sent *httptest.ResponseRecorder
	wg.Go(func() { <-start; received = f.request("bob", "GET", "/messages?from=alice", "") })
	wg.Go(func() {
		<-start
		sent = f.request("bob", "POST", "/messages", `{"to":"carol","body":"prepared before receiving"}`)
	})
	close(start)
	wg.Wait()
	expectMessageStatus(t, received, http.StatusOK)
	if sent.Code != http.StatusCreated && sent.Code != http.StatusForbidden {
		t.Fatalf("unexpected concurrent send: %s", sent.Body.String())
	}
	expectMessageStatus(t, f.request("bob", "POST", "/messages", `{"to":"carol","body":"after receiving"}`), http.StatusForbidden)
	if l := f.disk(t).Labels[f.principals["bob"].Key]; l.Audience != "me" || l.Trust != "untrusted" {
		t.Fatalf("lost concurrent label update: %+v", l)
	}
}

func TestMessagesSSHAuthenticationAndRouting(t *testing.T) {
	f := newMessageFixture(t, messageLimit{Audience: "me", Trust: "untrusted"})
	ln := &messageTestListener{connections: make(chan net.Conn), closed: make(chan struct{})}
	defer ln.Close()
	go f.m.serveSSH(ln)
	client := func(name string) *http.Client {
		t.Helper()
		serverConn, clientConn := net.Pipe()
		// SSH peers both write their version before reading the other's. Read-ahead
		// gives net.Pipe the buffering a TCP socket normally supplies.
		ln.connections <- bufferMessageTestConn(serverConn)
		clientConn = bufferMessageTestConn(clientConn)
		clientConn.SetDeadline(time.Now().Add(3 * time.Second))
		conn, channels, requests, err := ssh.NewClientConn(clientConn, "memory:22", &ssh.ClientConfig{User: "monitor", Auth: []ssh.AuthMethod{ssh.PublicKeys(f.keys[name])},
			HostKeyCallback: ssh.FixedHostKey(f.m.live.Load().HostKey.PublicKey())})
		if err != nil {
			clientConn.Close()
			t.Fatal(err)
		}
		clientConn.SetDeadline(time.Time{})
		sshClient := ssh.NewClient(conn, channels, requests)
		t.Cleanup(func() { sshClient.Close() })
		transport := &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return sshClient.DialContext(ctx, network, addr)
		}}
		t.Cleanup(transport.CloseIdleConnections)
		return &http.Client{Transport: transport, Timeout: 3 * time.Second}
	}
	alice, bob := client("alice"), client("bob")
	resp, err := alice.Post("http://messages.monitor/messages", "application/json", strings.NewReader(`{"to":"bob","body":"via SSH"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("send over SSH: %s: %s", resp.Status, body)
	}
	resp, err = bob.Get("http://messages.monitor/messages?from=alice")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || !bytes.Contains(body, []byte("via SSH")) {
		t.Fatalf("receive over SSH: %s: %s", resp.Status, body)
	}
	resp, err = alice.Get("http://messages.monitor/messages?from=alice")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatal("SSH caller could impersonate the recipient")
	}
}

type messageTestListener struct {
	connections chan net.Conn
	closed      chan struct{}
	once        sync.Once
}

func (l *messageTestListener) Accept() (net.Conn, error) {
	select {
	case conn := <-l.connections:
		return conn, nil
	case <-l.closed:
		return nil, net.ErrClosed
	}
}

func (l *messageTestListener) Close() error { l.once.Do(func() { close(l.closed) }); return nil }
func (*messageTestListener) Addr() net.Addr { return &net.TCPAddr{} }

type messageTestConn struct {
	net.Conn
	reader *io.PipeReader
}

func bufferMessageTestConn(conn net.Conn) net.Conn {
	r, w := io.Pipe()
	go func() { _, err := io.Copy(w, conn); w.CloseWithError(err) }()
	return &messageTestConn{Conn: conn, reader: r}
}

func (c *messageTestConn) Read(b []byte) (int, error) { return c.reader.Read(b) }
func (c *messageTestConn) Close() error               { c.reader.Close(); return c.Conn.Close() }

func TestMessageConfigurationValidation(t *testing.T) {
	f := newMessageFixture(t, messageLimit{Audience: "anyone", Trust: "trusted"})
	for _, patch := range []string{
		`{"identities":{"alice":{"messages":{"send":["missing"]}}}}`,
		`{"identities":{"bob":{"messages":{"receive":{"alice":{"trust":"unknown"}}}}}}`,
		`{"identities":{"bob":{"messages":{"receive":{"alice":{"audience":"unknown"}}}}}}`,
		`{"identities":{"alice":{"messages":{"send":["alice"]}}}}`,
		`{"accounts":{"messages":{"preset":"web","contents":"anyone","sends":"anyone","connections":{"":{"http":{"hosts":["*"]}}}}}}`,
	} {
		if err := f.patch(t, patch); err == nil {
			t.Fatalf("invalid config accepted: %s", patch)
		}
	}
	duplicate, _ := json.Marshal(map[string]any{"identities": map[string]any{"bob": map[string]string{"key": string(ssh.MarshalAuthorizedKey(f.keys["alice"].PublicKey()))}}})
	if err := f.patch(t, string(duplicate)); err == nil {
		t.Fatal("duplicate public key accepted")
	}
}
