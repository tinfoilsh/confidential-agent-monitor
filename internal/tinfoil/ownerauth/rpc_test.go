package ownerauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"filippo.io/edwards25519"
)

const testResource = "s3://tinfoil-containers?prefix=containers%2Fowner%2Fmonitor%2F&region=us-east-1"

type ownerFixture struct {
	Owner    string `json:"owner"`
	Seed     string `json:"seed"`
	Requests []struct {
		Name      string `json:"name"`
		Bytes     string `json:"bytes"`
		Envelope  string `json:"envelope"`
		InnerBody string `json:"inner_body"`
	} `json:"requests"`
	ServerRejects []struct {
		Case      string  `json:"case"`
		Bytes     string  `json:"bytes"`
		Signature string  `json:"signature"`
		Error     *string `json:"error"`
		Server    struct {
			NowMs    int64  `json:"now_ms"`
			Owner    string `json:"owner"`
			Protocol string `json:"protocol"`
			Resource string `json:"resource"`
		} `json:"server"`
	} `json:"server_rejects"`
	InvalidRequests []struct {
		Case  string `json:"case"`
		Bytes string `json:"bytes"`
	} `json:"invalid_requests"`
}

func loadFixture(t *testing.T) ownerFixture {
	raw, err := os.ReadFile("testdata/owner-contract-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var f struct {
		OwnerRequest ownerFixture `json:"owner_request"`
	}
	if err := json.Unmarshal(raw, &f); err != nil {
		t.Fatal(err)
	}
	return f.OwnerRequest
}

// innerCall is what the owner API saw for one authenticated request.
type innerCall struct{ method, target, body string }

func recordingAPI(calls *[]innerCall, mu *sync.Mutex) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		*calls = append(*calls, innerCall{r.Method, r.URL.RequestURI(), string(body)})
		mu.Unlock()
		fmt.Fprintf(w, "ok %d", len(body))
	})
}

func at(ms int64) func() time.Time { return func() time.Time { return time.UnixMilli(ms) } }

func post(h http.Handler, envelope []byte) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/owner/rpc", bytes.NewReader(envelope)))
	return w
}

func class(w *httptest.ResponseRecorder) string {
	var body struct{ Error string }
	json.Unmarshal(w.Body.Bytes(), &body)
	return body.Error
}

func TestAdmittedEffectSurvivesLostConnection(t *testing.T) {
	s := newSigner(t)
	const start = 1_800_000_000_000
	var now atomic.Int64
	now.Store(start)
	var runs, completed atomic.Int32
	entered, release := make(chan struct{}), make(chan struct{})
	h := s.handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		runs.Add(1)
		close(entered)
		<-release
		if err := r.Context().Err(); err != nil {
			http.Error(w, err.Error(), http.StatusServiceUnavailable)
			return
		}
		if _, ok := FromContext(r.Context()); !ok {
			http.Error(w, "owner context lost", http.StatusUnauthorized)
			return
		}
		completed.Add(1)
		w.Write([]byte(`{"unlocked":true}`))
	}), &now)
	operation := newOperation()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	first := httptest.NewRecorder()
	envelope := s.sign(http.MethodPost, "/unlock", "{}", operation, start)
	done := make(chan struct{})
	go func() {
		h.ServeHTTP(first, httptest.NewRequest(http.MethodPost, "/owner/rpc", bytes.NewReader(envelope)).WithContext(ctx))
		close(done)
	}()
	select {
	case <-entered:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("effect did not start")
	}
	cancel()
	close(release)
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("admitted effect did not finish")
	}
	retry := post(h, s.sign(http.MethodPost, "/unlock", "{}", operation, start))
	if runs.Load() != 1 || completed.Load() != 1 || retry.Code != http.StatusOK || retry.Body.String() != `{"unlocked":true}` {
		t.Fatalf("runs=%d completed=%d retry=%d %s", runs.Load(), completed.Load(), retry.Code, retry.Body)
	}
}

func envelopeFor(t *testing.T, raw []byte, signature string) []byte {
	out, err := contractJSON(envelope{Request: base64.RawURLEncoding.EncodeToString(raw), Signature: signature})
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestOwnerContractFixture(t *testing.T) {
	f := loadFixture(t)
	key, err := ParseOwnerKey(f.Owner)
	if err != nil {
		t.Fatal(err)
	}
	for _, vector := range f.Requests {
		t.Run(vector.Name, func(t *testing.T) {
			var call request
			if err := decodeCanonical([]byte(vector.Bytes), &call); err != nil {
				t.Fatal(err)
			}
			var calls []innerCall
			var mu sync.Mutex
			h := &Handler{Key: key, Resource: call.Resource, MaxBytes: 1 << 20, API: recordingAPI(&calls, &mu), Generation: func() (uint64, bool) { return 0, false }, Now: at(call.IssuedAt)}
			w := post(h, []byte(vector.Envelope))
			if call.Protocol != Protocol {
				if w.Code != http.StatusUnauthorized || class(w) != "wrong_protocol" || len(calls) != 0 {
					t.Fatalf("other protocol: %d %s %v", w.Code, w.Body, calls)
				}
				return
			}
			want := innerCall{call.Method, call.Path, vector.InnerBody}
			if w.Code != http.StatusOK || len(calls) != 1 || calls[0] != want {
				t.Fatalf("got %d %s %v, want %v", w.Code, w.Body, calls, want)
			}
		})
	}
	for _, vector := range f.ServerRejects {
		if vector.Server.Protocol != Protocol {
			continue
		}
		t.Run(vector.Case, func(t *testing.T) {
			measured, err := ParseOwnerKey(vector.Server.Owner)
			if err != nil {
				t.Fatal(err)
			}
			var calls []innerCall
			var mu sync.Mutex
			h := &Handler{Key: measured, Resource: vector.Server.Resource, MaxBytes: 1 << 20, API: recordingAPI(&calls, &mu), Generation: func() (uint64, bool) { return 0, false }, Now: at(vector.Server.NowMs)}
			w := post(h, envelopeFor(t, []byte(vector.Bytes), vector.Signature))
			if vector.Error == nil {
				if w.Code != http.StatusOK || len(calls) != 1 {
					t.Fatalf("want accepted, got %d %s", w.Code, w.Body)
				}
				return
			}
			if class(w) != *vector.Error || len(calls) != 0 {
				t.Fatalf("want %s, got %d %s (calls %v)", *vector.Error, w.Code, w.Body, calls)
			}
		})
	}
	seed, err := decodeB64U(f.Seed, ed25519.SeedSize)
	if err != nil {
		t.Fatal(err)
	}
	private := ed25519.NewKeyFromSeed(seed)
	for _, vector := range f.InvalidRequests {
		t.Run("validly_signed_"+vector.Case, func(t *testing.T) {
			var call request
			json.Unmarshal([]byte(vector.Bytes), &call)
			signature := ed25519.Sign(private, append([]byte(RequestContext), vector.Bytes...))
			h := &Handler{Key: key, Resource: call.Resource, MaxBytes: 1 << 20, API: http.NotFoundHandler(), Generation: func() (uint64, bool) { return 0, false }, Now: at(call.IssuedAt)}
			if w := post(h, envelopeFor(t, []byte(vector.Bytes), base64.RawURLEncoding.EncodeToString(signature))); class(w) != "malformed" {
				t.Fatalf("got %d %s", w.Code, w.Body)
			}
		})
	}
}

// signer issues owner requests for one key against testResource.
type signer struct {
	t       *testing.T
	private ed25519.PrivateKey
}

func newSigner(t *testing.T) signer {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return signer{t, private}
}

func (s signer) handler(api http.Handler, now *atomic.Int64) *Handler {
	return &Handler{Key: s.private.Public().(ed25519.PublicKey), Resource: testResource, MaxBytes: 8 << 20, API: api,
		Generation: func() (uint64, bool) { return 0, false }, Untracked: []string{"/sandboxes/relay"},
		Now: func() time.Time { return time.UnixMilli(now.Load()) }}
}

func (s signer) sign(method, path, body, operation string, issued int64) []byte {
	nonce := make([]byte, nonceBytes)
	rand.Read(nonce)
	raw, err := contractJSON(request{Protocol: Protocol, Owner: OwnerKey(s.private.Public().(ed25519.PublicKey)), Resource: testResource,
		Method: method, Path: path, Body: base64.RawURLEncoding.EncodeToString([]byte(body)), Operation: operation,
		IssuedAt: issued, Nonce: base64.RawURLEncoding.EncodeToString(nonce)})
	if err != nil {
		s.t.Fatal(err)
	}
	signature := ed25519.Sign(s.private, append([]byte(RequestContext), raw...))
	return envelopeFor(s.t, raw, base64.RawURLEncoding.EncodeToString(signature))
}

func newOperation() string {
	id := make([]byte, 16)
	rand.Read(id)
	return base64.RawURLEncoding.EncodeToString(id)
}

func TestNonceWindowIsInclusiveAndNeverEvictsLiveNonces(t *testing.T) {
	s := newSigner(t)
	const start = 1_800_000_000_000
	var now atomic.Int64
	now.Store(start)
	var calls []innerCall
	var mu sync.Mutex
	h := s.handler(recordingAPI(&calls, &mu), &now)
	first := s.sign(http.MethodGet, "/audit", "", newOperation(), start)
	if w := post(h, first); w.Code != http.StatusOK {
		t.Fatalf("first: %d %s", w.Code, w.Body)
	}
	for i := 1; i < maxNonces; i++ {
		if w := post(h, s.sign(http.MethodGet, "/audit", "", newOperation(), start)); w.Code != http.StatusOK {
			t.Fatalf("fill %d: %d %s", i, w.Code, w.Body)
		}
	}
	now.Store(start + RequestWindow)
	if w := post(h, first); class(w) != "replayed" {
		t.Fatalf("replay at the inclusive deadline: %d %s", w.Code, w.Body)
	}
	if w := post(h, s.sign(http.MethodGet, "/audit", "", newOperation(), start+RequestWindow)); class(w) != "owner_busy" {
		t.Fatalf("full of live nonces: %d %s", w.Code, w.Body)
	}
	now.Store(start + RequestWindow + 1)
	if w := post(h, first); class(w) != "request_expired" {
		t.Fatalf("replay after the deadline: %d %s", w.Code, w.Body)
	}
	if w := post(h, s.sign(http.MethodGet, "/audit", "", newOperation(), start+RequestWindow+1)); w.Code != http.StatusOK {
		t.Fatalf("after expiry: %d %s", w.Code, w.Body)
	}
	if w := post(h, s.sign(http.MethodGet, "/audit", "", newOperation(), start+RequestWindow+2)); class(w) != "request_time_in_future" {
		t.Fatalf("future: %d %s", w.Code, w.Body)
	}
	if len(calls) != maxNonces+1 {
		t.Fatalf("dispatched %d calls", len(calls))
	}
}

func TestOperationRetriesShareOneEffect(t *testing.T) {
	s := newSigner(t)
	const start = 1_800_000_000_000
	var now atomic.Int64
	now.Store(start)
	var runs atomic.Int32
	release := make(chan struct{})
	h := s.handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		n := runs.Add(1)
		if string(body) == "slow" {
			<-release
		}
		if string(body) == "large" {
			w.Write(bytes.Repeat([]byte("x"), maxResultBytes+1))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		fmt.Fprintf(w, `{"run":%d}`, n)
	}), &now)

	operation := newOperation()
	responses := make(chan *httptest.ResponseRecorder, 2)
	for range 2 {
		go func() { responses <- post(h, s.sign(http.MethodPost, "/enroll", "slow", operation, start)) }()
	}
	for runs.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	close(release)
	for range 2 {
		w := <-responses
		if w.Code != http.StatusCreated || w.Body.String() != `{"run":1}` || w.Header().Get("Content-Type") != "application/json" {
			t.Fatalf("concurrent duplicate: %d %q %v", w.Code, w.Body, w.Header())
		}
	}
	// A lost reply is retried with a fresh nonce and the original content and time.
	now.Store(start + RequestWindow)
	if w := post(h, s.sign(http.MethodPost, "/enroll", "slow", operation, start)); w.Code != http.StatusCreated || w.Body.String() != `{"run":1}` {
		t.Fatalf("retry: %d %q", w.Code, w.Body)
	}
	if w := post(h, s.sign(http.MethodPost, "/enroll", "other", operation, start)); class(w) != "operation_conflict" {
		t.Fatalf("changed content: %d %s", w.Code, w.Body)
	}
	if w := post(h, s.sign(http.MethodPost, "/enroll", "slow", operation, start+1)); class(w) != "operation_conflict" {
		t.Fatalf("changed time: %d %s", w.Code, w.Body)
	}
	now.Store(start + RequestWindow + 1)
	if w := post(h, s.sign(http.MethodPost, "/enroll", "slow", operation, start)); class(w) != "request_expired" {
		t.Fatalf("after the deadline: %d %s", w.Code, w.Body)
	}
	if runs.Load() != 1 {
		t.Fatalf("effect ran %d times", runs.Load())
	}

	// Relay and GET own no effects, so each request runs.
	relay := newOperation()
	for range 2 {
		post(h, s.sign(http.MethodPost, "/sandboxes/relay", "ciphertext", relay, start+RequestWindow+1))
	}
	if runs.Load() != 3 {
		t.Fatalf("relay ran %d times", runs.Load()-1)
	}

	// A result too large to keep is not replayed as success.
	large := newOperation()
	if w := post(h, s.sign(http.MethodPost, "/policy", "large", large, start+RequestWindow+1)); w.Code != http.StatusOK || w.Body.Len() != maxResultBytes+1 {
		t.Fatalf("large: %d %d", w.Code, w.Body.Len())
	}
	if w := post(h, s.sign(http.MethodPost, "/policy", "large", large, start+RequestWindow+1)); class(w) != "owner_busy" || runs.Load() != 4 {
		t.Fatalf("large retry: %d %s after %d runs", w.Code, w.Body, runs.Load())
	}
}

func TestOwnerRequestBindings(t *testing.T) {
	s := newSigner(t)
	const start = 1_800_000_000_000
	var now atomic.Int64
	now.Store(start)
	h := s.handler(http.NotFoundHandler(), &now)
	h.Generation = func() (uint64, bool) { return 3, true }
	for name, path := range map[string]string{"app": "/app/index.html", "nested rpc": "/owner/rpc", "dot segments": "/a/../unlock", "escaped dots": "/%2e%2e/unlock"} {
		if w := post(h, s.sign(http.MethodPost, path, "{}", newOperation(), start)); class(w) != "malformed" {
			t.Fatalf("%s: %d %s", name, w.Code, w.Body)
		}
	}
	nonce := make([]byte, nonceBytes)
	raw, _ := contractJSON(request{Protocol: Protocol, Owner: OwnerKey(s.private.Public().(ed25519.PublicKey)), Resource: testResource, Method: http.MethodPost,
		Path: "/unlock", Operation: newOperation(), Generation: 4, IssuedAt: start, Nonce: base64.RawURLEncoding.EncodeToString(nonce)})
	stale := envelopeFor(t, raw, base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.private, append([]byte(RequestContext), raw...))))
	if w := post(h, stale); class(w) != "stale_generation" {
		t.Fatalf("stale generation: %d %s", w.Code, w.Body)
	}
	// Monitor has no shell sessions to bind.
	raw, _ = contractJSON(request{Protocol: Protocol, Owner: OwnerKey(s.private.Public().(ed25519.PublicKey)), Resource: testResource, Method: http.MethodGet,
		Path: "/audit", Operation: newOperation(), Session: newOperation(), IssuedAt: start, Nonce: base64.RawURLEncoding.EncodeToString(nonce)})
	if w := post(h, envelopeFor(t, raw, base64.RawURLEncoding.EncodeToString(ed25519.Sign(s.private, append([]byte(RequestContext), raw...))))); class(w) != "malformed" {
		t.Fatalf("session: %d %s", w.Code, w.Body)
	}
	other := newSigner(t)
	if w := post(h, other.sign(http.MethodGet, "/audit", "", newOperation(), start)); class(w) != "invalid_signature" {
		t.Fatalf("another key: %d %s", w.Code, w.Body)
	}
	if w := post(h, []byte(strings.Replace(string(s.sign(http.MethodGet, "/audit", "", newOperation(), start)), `{"request"`, `{ "request"`, 1))); class(w) != "malformed" {
		t.Fatalf("reformatted envelope: %d %s", w.Code, w.Body)
	}
}

// TestSmallOrderOwnerKeyIsRejected keeps signature possession meaningful: the identity
// point verifies a signature with R = B and S = 1 for any message.
func TestSmallOrderOwnerKeyIsRejected(t *testing.T) {
	identity := edwards25519.NewIdentityPoint().Bytes()
	forged := append(edwards25519.NewGeneratorPoint().Bytes(), make([]byte, 32)...)
	forged[32] = 1
	message := []byte(RequestContext + `{"protocol":"monitor-owner-v2","path":"/unlock"}`)
	if !ed25519.Verify(identity, message, forged) {
		t.Fatal("the forgery this guards against no longer verifies")
	}
	if _, err := ParseOwnerKey(OwnerKey(identity)); err == nil {
		t.Fatal("accepted the identity point as an owner key")
	}
	// Points of order 2 and 4: y = -1, and y = 0 with either sign.
	minusOne := append([]byte{0xec}, bytes.Repeat([]byte{0xff}, 30)...)
	for _, raw := range [][]byte{append(minusOne, 0x7f), make([]byte, 32), append(make([]byte, 31), 0x80)} {
		if _, err := ParseOwnerKey(OwnerKey(raw)); err == nil {
			t.Fatalf("accepted small-order key %x", raw)
		}
	}
	// p + k encodes the large-order point with y = k, which SetBytes alone accepts.
	noncanonical := 0
	for k := byte(2); k <= 18; k++ {
		raw := append(append([]byte{0xed + k}, bytes.Repeat([]byte{0xff}, 30)...), 0x7f)
		point, err := new(edwards25519.Point).SetBytes(raw)
		if err != nil || new(edwards25519.Point).MultByCofactor(point).Equal(edwards25519.NewIdentityPoint()) == 1 {
			continue
		}
		noncanonical++
		if _, err := ParseOwnerKey(OwnerKey(raw)); err == nil {
			t.Fatalf("accepted the non-canonical encoding %x", raw)
		}
	}
	if noncanonical == 0 {
		t.Fatal("no non-canonical large-order encoding was tested")
	}
	for _, malformed := range []string{"ed25519:" + base64.RawStdEncoding.EncodeToString(identity), "ssh-ed25519 AAAA", OwnerKey(identity) + "\n"} {
		if _, err := ParseOwnerKey(malformed); err == nil {
			t.Fatalf("accepted %q", malformed)
		}
	}
	public, _, _ := ed25519.GenerateKey(rand.Reader)
	if _, err := ParseOwnerKey(OwnerKey(public)); err != nil {
		t.Fatal(err)
	}
}
