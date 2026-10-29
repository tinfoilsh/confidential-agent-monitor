package monitor

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/internal/tinfoil/ownerauth"
	"gocloud.dev/blob"
	"gocloud.dev/blob/memblob"
)

const testBucketURL = "s3://tinfoil-containers?prefix=containers%2Fowner%2Fmonitor%2F&region=us-east-1"

type owner struct {
	t       *testing.T
	private ed25519.PrivateKey
}

// call sends one owner request signed as a client would, through the measured handler.
func (o owner) call(h http.Handler, method, path string, body any, generation uint64) (int, map[string]any) {
	var raw []byte
	if body != nil {
		raw, _ = json.Marshal(body)
	}
	id := func(n int) string {
		b := make([]byte, n)
		rand.Read(b)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	request := fmt.Sprintf(`{"protocol":"monitor-owner-v2","owner":%q,"resource":%q,"method":%q,"path":%q,"body":%q,"operation":%q,"session":"","generation":%d,"issued_at":%d,"nonce":%q}`,
		ownerauth.OwnerKey(o.private.Public().(ed25519.PublicKey)), testBucketURL, method, path, base64.RawURLEncoding.EncodeToString(raw), id(16), generation, time.Now().UnixMilli(), id(24))
	signature := ed25519.Sign(o.private, append([]byte(ownerauth.RequestContext), request...))
	envelope := fmt.Sprintf(`{"request":%q,"signature":%q}`, base64.RawURLEncoding.EncodeToString([]byte(request)), base64.RawURLEncoding.EncodeToString(signature))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/owner/rpc", bytes.NewReader([]byte(envelope))))
	var reply map[string]any
	json.Unmarshal(w.Body.Bytes(), &reply)
	return w.Code, reply
}

func boot(t *testing.T, bucket *blob.Bucket, public ed25519.PublicKey) http.Handler {
	m := New(Options{Bucket: bucket, BucketURL: testBucketURL, OwnerPublicKey: public, Connectors: map[string]connector.Kind{}})
	t.Cleanup(m.Close)
	return m.HTTPHandler(nil)
}

func TestUnlockInitializesOnlyConfirmedAbsentState(t *testing.T) {
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	o := owner{t, private}
	key := make([]byte, 32)
	rand.Read(key)
	unlock := func(minimum uint64, key []byte) map[string]any {
		return map[string]any{"generation": minimum, "storage_key": key}
	}

	bucket := memblob.OpenBucket(nil)
	h := boot(t, bucket, public)
	if code, health := o.call(h, http.MethodGet, "/healthz", nil, 0); code != http.StatusOK || health["state"] != "absent" || health["locked"] != true {
		t.Fatalf("empty healthz: %d %v", code, health)
	}
	// A client that saved a generation never gets an empty replacement for missing state.
	if code, _ := o.call(h, http.MethodPost, "/unlock", unlock(3, key), 3); code == http.StatusOK {
		t.Fatal("initialized with a saved minimum")
	}
	if exists, _ := bucket.Exists(context.Background(), "monitor.enc"); exists {
		t.Fatal("a refused unlock wrote state")
	}
	code, view := o.call(h, http.MethodPost, "/unlock", unlock(0, key), 0)
	if code != http.StatusOK || view["initialized"] != true || view["generation"] != 1.0 {
		t.Fatalf("first unlock: %d %v %v", code, view["initialized"], view["generation"])
	}
	if code, view := o.call(h, http.MethodPost, "/unlock", unlock(0, key), 0); code != http.StatusOK || view["initialized"] != false {
		t.Fatalf("repeated unlock: %d %v", code, view["initialized"])
	}
	if code, health := o.call(h, http.MethodGet, "/healthz", nil, 0); code != http.StatusOK || health["state"] != "present" || health["locked"] != false {
		t.Fatalf("healthz: %d %v", code, health)
	}
	// Unauthenticated health reports only the lock.
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Body.String() != `{"locked":false}` {
		t.Fatalf("public healthz: %s", w.Body)
	}

	// A new boot, even from a client without a saved generation, loads the stored state.
	restarted := boot(t, bucket, public)
	other := make([]byte, 32)
	rand.Read(other)
	if code, _ := o.call(restarted, http.MethodPost, "/unlock", unlock(0, other), 0); code != http.StatusUnauthorized {
		t.Fatalf("wrong storage key: %d", code)
	}
	if code, _ := o.call(restarted, http.MethodPost, "/unlock", unlock(2, key), 2); code == http.StatusOK {
		t.Fatal("loaded state older than the saved generation")
	}
	// Unlocking commits once more, so the loaded generation 1 becomes 2.
	if code, view := o.call(restarted, http.MethodPost, "/unlock", unlock(0, key), 0); code != http.StatusOK || view["initialized"] != false || view["generation"] != 2.0 {
		t.Fatalf("restart unlock: %d %v %v", code, view["initialized"], view["generation"])
	}
	if code, _ := o.call(restarted, http.MethodPost, "/sandboxes/name/enroll", map[string]any{}, 0); code != http.StatusNotFound {
		t.Fatalf("retired enrollment route: %d", code)
	}
}
