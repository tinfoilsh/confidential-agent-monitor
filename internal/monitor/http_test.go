package monitor

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tinfoilsh/monitor/internal/store"
	"github.com/tinfoilsh/monitor/internal/tinfoil/ownerauth"
	"gocloud.dev/blob/memblob"
)

func TestPublicMonitorDoesNotExposeStorageOrUnlockState(t *testing.T) {
	bucket := memblob.OpenBucket(nil)
	defer bucket.Close()
	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, attacker, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	m := New(Options{Bucket: bucket, OwnerPublicKey: public, BucketURL: "s3://test/owner"})
	defer m.Close()
	handler := m.HTTPHandler(nil)
	key := bytes.Repeat([]byte{1}, store.OwnerKeyBytes)
	for _, stage := range []string{"empty", "unlocked", "unavailable"} {
		t.Run(stage, func(t *testing.T) {
			if stage == "unlocked" {
				if _, err := m.unlock(t.Context(), key, 0); err != nil {
					t.Fatal(err)
				}
			}
			if stage == "unavailable" {
				if err := bucket.Close(); err != nil {
					t.Fatal(err)
				}
			}
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, httptest.NewRequest("GET", "/healthz", nil))
			if w.Code != 200 || strings.TrimSpace(w.Body.String()) != "{}" {
				t.Fatalf("public health exposed state: %d %s", w.Code, w.Body)
			}
			for _, path := range []string{"/healthz", "/unlock"} {
				// A different signing identity must be rejected before any state
				// probe or decryption, even with the correct storage key.
				body, _ := json.Marshal(unlockInput{StorageKey: key})
				request, _ := json.Marshal(map[string]any{"path": path, "body": base64.RawURLEncoding.EncodeToString(body)})
				digest := sha256.Sum256(request)
				signature := ed25519.Sign(attacker, append([]byte(ownerauth.RequestContext), digest[:]...))
				envelope, _ := json.Marshal(struct {
					Request   string `json:"request"`
					Signature string `json:"signature"`
				}{base64.RawURLEncoding.EncodeToString(request), base64.RawURLEncoding.EncodeToString(signature)})
				w := httptest.NewRecorder()
				handler.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/owner/rpc", bytes.NewReader(envelope)))
				if w.Code != http.StatusUnauthorized || !strings.Contains(w.Body.String(), "invalid_signature") {
					t.Fatalf("unauthenticated RPC: %d %s", w.Code, w.Body)
				}
			}
		})
	}
}
