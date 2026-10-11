package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"gocloud.dev/blob"
)

// Exercise the real S3 driver and AWS credential provider. The HTTP fixture
// reproduces S3's missing-object 403 with prefix-restricted ListBucket access.
func TestS3StateAndCredentialRenewal(t *testing.T) {
	var mu sync.Mutex
	var encrypted []byte
	credentials, writes := 0, 0
	denyRead, denyList, denyCredentials := false, false, false
	const prefix = "containers/owner/storage/"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		deny := func() {
			w.Header().Set("Content-Type", "application/xml")
			w.WriteHeader(403)
			io.WriteString(w, `<Error><Code>AccessDenied</Code><Message>denied</Message></Error>`)
		}
		if r.URL.Path == "/credentials" {
			if r.Header.Get("Authorization") != "Bearer deployment-token" {
				t.Error("missing deployment authentication")
				deny()
				return
			}
			if denyCredentials {
				deny()
				return
			}
			credentials++
			// Already-expired test credentials force the SDK to renew on the
			// next request without sleeping or invalidating its cache by hand.
			json.NewEncoder(w).Encode(map[string]any{"AccessKeyId": fmt.Sprintf("ASIATEST%d", credentials), "SecretAccessKey": "secret", "Token": "session", "Expiration": time.Now().Add(-time.Minute).UTC()})
			return
		}
		if !strings.Contains(r.Header.Get("Authorization"), "Credential=ASIATEST") || r.Header.Get("X-Amz-Security-Token") != "session" {
			t.Error("request did not use issued AWS credentials")
			deny()
			return
		}
		if r.Method == http.MethodGet && r.URL.Query().Get("list-type") == "2" {
			if r.URL.Query().Get("prefix") != prefix+stateObject {
				t.Errorf("unscoped listing: %s", r.URL)
				deny()
				return
			}
			if denyList {
				deny()
				return
			}
			w.Header().Set("Content-Type", "application/xml")
			contents := ""
			if len(encrypted) > 0 {
				contents = fmt.Sprintf("<Contents><Key>%s%s</Key><Size>%d</Size><LastModified>2026-01-01T00:00:00Z</LastModified></Contents>", prefix, stateObject, len(encrypted))
			}
			fmt.Fprintf(w, `<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><IsTruncated>false</IsTruncated>%s</ListBucketResult>`, contents)
			return
		}
		if r.URL.Path != "/state-bucket/"+prefix+stateObject {
			t.Errorf("unscoped object: %s", r.URL)
			deny()
			return
		}
		switch r.Method {
		case http.MethodGet:
			if denyRead || len(encrypted) == 0 {
				deny()
				return
			}
			w.Header().Set("Content-Length", strconv.Itoa(len(encrypted)))
			w.Write(encrypted)
		case http.MethodPut:
			var err error
			encrypted, err = io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
			}
			writes++
			w.Header().Set("ETag", `"test"`)
		default:
			t.Errorf("unexpected S3 method %s", r.Method)
			deny()
		}
	}))
	defer server.Close()
	for _, name := range []string{"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE"} {
		t.Setenv(name, "")
	}
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", t.TempDir()+"/absent")
	t.Setenv("AWS_CONFIG_FILE", t.TempDir()+"/absent")
	t.Setenv("AWS_EC2_METADATA_DISABLED", "true")
	t.Setenv("AWS_CONTAINER_CREDENTIALS_FULL_URI", server.URL+"/credentials")
	t.Setenv("AWS_CONTAINER_AUTHORIZATION_TOKEN", "Bearer deployment-token")
	query := url.Values{"region": {"us-west-2"}, "prefix": {prefix}, "endpoint": {server.URL}, "use_path_style": {"true"}, "hostname_immutable": {"true"}}
	store, err := blob.OpenBucket(t.Context(), "s3://state-bucket?"+query.Encode())
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	key := bytes.Repeat([]byte{7}, ownerKeyBytes)
	digest := sha256.Sum256(key)
	open := func() *monitor { return &monitor{store: store, ownerKeyHash: digest[:]} }
	m := open()
	if err := m.unlock(t.Context(), key, 0); err != nil {
		t.Fatal(err)
	}
	if m.doc.Generation != 1 {
		t.Fatalf("generation = %d", m.doc.Generation)
	}
	aead, err := newAEAD(key)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	ciphertext := bytes.Clone(encrypted)
	mu.Unlock()
	plain, err := aead.Open(nil, nil, ciphertext, nil)
	if err != nil || !json.Valid(plain) {
		t.Fatalf("state was not owner-encrypted JSON: %v", err)
	}
	m = open()
	if err := m.unlock(t.Context(), key, 1); err != nil {
		t.Fatal(err)
	}
	if m.doc.Generation != 2 {
		t.Fatalf("restart generation = %d", m.doc.Generation)
	}
	mu.Lock()
	if credentials < 2 || writes != 2 {
		t.Errorf("credentials=%d writes=%d", credentials, writes)
	}
	mu.Unlock()
	for _, scenario := range []string{"existing object denied", "listing denied", "credential revoked", "missing object with saved generation"} {
		t.Run(scenario, func(t *testing.T) {
			mu.Lock()
			before := writes
			denyRead, denyList, denyCredentials = true, scenario == "listing denied", scenario == "credential revoked"
			minimum := uint64(0)
			if scenario == "missing object with saved generation" {
				encrypted = nil
				minimum = 2
			}
			mu.Unlock()
			if err := open().unlock(t.Context(), key, minimum); err == nil {
				t.Fatal("unavailable state accepted as an empty Monitor")
			}
			mu.Lock()
			defer mu.Unlock()
			if writes != before {
				t.Fatal("failed read overwrote persistent state")
			}
		})
	}
}
