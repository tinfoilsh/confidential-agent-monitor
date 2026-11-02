package store

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"gocloud.dev/blob"
	"gocloud.dev/blob/s3blob"
)

func TestS3CommitRejectsStaleAndConcurrentInitialWriters(t *testing.T) {
	var mu sync.Mutex
	var object []byte
	var etag string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		if r.URL.Path != "/test-bucket/owner/monitor.enc" {
			t.Errorf("unexpected storage path: %s", r.URL)
			w.WriteHeader(400)
			return
		}
		switch r.Method {
		case http.MethodGet:
			if object == nil {
				w.WriteHeader(404)
				fmt.Fprint(w, `<Error><Code>NoSuchKey</Code></Error>`)
				return
			}
			w.Header().Set("ETag", etag)
			w.Write(object)
		case http.MethodPut:
			match, absent := r.Header.Get("If-Match"), r.Header.Get("If-None-Match")
			if match == "" && absent != "*" {
				t.Error("state PUT did not have a precondition")
			}
			if absent == "*" && object != nil || match != "" && match != etag {
				w.WriteHeader(412)
				fmt.Fprint(w, `<Error><Code>PreconditionFailed</Code></Error>`)
				return
			}
			var err error
			object, err = io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
			}
			etag = fmt.Sprintf(`"%x"`, sha256.Sum256(object))
			w.Header().Set("ETag", etag)
		default:
			t.Errorf("unexpected storage method: %s", r.Method)
			w.WriteHeader(400)
		}
	}))
	defer server.Close()
	client := s3.NewFromConfig(aws.Config{Region: "us-east-2", Credentials: aws.AnonymousCredentials{}, HTTPClient: server.Client(), RequestChecksumCalculation: aws.RequestChecksumCalculationWhenRequired}, func(o *s3.Options) {
		o.BaseEndpoint, o.UsePathStyle = aws.String(server.URL), true
	})
	bucket, err := s3blob.OpenBucket(t.Context(), client, "test-bucket", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer bucket.Close()
	base := Store{Bucket: blob.PrefixedBucket(bucket, "owner/"), BucketURL: "s3://test-bucket?prefix=owner%2F&region=us-east-2"}
	key := bytes.Repeat([]byte{1}, OwnerKeyBytes)
	load := func() Store {
		t.Helper()
		state, _, err := base.Load(t.Context(), key, 0)
		if err != nil {
			t.Fatal(err)
		}
		return state
	}
	first, concurrent := load(), load()
	if err := first.Commit(t.Context(), first.Doc); err != nil {
		t.Fatal(err)
	}
	if err := concurrent.Commit(t.Context(), concurrent.Doc); err == nil || concurrent.Doc.Generation != 0 {
		t.Fatalf("concurrent initialization overwrote state: %v, generation %d", err, concurrent.Doc.Generation)
	}
	first, stale := load(), load()
	newDoc := first.Doc
	newDoc.Policy = "new policy"
	if err := first.Commit(t.Context(), newDoc); err != nil {
		t.Fatal(err)
	}
	if err := stale.Commit(t.Context(), stale.Doc); err == nil || stale.Doc.Generation != 1 {
		t.Fatalf("stale commit overwrote state: %v, generation %d", err, stale.Doc.Generation)
	}
	// A second commit uses the ETag returned by PUT, without an intervening HEAD.
	if err := first.Commit(t.Context(), first.Doc); err != nil {
		t.Fatal(err)
	}
	saved := load()
	if saved.Doc.Generation != 3 || saved.Doc.Policy != "new policy" {
		t.Fatalf("unexpected persisted document: %+v", saved.Doc)
	}
	if _, _, err := base.Load(t.Context(), key, 4); err == nil {
		t.Fatal("accepted an older generation than the owner's checkpoint")
	}
}
