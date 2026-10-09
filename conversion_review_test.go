package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/tinfoilsh/monitor/facts"
)

func TestPolicyEditDoesNotWaitForCredentialRefresh(t *testing.T) {
	for _, remove := range []bool{false, true} {
		t.Run(fmt.Sprint("remove=", remove), func(t *testing.T) {
			started, release := make(chan struct{}), make(chan struct{})
			resume := sync.OnceFunc(func() { close(release) })
			provider := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				close(started)
				<-release
				w.Header().Set("Content-Type", "application/json")
				w.Write([]byte(`{"access_token":"new","token_type":"Bearer","refresh_token":"rotated","expires_in":3600}`))
			}))
			defer provider.Close()
			defer resume()
			f := discoveryFixture(t)
			c := f.m.live.Load().connections["web"]
			path := append(c.path(), "secrets", "TOKEN")
			grant, _ := json.Marshal(map[string]any{"oauth": map[string]any{"token_url": provider.URL, "client_id": "fixture", "auth_style": "params", "refresh_token": "old"}})
			if _, err := f.m.editPolicyState(t.Context(), []sourceChange{{Path: path, Value: grant}}); err != nil {
				t.Fatal(err)
			}
			c = f.m.live.Load().connections["web"]
			value := c.Secrets[path[6]]
			value.Client = provider.Client()
			refreshed := make(chan error, 1)
			go func() { _, err := value.Value(t.Context()); refreshed <- err }()
			waitForTest(t, started)
			change := sourceChange{Path: []string{"lattices", "integrity"}, Value: json.RawMessage(`false`)}
			if remove {
				change = sourceChange{Path: path, Delete: true}
			}
			edited := make(chan error, 1)
			go func() { _, err := f.m.editPolicyState(t.Context(), []sourceChange{change}); edited <- err }()
			select {
			case err := <-edited:
				if err != nil {
					t.Fatal(err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("policy edit waited for an in-flight token refresh")
			}
			next := f.m.live.Load().connections["web"]
			if (next == c) == remove {
				t.Fatal("connection reuse did not follow changed credential paths")
			}
			resume()
			select {
			case err := <-refreshed:
				if (err != nil) != remove {
					t.Fatalf("refresh after edit: %v", err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("refresh did not finish")
			}
			if remove && f.m.doc.Secrets.get(credentialID(path)) != nil {
				t.Fatal("refresh restored a deleted credential")
			}
		})
	}
}

func TestCredentialProtocolsRequireTLS(t *testing.T) {
	for _, kind := range []string{"imap", "redis"} {
		for _, scheme := range []string{kind, "http", "https", "wrong", kind + "s"} {
			instance := connectorKinds[kind]()
			err := facts.DecodeNumbers([]byte(fmt.Sprintf(`{"url":%q}`, scheme+"://example.com")), instance)
			if (err == nil) != (scheme == kind+"s") {
				t.Errorf("%s accepted %s: %v", kind, scheme, err)
			}
		}
	}
}
