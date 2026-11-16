package worker_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/worker"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

func fixtureKinds() map[string]connector.Kind {
	return map[string]connector.Kind{"fixture": {
		Parse: func(s connector.Setup) (connector.Prepared, error) {
			if !s.Vocabulary.ValidEffects([]string{"fixture"}) {
				return connector.Prepared{}, fmt.Errorf("worker lost vocabulary")
			}
			return connector.Prepared{}, nil
		},
		Open: func(context.Context, connector.Prepared, map[string]connector.Secret, *connector.Env) (connector.Handler, error) {
			return connector.HandlerFunc(func(s *connector.Stream) {
				if s.Gate(s.Context, facts.Capture(facts.Facts{Operation: &facts.Operation{ID: "fixture", Action: "fixture", Effects: []string{"fixture"}}}, nil)) == nil {
					io.WriteString(s, "approved")
				}
			}), nil
		},
	}}
}

func TestWorkerChild(t *testing.T) {
	if os.Args[len(os.Args)-1] != "worker-child" {
		return
	}
	if err := worker.ServeChild(fixtureKinds()); err != nil {
		t.Fatal(err)
	}
}

// The deployment backend needs user namespaces and a static test executable:
// CGO_ENABLED=0 PERIMETER_TEST_WORKERS=1 go test ./connector/worker
func TestIsolatedWorkerVocabularyAndGate(t *testing.T) {
	if os.Getenv("PERIMETER_TEST_WORKERS") != "1" {
		t.Skip("requires bubblewrap user namespaces; opt in with PERIMETER_TEST_WORKERS=1")
	}
	root := t.TempDir()
	for _, dir := range []string{"dev", "proc", "tmp"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"worker", "broker.sock"} {
		if err := os.WriteFile(filepath.Join(root, name), nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	kinds := worker.Isolate(&worker.Local{Root: root, Args: []string{"-test.run=^TestWorkerChild$", "--", "worker-child"}}, fixtureKinds())
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	vocabulary := facts.Vocabulary{Effects: map[string]facts.Obligations{"fixture": {}}}
	instance, err := connector.Start(ctx, kinds["fixture"], connector.Setup{Config: json.RawMessage(`{}`), Definition: json.RawMessage(`{}`), Options: json.RawMessage(`{}`), Vocabulary: vocabulary}, nil, &connector.Env{Dialer: &net.Dialer{}})
	if err != nil {
		t.Fatal(err)
	}
	defer instance.Close()
	host, client := net.Pipe()
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	gated := make(chan facts.Event, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		instance.Serve(ctx, host, "fixture", "", 80, func(_ context.Context, e facts.Event) error { gated <- e; return nil })
	}()
	response, err := io.ReadAll(client)
	if err != nil {
		t.Fatal(err)
	}
	if string(response) != "approved" {
		t.Fatalf("worker response: %q", response)
	}
	select {
	case e := <-gated:
		f, err := e.Facts()
		if err != nil || f.Operation.ID != "fixture" {
			t.Fatalf("event: %+v, %v", f, err)
		}
	default:
		t.Fatal("worker bypassed host gate")
	}
	<-done
}
