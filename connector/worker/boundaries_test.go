package worker_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/connector/worker"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

const brokerSocket = "/broker.sock"

var (
	limits = worker.Limits{Streams: 128, Upstreams: 32, Handshake: 30 * time.Second, Credential: 30 * time.Second, Sign: 10 * time.Second,
		Connections: 32, Idle: 8, PoolIdle: 30 * time.Second, Read: 10 * time.Second, ServeIdle: time.Minute, Drain: time.Second}
)

// fixture gates one operation, then reports what the host's grants let it learn.
func fixture(_ context.Context, data json.RawMessage, host worker.Host) (worker.Instance, error) {
	var want string
	if err := json.Unmarshal(data, &want); err != nil || want != "fixture" {
		return worker.Instance{}, fmt.Errorf("worker lost its data: %s", data)
	}
	return worker.Instance{Serve: func(ctx context.Context, conn net.Conn, name, _ string, _ uint32, gate func(context.Context, facts.Event) error) {
		if gate(ctx, facts.Capture(facts.Observation{Operation: &facts.Operation{ID: name, Action: "fixture"}}, nil)) != nil {
			io.WriteString(conn, "refused")
			return
		}
		granted, err := host.Secret(ctx, "granted")
		_, missing := host.Secret(ctx, "missing")
		fmt.Fprintf(conn, "approved %s %v %s %v %v %v", granted, err, host.Placeholder("granted"), host.Configured("granted"), missing != nil, host.HostKey == nil)
	}}, nil
}

func TestWorkerChild(t *testing.T) {
	if os.Args[len(os.Args)-1] != "worker-child" {
		return
	}
	file := os.NewFile(3, "connector-listener")
	ln, err := net.FileListener(file)
	file.Close()
	if err != nil {
		t.Fatal(err)
	}
	broker := func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", brokerSocket)
	}
	if err := worker.Serve(context.Background(), fixture, os.Stdin, ln, broker, limits); err != nil {
		t.Fatal(err)
	}
}

// The deployment backend needs user namespaces and a static test executable:
// CGO_ENABLED=0 PERIMETER_TEST_WORKERS=1 go test ./worker
func TestIsolatedWorkerGateAndGrants(t *testing.T) {
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
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	local := &worker.Local{Limit: 32, Limits: limits, Command: func(broker string) (*exec.Cmd, error) {
		userns := "--disable-userns"
		if value, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil && strings.TrimSpace(string(value)) == "0" {
			userns = "--assert-userns-disabled"
		}
		cmd := exec.Command("bwrap", "--unshare-all", "--unshare-user", "--die-with-parent", "--new-session", userns, "--cap-drop", "ALL", "--clearenv",
			"--ro-bind", root, "/", "--ro-bind", executable, "/worker", "--ro-bind", broker, brokerSocket, "--proc", "/proc", "--dev", "/dev",
			"--tmpfs", "/tmp", "--chdir", "/tmp", "--remount-ro", "/dev", "--remount-ro", "/",
			"--", "/worker", "-test.run=^TestWorkerChild$", "--", "worker-child")
		cmd.Env = []string{}
		return cmd, nil
	}}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	grants := worker.Grants{
		Connect: http.NotFoundHandler(),
		Secrets: map[string]worker.Secret{"granted": {Configured: true, Placeholder: "tfm_granted", Value: func(context.Context) (string, error) { return "value", nil }}},
	}
	process, err := worker.Launch(ctx, local.Start, json.RawMessage(`"fixture"`), grants, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer process.Close()
	serve := func(gate func(context.Context, facts.Event) error) string {
		host, client := net.Pipe()
		defer client.Close()
		client.SetDeadline(time.Now().Add(5 * time.Second))
		done := make(chan struct{})
		go func() { defer close(done); process.Serve(ctx, host, "fixture", "", 80, gate) }()
		response, err := io.ReadAll(client)
		if err != nil {
			t.Fatal(err)
		}
		<-done
		return string(response)
	}
	gated := make(chan facts.Event, 1)
	response := serve(func(_ context.Context, e facts.Event) error { gated <- e; return nil })
	if response != "approved value <nil> tfm_granted true true true" {
		t.Fatalf("worker response: %q", response)
	}
	select {
	case e := <-gated:
		o, err := e.Decode()
		if err != nil || o.Operation.ID != "fixture" {
			t.Fatalf("event: %+v, %v", o, err)
		}
	default:
		t.Fatal("worker bypassed host gate")
	}
	if response := serve(func(context.Context, facts.Event) error { return errors.New("denied") }); response != "refused" {
		t.Fatalf("denied gate: worker response %q", response)
	}
}
