package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// Run the Python enrollment code against the real owner handlers and config
// validation. The CLI needs only the GET / and POST /policy/edits endpoints.
func TestVMLaunchEnrollment(t *testing.T) {
	if _, err := exec.LookPath("python3"); err != nil {
		t.Skip("python3 is required")
	}
	f := newMonitorFixture(t)
	server := httptest.NewServer(f.m.handler())
	defer server.Close()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	fixtureInput, err := json.Marshal(map[string]string{
		"url": server.URL, "owner": base64.StdEncoding.EncodeToString(f.m.owner),
		"key": string(ssh.MarshalAuthorizedKey(signer.PublicKey())), "directory": t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "python3", "-c", `
import json, pathlib, runpy, sys
m = runpy.run_path('client/monitor')
data = json.load(sys.stdin)
owner = m['OwnerClient'](data['url'], data['owner'])
state = {'name': 'vm-enrollment-test', 'enrolled': False}
path = pathlib.Path(data['directory']) / 'state.json'
access = {'web': {'level': 'allow'}}
m['enroll_identity'](owner, state, path, data['key'], access)
assert owner.request()['config']['identities'][state['name']]['accounts'] == access
owner.edit([{'path': ['identities', state['name'], 'accounts', 'web', 'level'], 'value': 'read'}])
m['enroll_identity'](owner, state, path, data['key'], access)
assert owner.request()['config']['identities'][state['name']]['accounts']['web']['level'] == 'read'
m['revoke_identity'](owner, state['name'], data['key'])
view = owner.request()['config']['identities']
assert state['name'] not in view
try:
    m['enroll_identity'](owner, state, path, data['key'], access)
except m['MonitorError'] as error:
    assert 'revoked' in str(error)
else:
    raise AssertionError('launch restored a revoked identity')
`)
	cmd.Stdin = strings.NewReader(string(fixtureInput))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Python enrollment against Monitor: %v\n%s", err, output)
	}
}

// Optional native boot: run the public CLI against the real owner and SSH
// servers. Claude --version makes no paid inference calls, but _agent must
// authenticate over vsock and obtain its model placeholder before launching it.
func TestVMNativeLaunch(t *testing.T) {
	image := os.Getenv("MONITOR_VM_IMAGE")
	if image == "" {
		t.Skip("set MONITOR_VM_IMAGE to a prepared Firecracker image")
	}
	f := newMonitorFixture(t)
	if err := f.patch(t, `{"accounts":{"model":{"preset":"web","contents":"anyone","sends":"anyone","strangers":true,"connections":{"":{"http":{"slots":[{"value":"token","origin":"https://api.anthropic.com","header":"x-api-key"}],"secrets":{"token":"fixture-model-secret"}}}}}}}`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, c := range f.m.running {
			c.cancel()
		}
		for _, c := range f.m.running {
			select {
			case <-c.done:
			case <-time.After(5 * time.Second):
				t.Error("connector cleanup timed out")
			}
		}
	}()
	server := httptest.NewServer(f.m.handler())
	defer server.Close()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	go f.m.serveSSH(listener)
	directory := t.TempDir()
	binDir := filepath.Join(directory, "bin with spaces")
	install := exec.Command("./install.sh", "--bin-dir", binDir)
	if output, err := install.CombinedOutput(); err != nil {
		t.Fatalf("install bundled client: %v\n%s", err, output)
	}
	key := filepath.Join(directory, "owner.key")
	if err := os.WriteFile(key, []byte(base64.StdEncoding.EncodeToString(f.m.owner)), 0600); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(directory, "project with spaces")
	if err := os.Mkdir(project, 0700); err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(directory, "settings", "client.json")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(ctx, filepath.Join(binDir, "monitor"), append([]string{"--client-config", config}, args...)...)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("monitor %s: %v\n%s", args[0], err, output)
		}
		return string(output)
	}
	run("setup", "--image", image, "--memory", "1024", "--owner-url", server.URL,
		"--owner-key-file", key, "--endpoint", listener.Addr().String(), "--connection", "model", "--account", "model=allow")
	for range 2 {
		output := run("launch", "--workspace", project, "claude", "--", "--version")
		if !strings.Contains(output, "Claude Code") {
			t.Fatalf("agent did not start: %s", output)
		}
	}
	run("destroy", "--workspace", project)
	for name := range f.m.live.Load().cfg.Identities {
		if strings.HasPrefix(name, "vm-") {
			t.Fatalf("destroy left an enrolled VM identity: %s", name)
		}
	}
}
