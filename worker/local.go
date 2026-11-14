// Package worker launches isolated local connector processes and carries their private protocol.
package worker

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/tinfoilsh/confidential-agent-monitor/connector"
)

const maxWorkers = 32

// Local uses a deployment-owned, read-only filesystem. The running executable
// is mounted separately, so a single Monitor build includes every connector.
type Local struct {
	Root   string
	Args   []string
	mu     sync.Mutex
	active int
}

// Isolate returns a copy of kinds whose instances each run in a worker that m starts.
func (m *Local) Isolate(kinds map[string]connector.Kind) map[string]connector.Kind {
	isolated := map[string]connector.Kind{}
	for name, kind := range kinds {
		wrapped := kind
		wrapped.New = func() connector.Server { return &proxy{Kind: kind, Protocol: name, Launcher: m} }
		isolated[name] = wrapped
	}
	return isolated
}

func (m *Local) acquire() (func(), error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active >= maxWorkers {
		return nil, errors.New("connector worker limit reached")
	}
	m.active++
	return func() { m.mu.Lock(); m.active--; m.mu.Unlock() }, nil
}

func unixDial(socket string) dialFunc {
	return func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}
}

// ServeInherited adapts the local launcher's descriptors to the common server.
func ServeInherited(kinds map[string]connector.Kind) error {
	file := os.NewFile(3, "connector-listener")
	ln, err := net.FileListener(file)
	file.Close()
	if err != nil {
		return err
	}
	return serve(context.Background(), kinds, os.Stdin, ln, unixDial("/broker.sock"))
}

// start runs the same binary in the prepared root. It never decodes config. Its context
// covers installation only; the returned Endpoint owns the process lifetime.
func (m *Local) start(ctx context.Context, config []byte, broker http.Handler) (endpoint, error) {
	if err := ctx.Err(); err != nil {
		return endpoint{}, err
	}
	if m == nil || broker == nil {
		return endpoint{}, errors.New("connector worker launcher is not configured")
	}
	root, err := filepath.Abs(m.Root)
	if err != nil || m.Root == "" || root == "/" {
		return endpoint{}, errors.New("worker root must be a prepared filesystem directory")
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil || root == "/" {
		return endpoint{}, errors.New("worker root must be a prepared filesystem directory")
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return endpoint{}, errors.New("worker root directory does not exist")
	}
	release, err := m.acquire()
	if err != nil {
		return endpoint{}, err
	}
	ok := false
	defer func() {
		if !ok {
			release()
		}
	}()
	executable, err := os.Executable()
	if err != nil {
		return endpoint{}, err
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return endpoint{}, err
	}
	launcher, err := exec.LookPath("bwrap")
	if err != nil {
		return endpoint{}, errors.New("bubblewrap is required for connector workers")
	}
	directory, err := os.MkdirTemp("", "monitor-worker-")
	if err != nil {
		return endpoint{}, err
	}
	defer func() {
		if !ok {
			os.RemoveAll(directory)
		}
	}()
	apiPath, brokerPath := filepath.Join(directory, "api.sock"), filepath.Join(directory, "broker.sock")
	api, err := net.ListenUnix("unix", &net.UnixAddr{Name: apiPath, Net: "unix"})
	if err != nil {
		return endpoint{}, err
	}
	api.SetUnlinkOnClose(false)
	defer api.Close()
	file, err := api.File()
	if err != nil {
		return endpoint{}, err
	}
	defer file.Close()
	bl, err := net.Listen("unix", brokerPath)
	if err != nil {
		return endpoint{}, err
	}
	// Workers outlive setup requests.
	childCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	brokerDone := make(chan struct{})
	go func() { defer close(brokerDone); serveRPC(childCtx, bl, broker) }()
	userns := "--disable-userns"
	if value, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil && strings.TrimSpace(string(value)) == "0" {
		// The CVM already forbids nested user namespaces. Verify that restriction;
		// --disable-userns would try to create a forbidden second namespace.
		userns = "--assert-userns-disabled"
	}
	args := []string{"--unshare-all", "--unshare-user", "--die-with-parent", "--new-session", userns, "--cap-drop", "ALL", "--clearenv",
		"--ro-bind", root, "/", "--ro-bind", executable, "/worker",
		"--ro-bind", brokerPath, "/broker.sock", "--proc", "/proc", "--dev", "/dev",
		"--size", "67108864", "--tmpfs", "/tmp", "--chdir", "/tmp",
		"--remount-ro", "/dev", "--remount-ro", "/",
		"--setenv", "HOME", "/tmp", "--setenv", "TMPDIR", "/tmp", "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
		"--setenv", "GOMEMLIMIT", "256MiB", "--setenv", "GOMAXPROCS", "2", "--", "/worker"}
	cmd := exec.Command(launcher, append(args, m.Args...)...)
	cmd.Env = []string{}
	cmd.Stdin = bytes.NewReader(config)
	cmd.ExtraFiles = []*os.File{file}
	if err := cmd.Start(); err != nil {
		cancel()
		bl.Close()
		<-brokerDone
		return endpoint{}, errors.New("could not start connector worker sandbox")
	}
	done := make(chan struct{})
	c := endpoint{Context: childCtx, Dial: unixDial(apiPath), Done: done, Close: sync.OnceFunc(func() {
		cancel()
		// Killing bubblewrap also kills the worker's PID namespace.
		cmd.Process.Kill()
		bl.Close()
	})}
	go func() {
		cmd.Wait()
		c.Close()
		<-brokerDone
		os.RemoveAll(directory)
		release()
		close(done)
	}()
	ok = true
	return c, nil
}
