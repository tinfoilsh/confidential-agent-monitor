// Package worker owns local process launch and sandbox setup.
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
	"time"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/rpc"
)

const maxWorkers = 32

// Local uses a deployment-owned, read-only filesystem. The running executable
// is mounted separately, so a single Monitor build includes every connector.
type Local struct {
	Root       string
	Sandbox    string
	Executable string // Defaults to os.Executable.
	mu         sync.Mutex
	active     int
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

func unixDial(socket string) rpc.DialFunc {
	return func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}
}

// ServeInherited adapts the local launcher's descriptors to the common server.
func ServeInherited(definitions map[string]connector.Definition) error {
	file := os.NewFile(3, "connector-listener")
	ln, err := net.FileListener(file)
	file.Close()
	if err != nil {
		return err
	}
	return rpc.Serve(context.Background(), definitions, os.Stdin, ln, unixDial("/broker.sock"))
}

// Start runs the same binary in the prepared root. It never decodes config.
func (m *Local) Start(ctx context.Context, config []byte, host http.Handler) (rpc.Endpoint, error) {
	if m == nil || host == nil {
		return rpc.Endpoint{}, errors.New("connector worker launcher is not configured")
	}
	root, err := filepath.Abs(m.Root)
	if err != nil || m.Root == "" || root == "/" {
		return rpc.Endpoint{}, errors.New("worker root must be a prepared filesystem directory")
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil || root == "/" {
		return rpc.Endpoint{}, errors.New("worker root must be a prepared filesystem directory")
	}
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		return rpc.Endpoint{}, errors.New("worker root directory does not exist")
	}
	release, err := m.acquire()
	if err != nil {
		return rpc.Endpoint{}, err
	}
	ok := false
	defer func() {
		if !ok {
			release()
		}
	}()
	executable := m.Executable
	if executable == "" {
		executable, err = os.Executable()
		if err != nil {
			return rpc.Endpoint{}, err
		}
	}
	executable, err = filepath.Abs(executable)
	if err != nil {
		return rpc.Endpoint{}, err
	}
	sandbox := m.Sandbox
	if sandbox == "" {
		sandbox = "bwrap"
	}
	launcher, err := exec.LookPath(sandbox)
	if err != nil {
		return rpc.Endpoint{}, errors.New("bubblewrap is required for connector workers")
	}
	directory, err := os.MkdirTemp("", "monitor-worker-")
	if err != nil {
		return rpc.Endpoint{}, err
	}
	defer func() {
		if !ok {
			os.RemoveAll(directory)
		}
	}()
	apiPath, brokerPath := filepath.Join(directory, "api.sock"), filepath.Join(directory, "broker.sock")
	api, err := net.ListenUnix("unix", &net.UnixAddr{Name: apiPath, Net: "unix"})
	if err != nil {
		return rpc.Endpoint{}, err
	}
	api.SetUnlinkOnClose(false)
	defer api.Close()
	file, err := api.File()
	if err != nil {
		return rpc.Endpoint{}, err
	}
	defer file.Close()
	bl, err := net.Listen("unix", brokerPath)
	if err != nil {
		return rpc.Endpoint{}, err
	}
	childCtx, cancel := context.WithCancel(ctx)
	server := &http.Server{Handler: host, ReadHeaderTimeout: 10 * time.Second, MaxHeaderBytes: 8 << 10, BaseContext: func(net.Listener) context.Context { return childCtx }}
	go server.Serve(bl)
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
		"--setenv", "GOMEMLIMIT", "256MiB", "--setenv", "GOMAXPROCS", "2", "--", "/worker", "--connector-worker"}
	cmd := exec.Command(launcher, args...)
	cmd.Env = []string{}
	cmd.Stdin = bytes.NewReader(config)
	cmd.ExtraFiles = []*os.File{file}
	if err := cmd.Start(); err != nil {
		cancel()
		server.Close()
		return rpc.Endpoint{}, errors.New("could not start connector worker sandbox")
	}
	done := make(chan struct{})
	c := rpc.Endpoint{Dial: unixDial(apiPath), Done: done, Close: sync.OnceFunc(func() {
		cancel()
		// Killing bubblewrap also kills the worker's PID namespace.
		cmd.Process.Kill()
		server.Close()
	})}
	stop := context.AfterFunc(ctx, c.Close)
	go func() {
		cmd.Wait()
		c.Close()
		stop()
		os.RemoveAll(directory)
		release()
		close(done)
	}()
	ok = true
	return c, nil
}
