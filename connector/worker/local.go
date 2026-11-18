package worker

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"

	"github.com/tinfoilsh/confidential-agent-monitor/core/connector"
)

// Start hands the child its listener as its first extra file.
const listenerFD = 3

type Local struct {
	Limit   int
	Command func(broker string) (*exec.Cmd, error)
	Limits  Limits
	mu      sync.Mutex
	active  int
}

func (m *Local) acquire() (func(), error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.active >= m.Limit {
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

func (m *Local) Start(ctx context.Context, config []byte, broker http.Handler) (Endpoint, error) {
	if err := ctx.Err(); err != nil {
		return Endpoint{}, err
	}
	release, err := m.acquire()
	if err != nil {
		return Endpoint{}, err
	}
	ok := false
	defer func() {
		if !ok {
			release()
		}
	}()
	directory, err := os.MkdirTemp("", "monitor-worker-")
	if err != nil {
		return Endpoint{}, err
	}
	defer func() {
		if !ok {
			os.RemoveAll(directory)
		}
	}()
	apiPath, brokerPath := filepath.Join(directory, "api.sock"), filepath.Join(directory, "broker.sock")
	api, err := net.ListenUnix("unix", &net.UnixAddr{Name: apiPath, Net: "unix"})
	if err != nil {
		return Endpoint{}, err
	}
	api.SetUnlinkOnClose(false)
	defer api.Close()
	file, err := api.File()
	if err != nil {
		return Endpoint{}, err
	}
	defer file.Close()
	bl, err := net.Listen("unix", brokerPath)
	if err != nil {
		return Endpoint{}, err
	}
	cmd, err := m.Command(brokerPath)
	if err != nil {
		bl.Close()
		return Endpoint{}, err
	}
	childCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	brokerDone := make(chan struct{})
	go func() { defer close(brokerDone); serveRPC(childCtx, bl, broker, m.Limits) }()
	cmd.Stdin = bytes.NewReader(config)
	cmd.ExtraFiles = []*os.File{file}
	if err := cmd.Start(); err != nil {
		cancel()
		bl.Close()
		<-brokerDone
		return Endpoint{}, errors.New("could not start connector worker sandbox")
	}
	done := make(chan struct{})
	c := Endpoint{Context: childCtx, Dial: unixDial(apiPath), Done: done, Close: sync.OnceFunc(func() {
		cancel()
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

func ServeLocal(ctx context.Context, factory func(ctx context.Context, data json.RawMessage, host Host) (connector.Instance, error), broker string, limits Limits) error {
	file := os.NewFile(listenerFD, "connector-listener")
	ln, err := net.FileListener(file)
	file.Close()
	if err != nil {
		return err
	}
	return Serve(ctx, factory, os.Stdin, ln, unixDial(broker), limits)
}
