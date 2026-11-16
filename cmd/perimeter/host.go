package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"code.dny.dev/ssrf"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/config"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/connections"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/worker"
	"github.com/tinfoilsh/confidential-agent-monitor/core"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/netx"
	"golang.org/x/crypto/ssh"
)

const (
	connectorOpenTimeout = time.Minute
	maxWorkers           = 32
	workerBroker         = "/broker.sock"
	workerListenerFD     = 3
	workerTmpBytes       = "67108864"
	workerMemoryLimit    = "256MiB"
	workerMaxProcs       = "2"
)

var workerLimits = worker.Limits{Streams: 128, Upstreams: 32, Handshake: connections.DialTimeout, Credential: credentialTimeout, Sign: 10 * time.Second,
	Connections: 32, Idle: 8, PoolIdle: 30 * time.Second, Read: 10 * time.Second, ServeIdle: time.Minute, Drain: connections.RelayDrain}

func guardedDialer(allowed []netip.Prefix) *net.Dialer {
	var v4, v6 []netip.Prefix
	for _, p := range allowed {
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	guard := ssrf.New(ssrf.WithAnyPort(), ssrf.WithAllowedV4Prefixes(v4...), ssrf.WithAllowedV6Prefixes(v6...))
	return &net.Dialer{Timeout: connections.DialTimeout, Control: guard.Safe}
}

func (st *settings) client() *http.Client {
	return &http.Client{Transport: connections.UpstreamTransport(guardedDialer(st.AllowNetworks).DialContext), CheckRedirect: connections.RefuseRedirects}
}

func (s *state) opener(st *settings, c *installed) core.Open {
	dial := s.routes.RouteDial(c.Hosts, s.identities.Keys, guardedDialer(st.AllowNetworks).DialContext)
	var hostKey ssh.Signer
	if c.HostKey {
		hostKey = st.hostKey
	}
	if workers == nil {
		return func(ctx context.Context) (core.Connector, error) {
			instance, err := c.Open(ctx, worker.Host{Dial: dial, HostKey: hostKey, TLS: st.streamTLS,
				Secret:      func(ctx context.Context, name string) (string, error) { return c.secrets[name].Value(ctx) },
				Configured:  func(name string) bool { return c.secrets[name].Configured() },
				Placeholder: func(name string) string { return c.placeholders[name] },
			})
			return core.Connector{Serve: instance.Serve, Close: instance.Close, Details: instance.Details, Control: instance.Control}, err
		}
	}
	return func(ctx context.Context) (core.Connector, error) {
		data, err := json.Marshal(c.ConnectionSpec)
		if err != nil {
			return core.Connector{}, err
		}
		grants := worker.Grants{Connect: netx.Connect(netx.Dial(dial, connections.RelayDrain)), Secrets: map[string]worker.Secret{}, HostKey: hostKey,
			Certificate: func(name string) (*tls.Certificate, error) {
				return st.tls.GetCertificate(&tls.ClientHelloInfo{ServerName: name})
			}}
		for name, value := range c.secrets {
			grants.Secrets[name] = worker.Secret{Configured: value.Configured(), Placeholder: c.placeholders[name], Value: value.Value}
		}
		p, err := worker.Launch(ctx, workers.Start, data, grants, workerLimits)
		if err != nil {
			return core.Connector{}, err
		}
		return core.Connector{Serve: p.Serve, Close: p.Close, Ready: p.Ready, Details: p.Details(), Control: p.Control()}, nil
	}
}

func (st *settings) streamTLS(_ context.Context, host string) *tls.Config {
	cfg := st.tls.Clone()
	issue := cfg.GetCertificate
	cfg.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName == "" {
			named := *hello
			named.ServerName = host
			hello = &named
		}
		return issue(hello)
	}
	return cfg
}

func bubblewrap(rootDir string) *worker.Local {
	return &worker.Local{Limit: maxWorkers, Limits: workerLimits, Command: func(broker string) (*exec.Cmd, error) {
		root, err := filepath.Abs(rootDir)
		if err != nil || rootDir == "" || root == "/" {
			return nil, errors.New("worker root must be a prepared filesystem directory")
		}
		root, err = filepath.EvalSymlinks(root)
		if err != nil || root == "/" {
			return nil, errors.New("worker root must be a prepared filesystem directory")
		}
		if info, err := os.Stat(root); err != nil || !info.IsDir() {
			return nil, errors.New("worker root directory does not exist")
		}
		executable, err := os.Executable()
		if err == nil {
			executable, err = filepath.Abs(executable)
		}
		if err != nil {
			return nil, err
		}
		launcher, err := exec.LookPath("bwrap")
		if err != nil {
			return nil, errors.New("bubblewrap is required for connector workers")
		}
		userns := "--disable-userns"
		if value, err := os.ReadFile("/proc/sys/kernel/unprivileged_userns_clone"); err == nil && strings.TrimSpace(string(value)) == "0" {
			userns = "--assert-userns-disabled"
		}
		cmd := exec.Command(launcher, "--unshare-all", "--unshare-user", "--die-with-parent", "--new-session", userns, "--cap-drop", "ALL", "--clearenv",
			"--ro-bind", root, "/", "--ro-bind", executable, "/worker",
			"--ro-bind", broker, workerBroker, "--proc", "/proc", "--dev", "/dev",
			"--size", workerTmpBytes, "--tmpfs", "/tmp", "--chdir", "/tmp",
			"--remount-ro", "/dev", "--remount-ro", "/",
			"--setenv", "HOME", "/tmp", "--setenv", "TMPDIR", "/tmp", "--setenv", "PATH", "/usr/local/bin:/usr/bin:/bin",
			"--setenv", "GOMEMLIMIT", workerMemoryLimit, "--setenv", "GOMAXPROCS", workerMaxProcs, "--", "/worker", "--"+serveWorkerFlag)
		cmd.Env = []string{}
		return cmd, nil
	}}
}
func serveWorkerChild() error {
	file := os.NewFile(workerListenerFD, "connector-listener")
	ln, err := net.FileListener(file)
	file.Close()
	if err != nil {
		return err
	}
	broker := func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", workerBroker)
	}
	return worker.Serve(context.Background(), func(ctx context.Context, data json.RawMessage, h worker.Host) (worker.Instance, error) {
		var spec config.ConnectionSpec
		if err := json.Unmarshal(data, &spec); err != nil {
			return worker.Instance{}, err
		}
		p, err := connections.Parse(spec)
		if err != nil {
			return worker.Instance{}, err
		}
		return p.Open(ctx, h)
	}, os.Stdin, ln, broker, workerLimits)
}
