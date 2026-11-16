// Local manual connector tests. Service credentials arrive only through stdin.
// This runs the shipped presets and real connector with a test-controlled gate.
package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"code.dny.dev/ssrf"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/catalog"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/credential"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/slots"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/web"
	"github.com/tinfoilsh/confidential-agent-monitor/core/certificates"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/netx"
)

type input struct {
	Service      string `json:"service"`
	BotToken     string `json:"bot_token"`
	AppToken     string `json:"app_token"`
	Channel      string `json:"channel"`
	PostTest     bool   `json:"post_test"`
	GrafanaURL   string `json:"grafana_url"`
	GrafanaToken string `json:"grafana_token"`
}

type liveConnection struct {
	preset  string
	handler web.Handler
	hash    string
}

func prepare(tlsConfig func(context.Context, string) *tls.Config, transport http.RoundTripper, name, credentialName, secret, placeholder, origin string) (*liveConnection, error) {
	raw, err := os.ReadFile(filepath.Join("cmd", "perimeter", "presets", name+".json"))
	if err != nil {
		return nil, err
	}
	p, err := catalog.Decode(raw)
	if err != nil {
		return nil, err
	}
	config := p.Catalog.Connection["http"]
	var options json.RawMessage
	if origin != "" {
		if !slots.ValidOrigin(origin) {
			return nil, errors.New("test destination must be an HTTPS origin")
		}
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(config, &fields); err != nil {
			return nil, err
		}
		var placements []slots.Slot
		if err := json.Unmarshal(fields["slots"], &placements); err != nil {
			return nil, err
		}
		if len(placements) != 1 || placements[0].Value != credentialName {
			return nil, errors.New("unexpected origin setup")
		}
		placements[0].Origin = origin
		fields["slots"], err = json.Marshal(placements)
		if err != nil {
			return nil, err
		}
		config, err = json.Marshal(fields)
		if err != nil {
			return nil, err
		}
		options, err = json.Marshal(map[string]string{"origin": origin})
		if err != nil {
			return nil, err
		}
	}
	setup, err := web.Parse(config, p.Source, options, func(raw json.RawMessage) (web.Slots, error) {
		set, err := slots.Parse(raw, slots.Options{Prefix: "tfm_", MaxSignedBody: 16 << 20})
		return web.Slots{Claim: set.Claim, Covers: set.Covers, Bind: set.Bind}, err
	})
	if err != nil {
		return nil, err
	}
	value := new(credential.Value)
	if secret != "" {
		value = credential.Static(secret)
	}
	handler := web.Handler{Setup: setup, Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are refused") }, UpstreamReadLimit: -1, MaxBody: 8 << 20, TLS: tlsConfig, ServeHTTP: netx.ServeConn,
		Placeholder: func(name string) string {
			if name == credentialName && value.Configured() {
				return placeholder
			}
			return ""
		},
		Secret: func(ctx context.Context, name string) (string, error) {
			if name != credentialName {
				return "", errors.New("credential is not declared")
			}
			return value.Value(ctx)
		},
	}
	return &liveConnection{preset: name, handler: handler, hash: fmt.Sprintf("%x", sha256.Sum256(p.Source))}, nil
}

func proxyAuthenticated(r *http.Request, expected string) bool {
	values := r.Header.Values("Proxy-Authorization")
	return len(values) == 1 && subtle.ConstantTimeCompare([]byte(values[0]), []byte(expected)) == 1
}

func testAuthOperation(id string) bool {
	return id == "auth.test" || id == "auth.test.form" || id == "auth_test"
}

func main() {
	// Connector and HTTP errors can contain user input. Emit only our own fixed status.
	log.SetOutput(io.Discard)
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL: local connector harness stopped; no credential details printed")
		os.Exit(1)
	}
}
func run() error {
	var in input
	decoder := json.NewDecoder(io.LimitReader(os.Stdin, 64<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&in); err != nil {
		return err
	}
	authority, err := certificates.NewAuthority("Monitor local manual test only", 2*time.Hour)
	if err != nil {
		return err
	}
	tlsConfig := func(_ context.Context, host string) *tls.Config {
		return &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			name := hello.ServerName
			if name == "" {
				name = host
			}
			return authority.Issue(name, 24*time.Hour, time.Hour)
		}}
	}
	guard := ssrf.New(ssrf.WithAnyPort())
	dialer := &net.Dialer{Timeout: 30 * time.Second, Control: guard.Safe}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = dialer.DialContext
	defer transport.CloseIdleConnections()
	var bot, socket, grafana *liveConnection
	switch in.Service {
	case "", "slack":
		if !strings.HasPrefix(in.BotToken, "xoxb-") || !strings.HasPrefix(in.AppToken, "xapp-") {
			return errors.New("wrong token types")
		}
		bot, err = prepare(tlsConfig, transport, "slack", "token", in.BotToken, "tfm_live_slack_bot", "")
		if err != nil {
			return err
		}
		socket, err = prepare(tlsConfig, transport, "slack_socket_mode", "token", in.AppToken, "tfm_live_slack_socket", "")
	case "grafana":
		if !slots.ValidOrigin(in.GrafanaURL) {
			return errors.New("Grafana requires an HTTPS origin")
		}
		grafana, err = prepare(tlsConfig, transport, "grafana", "api_key", in.GrafanaToken, "tfm_manual_grafana", in.GrafanaURL)
	default:
		return errors.New("unknown manual test service")
	}
	if err != nil {
		return err
	}
	grafanaConfigured := in.GrafanaToken != ""
	in.BotToken, in.AppToken, in.GrafanaToken = "", "", ""
	caPEM, _ := authority.PEM()
	dir, err := os.MkdirTemp("", "monitor-manual-test-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	certFile := filepath.Join(dir, "public-ca.pem")
	if err := os.WriteFile(certFile, []byte(caPEM), 0600); err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	var output sync.Mutex
	status := func(text string) { output.Lock(); defer output.Unlock(); fmt.Fprintln(os.Stderr, text) }
	var active sync.WaitGroup
	var posted atomic.Bool
	start := func(connection *liveConnection) (string, error) {
		var nonce [32]byte
		if _, err := rand.Read(nonce[:]); err != nil {
			return "", err
		}
		password := base64.RawURLEncoding.EncodeToString(nonce[:])
		expected := "Basic " + base64.StdEncoding.EncodeToString([]byte("monitor:"+password))
		listener, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			return "", err
		}
		gate := func(_ context.Context, event facts.Event) error {
			f, err := event.Decode()
			if err != nil || f.Operation == nil {
				status("BLOCKED: request did not match the reviewed preset")
				return errors.New("unrecognized request")
			}
			allowed := false
			if connection.preset == "slack_socket_mode" {
				allowed = f.Operation.Action == "connect" || f.Operation.Action == "receive" || f.Operation.Action == "respond"
			} else if connection.preset == "grafana" {
				allowed = f.Operation.ID == "getHealth" || f.Operation.ID == "search"
			} else {
				allowed = testAuthOperation(f.Operation.ID)
				if in.PostTest && f.Operation.ID == "chat.postMessage" && f.Parameters["channel"] == in.Channel {
					allowed = posted.CompareAndSwap(false, true)
				}
			}
			if !allowed {
				status("BLOCKED: operation outside this test's allowlist")
				return errors.New("operation not in test allowlist")
			}
			// IDs come from shipped definitions, never from payloads or query strings.
			status("ADMITTED " + connection.preset + " " + f.Operation.ID)
			return nil
		}
		connect := netx.Connect(func(ctx context.Context, host string, port uint32, accept func() (net.Conn, error)) error {
			if connection.handler.Setup.Claim(host, port) < 0 {
				return errors.New("this service does not serve the target")
			}
			conn, err := accept()
			if err == nil {
				connection.handler.Serve(ctx, conn, connection.preset, host, port, gate)
			}
			return err
		})
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !proxyAuthenticated(r, expected) {
				w.Header().Set("Proxy-Authenticate", `Basic realm="monitor-slack-test"`)
				http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
				return
			}
			if _, port, _ := net.SplitHostPort(r.Host); port == "80" {
				http.Error(w, "destination refused", http.StatusForbidden)
				status("BLOCKED: unrecognized CONNECT destination")
				return
			}
			active.Add(1)
			defer active.Done()
			connect.ServeHTTP(w, r)
		})
		server := &http.Server{Handler: handler, BaseContext: func(net.Listener) context.Context { return ctx }, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: time.Minute, ErrorLog: log.New(io.Discard, "", 0)}
		go func() { <-ctx.Done(); server.Close() }()
		go server.Serve(listener)
		// Delivered only over the supervisor's private pipe, never printed in status.
		return "http://monitor:" + password + "@" + listener.Addr().String(), nil
	}
	ready := map[string]any{"service": in.Service, "ca_file": certFile}
	if grafana != nil {
		proxy, err := start(grafana)
		if err != nil {
			stop()
			return err
		}
		ready["grafana_proxy"], ready["grafana_origin"] = proxy, in.GrafanaURL
		ready["grafana_sha256"], ready["grafana_configured"] = grafana.hash, grafanaConfigured
	} else {
		botProxy, err := start(bot)
		if err != nil {
			stop()
			return err
		}
		socketProxy, err := start(socket)
		if err != nil {
			stop()
			return err
		}
		ready["bot_proxy"], ready["socket_proxy"] = botProxy, socketProxy
		ready["slack_sha256"], ready["socket_sha256"] = bot.hash, socket.hash
	}
	if err := json.NewEncoder(os.Stdout).Encode(ready); err != nil {
		stop()
		return err
	}
	<-ctx.Done()
	active.Wait()
	return nil
}
