// Local manual connector tests. Service credentials arrive only through stdin.
// This runs the shipped presets and real connector, not Monitor's policy engine.
package main

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/connector/web"
	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/presets"
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

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c bufferedConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

type authority struct {
	certificate *x509.Certificate
	private     ed25519.PrivateKey
	pem         []byte
}

func newAuthority() (*authority, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: "Monitor local manual test only"}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(2 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, root, root, public, private)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &authority{cert, private, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}, nil
}
func (a *authority) leaf(host string) (tls.Certificate, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	leaf := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), DNSNames: []string{host}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, leaf, a.certificate, public, a.private)
	if err != nil {
		return tls.Certificate{}, err
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}, nil
}

type liveConnection struct {
	preset string
	server *web.Server
	setup  *web.Setup
	hash   string
}

func prepare(name, credentialName, secret, placeholder, origin string) (*liveConnection, error) {
	shipped, err := presets.Shipped()
	if err != nil {
		return nil, err
	}
	p := shipped[name]
	if p == nil {
		return nil, errors.New("missing shipped preset")
	}
	source := connector.Setup{Config: p.Catalog.Connection["http"], Definition: p.Source}
	if origin != "" {
		if !web.ValidOrigin(origin) {
			return nil, errors.New("test destination must be an HTTPS origin")
		}
		// Apply the same origin setup as the catalog form; keep definitions intact.
		var config map[string]json.RawMessage
		if err := json.Unmarshal(source.Config, &config); err != nil {
			return nil, err
		}
		var slots []web.Slot
		if err := json.Unmarshal(config["slots"], &slots); err != nil {
			return nil, err
		}
		if len(slots) != 1 || slots[0].Value != credentialName {
			return nil, errors.New("unexpected origin setup")
		}
		slots[0].Origin = origin
		config["slots"], err = json.Marshal(slots)
		if err != nil {
			return nil, err
		}
		source.Config, err = json.Marshal(config)
		if err != nil {
			return nil, err
		}
		source.Options, err = json.Marshal(map[string]string{"Origin": origin})
		if err != nil {
			return nil, err
		}
	}
	prepared, err := web.Parse(source)
	if err != nil {
		return nil, err
	}
	values := map[string]*credential.Value{}
	if secret != "" {
		raw, err := json.Marshal(secret)
		if err != nil {
			return nil, err
		}
		defer clear(raw)
		v := new(credential.Value)
		if err := json.Unmarshal(raw, v); err != nil {
			return nil, err
		}
		v.Placeholder = placeholder
		values[credentialName] = v
	}
	server := new(web.Server)
	if err := server.Update(context.Background(), prepared, values, nil); err != nil {
		return nil, err
	}
	return &liveConnection{name, server, prepared.Value.(*web.Setup), fmt.Sprintf("%x", sha256.Sum256(p.Source))}, nil
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
	var bot, socket, grafana *liveConnection
	var err error
	switch in.Service {
	case "", "slack":
		if !strings.HasPrefix(in.BotToken, "xoxb-") || !strings.HasPrefix(in.AppToken, "xapp-") {
			return errors.New("wrong token types")
		}
		bot, err = prepare("slack", "token", in.BotToken, "tfm_live_slack_bot", "")
		if err != nil {
			return err
		}
		socket, err = prepare("slack_socket_mode", "token", in.AppToken, "tfm_live_slack_socket", "")
	case "grafana":
		if !web.ValidOrigin(in.GrafanaURL) {
			return errors.New("Grafana requires an HTTPS origin")
		}
		grafana, err = prepare("grafana", "api_key", in.GrafanaToken, "tfm_manual_grafana", in.GrafanaURL)
	default:
		return errors.New("unknown manual test service")
	}
	if err != nil {
		return err
	}
	grafanaConfigured := in.GrafanaToken != ""
	in.BotToken, in.AppToken, in.GrafanaToken = "", "", ""
	ca, err := newAuthority()
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "monitor-manual-test-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	certFile := filepath.Join(dir, "public-ca.pem")
	if err := os.WriteFile(certFile, ca.pem, 0600); err != nil {
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
		handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !proxyAuthenticated(r, expected) {
				w.Header().Set("Proxy-Authenticate", `Basic realm="monitor-slack-test"`)
				http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
				return
			}
			host, port, err := net.SplitHostPort(r.Host)
			number, portErr := strconv.ParseUint(port, 10, 16)
			if r.Method != "CONNECT" || err != nil || portErr != nil || number == 0 || number == 80 || strconv.FormatUint(number, 10) != port || connection.setup.Claim(host, uint32(number)) < 0 {
				http.Error(w, "destination refused", http.StatusForbidden)
				status("BLOCKED: unrecognized CONNECT destination")
				return
			}
			cert, err := ca.leaf(host)
			if err != nil {
				http.Error(w, "local TLS setup failed", 500)
				return
			}
			raw, rw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			active.Add(1)
			defer active.Done()
			stream := connector.NewStream(ctx, bufferedConn{raw, rw.Reader})
			defer stream.Close()
			if _, err := io.WriteString(raw, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
				return
			}
			stream.Host, stream.Port = host, uint32(number)
			stream.Gate = func(_ context.Context, event facts.Event) error {
				f, err := event.Facts()
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
			env := &connector.Env{TLS: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}, Dialer: connector.NewDialer(nil)}
			connection.server.Serve(stream, env)
		})
		server := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, IdleTimeout: time.Minute, ErrorLog: log.New(io.Discard, "", 0)}
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
