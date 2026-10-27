package worker

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/facts"
	"golang.org/x/crypto/ssh"
)

const (
	maxStreams             = 128
	maxUpstreamConnections = 32
)

// Endpoint owns one actual process. Context ends when it stops; Done closes
// after process and broker callbacks have joined. Close is safe to repeat.
type Endpoint struct {
	Context context.Context
	Dial    DialFunc
	Done    <-chan struct{}
	Close   func()
}

// Start uses its context for installation. A returned Endpoint owns its lifetime
// independently; canceling installation after success must not stop the process.
type Launcher interface {
	Start(context.Context, []byte, http.Handler) (Endpoint, error)
}

// Proxy is stable across setup changes. Update and Close are serialized by its
// owner; calls already handed off retain their original process capabilities.
type Proxy struct {
	Protocol string
	Kind     connector.Kind
	Launcher Launcher
	mu       sync.Mutex
	current  *process
}

type process struct {
	Endpoint
	env         *connector.Env
	usesHostKey bool
	secrets     map[string]*credential.Value
	transport   *http.Transport
	details     json.RawMessage
	mu          sync.Mutex
	next        uint64
	streams     map[string]*connector.Stream
}

func (p *Proxy) Update(ctx context.Context, prepared connector.Prepared, secrets map[string]*credential.Value, env *connector.Env) error {
	p.Close()
	if p.Launcher == nil || env.Dialer == nil {
		return errors.New("connector worker is not configured")
	}
	settings, err := json.Marshal(p.Kind.Settings)
	if err != nil {
		return err
	}
	boot := bootstrap{Setup: prepared.Source, Version: protocolVersion, Protocol: p.Protocol, Settings: settings, Secrets: map[string]secretHandle{}}
	for name, value := range secrets {
		boot.Secrets[name] = secretHandle{len(value.Raw()) > 0, value.Placeholder}
	}
	if p.Kind.UsesHostKey && env.HostKey != nil {
		boot.HostKey = env.HostKey.PublicKey().Marshal()
	}
	raw, err := json.Marshal(boot)
	if err != nil {
		return err
	}
	if len(raw) > maxMessage {
		return errors.New("worker configuration exceeds size limit")
	}
	running := &process{env: env, usesHostKey: p.Kind.UsesHostKey, secrets: maps.Clone(secrets), streams: map[string]*connector.Stream{}}
	running.Endpoint, err = p.Launcher.Start(ctx, raw, running.broker())
	if err != nil {
		return err
	}
	running.transport = running.Dial.Transport()
	ready, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	err = call(ready, running.transport, readyPath, nil, &running.details)
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		running.close()
		return fmt.Errorf("connector worker startup: %w", err)
	}
	if string(running.details) == "null" {
		running.details = nil
	}
	p.mu.Lock()
	p.current = running
	p.mu.Unlock()
	return nil
}

func (p *Proxy) snapshot() *process { p.mu.Lock(); defer p.mu.Unlock(); return p.current }

func (p *Proxy) Ready() error {
	running := p.snapshot()
	if running == nil {
		return errors.New("connector worker is unavailable")
	}
	return running.Context.Err()
}

func (p *Proxy) Close() error {
	p.mu.Lock()
	running := p.current
	p.current = nil
	p.mu.Unlock()
	if running != nil {
		running.close()
	}
	return nil
}

func (p *process) close() {
	p.Endpoint.Close()
	<-p.Done
	p.transport.CloseIdleConnections()
}

func (p *Proxy) Serve(s *connector.Stream, _ *connector.Env) {
	defer s.Close()
	running := p.snapshot()
	if running == nil {
		return
	}
	ctx, cancel := connector.Bind(s.Context, running.Context)
	defer cancel()
	running.mu.Lock()
	if ctx.Err() != nil || len(running.streams) >= maxStreams {
		running.mu.Unlock()
		return
	}
	running.next++
	id := fmt.Sprint(running.next)
	running.streams[id] = s
	running.mu.Unlock()
	defer func() { running.mu.Lock(); delete(running.streams, id); running.mu.Unlock() }()
	raw, _ := json.Marshal(streamInfo{id, s.Name, s.Host, s.Port})
	header := http.Header{streamHeader: {base64.RawStdEncoding.EncodeToString(raw)}, "Connection": {"Upgrade"}, "Upgrade": {"monitor-connector"}}
	request := &http.Request{Method: "GET", URL: &url.URL{Path: "/stream"}, Host: "worker", Header: header}
	upstream, err := connect(ctx, running.Dial, request, http.StatusSwitchingProtocols)
	if err != nil {
		return
	}
	connector.Relay(ctx, s.Conn, upstream)
}

func (p *Proxy) Details() json.RawMessage {
	if running := p.snapshot(); running != nil {
		return running.details
	}
	return nil
}

func (p *Proxy) Control() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		running := p.snapshot()
		if running == nil {
			http.Error(w, "connector worker is unavailable", 503)
			return
		}
		ctx, cancel := connector.Bind(r.Context(), running.Context)
		defer cancel()
		proxy := httputil.ReverseProxy{Transport: running.transport, Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme, r.Out.URL.Host, r.Out.Host = "http", "connector", "connector"
			r.Out.URL.Path = "/control" + r.Out.URL.Path
			r.Out.URL.RawPath = ""
			// Monitor authenticates controls; they carry no stream authority.
			for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie", streamHeader} {
				r.Out.Header.Del(name)
			}
		}, FlushInterval: -1}
		proxy.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (p *process) broker() http.Handler {
	mux := http.NewServeMux()
	// These capabilities belong to the connection, including setup and owner controls.
	mux.Handle("POST /credential/{name}", callback(func(ctx context.Context, r *http.Request, _ []byte) (any, error) {
		return p.credential(ctx, r.PathValue("name"))
	}))
	mux.Handle("POST /host-sign", callback(func(_ context.Context, _ *http.Request, raw []byte) (any, error) {
		return p.signHost(raw)
	}))
	// These operations additionally require a live stream admitted by the host.
	mux.Handle("POST /gate/{stream}", p.streamCallback(func(ctx context.Context, stream *connector.Stream, raw []byte) (any, error) {
		return nil, stream.Gate(ctx, facts.Event(raw))
	}))
	mux.Handle("POST /certificate/{stream}", p.streamCallback(p.certificate))
	network := connectProxy(p.env.Dialer)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			network.ServeHTTP(w, r)
		} else {
			mux.ServeHTTP(w, r)
		}
	})
}

func callback(fn func(context.Context, *http.Request, []byte) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, err := readRequest(w, r)
		var value any
		if err == nil {
			value, err = fn(r.Context(), r, raw)
		}
		reply(w, value, err)
	}
}

func (p *process) streamCallback(fn func(context.Context, *connector.Stream, []byte) (any, error)) http.HandlerFunc {
	return callback(func(ctx context.Context, r *http.Request, raw []byte) (any, error) {
		p.mu.Lock()
		stream := p.streams[r.PathValue("stream")]
		p.mu.Unlock()
		if stream == nil {
			return nil, errors.New("stream is not admitted")
		}
		if err := stream.Context.Err(); err != nil {
			return nil, err
		}
		return fn(ctx, stream, raw)
	})
}

func (p *process) credential(ctx context.Context, name string) (string, error) {
	if value := p.secrets[name]; value != nil {
		return value.Value(ctx)
	}
	return "", errors.New("credential is not granted")
}

func (p *process) signHost(raw []byte) (*ssh.Signature, error) {
	if !p.usesHostKey || p.env.HostKey == nil {
		return nil, errors.New("host identity is not granted")
	}
	var in signing
	if err := facts.DecodeNumbers(raw, &in); err != nil {
		return nil, err
	}
	if len(in.Data) > 1024 {
		return nil, errors.New("signing input exceeds limit")
	}
	if in.Algorithm != "" {
		signer, ok := p.env.HostKey.(ssh.AlgorithmSigner)
		if !ok {
			return nil, errors.New("unsupported signing algorithm")
		}
		return signer.SignWithAlgorithm(rand.Reader, in.Data, in.Algorithm)
	}
	return p.env.HostKey.Sign(rand.Reader, in.Data)
}

func (p *process) certificate(_ context.Context, stream *connector.Stream, raw []byte) (any, error) {
	var name string
	if err := facts.DecodeNumbers(raw, &name); err != nil {
		return nil, err
	}
	if len(name) > 253 || stream.Host != "" && name != "" && !strings.EqualFold(name, stream.Host) {
		return nil, errors.New("TLS name differs from admitted stream")
	}
	if p.env.TLS == nil || p.env.TLS.GetCertificate == nil {
		return nil, errors.New("TLS identity unavailable")
	}
	if name == "" {
		name = stream.Host
	}
	cert, err := p.env.TLS.GetCertificate(&tls.ClientHelloInfo{ServerName: name})
	if err != nil {
		return nil, err
	}
	if len(cert.Certificate) == 0 {
		return nil, errors.New("empty certificate")
	}
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil || leaf.IsCA {
		return nil, errors.New("only leaf certificates may enter a worker")
	}
	key, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
	return certificate{cert.Certificate, key}, err
}

func connectProxy(dialer connector.Dialer) http.Handler {
	slots := make(chan struct{}, maxUpstreamConnections)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.URL.Host != r.Host || len(r.Host) > 8192 {
			http.Error(w, "worker upstream was refused", 403)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "worker connection limit", 503)
			return
		}
		upstream, err := dialer.DialContext(r.Context(), "tcp", r.Host)
		if err != nil {
			http.Error(w, "worker upstream unavailable", 502)
			return
		}
		defer upstream.Close()
		client, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		if _, err = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if err = rw.Flush(); err != nil {
			return
		}
		connector.Relay(r.Context(), &bufferedConn{Conn: client, reader: rw.Reader}, upstream)
	})
}
