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
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"

	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"golang.org/x/crypto/ssh"
)

// Endpoint owns one actual process. Context ends when it stops; Done closes
// after process and broker callbacks have joined. Close is safe to repeat.
type Endpoint struct {
	Context context.Context
	Dial    func(context.Context) (net.Conn, error)
	Done    <-chan struct{}
	Close   func()
}

// Secret is a credential handle the host grants; only its value leaves the host, and only when asked.
type Secret struct {
	Configured  bool
	Placeholder string
	Value       func(context.Context) (string, error)
}

// Grants are the host capabilities a worker may ask for. Nil fields grant nothing.
type Grants struct {
	// Connect serves the worker's CONNECT requests through the host's dialer.
	Connect http.Handler
	Secrets map[string]Secret
	// Certificate issues the TLS leaf for name, which the host has checked against the admitted stream.
	Certificate func(name string) (*tls.Certificate, error)
	HostKey     ssh.Signer
}

// Process is one setup served by one worker; calls already handed off retain its capabilities.
type Process struct {
	Endpoint
	grants    Grants
	net       Net
	limits    Limits
	transport *http.Transport
	details   json.RawMessage
	mu        sync.Mutex
	next      uint64
	streams   map[string]*stream
}

// stream is an admitted stream the worker may call back for.
type stream struct {
	ctx  context.Context
	host string
	gate func(context.Context, facts.Event) error
}

// Launch starts a worker with start, hands it the host's prepared protocol data and waits under ctx until it serves.
func Launch(ctx context.Context, start func(ctx context.Context, config []byte, broker http.Handler) (Endpoint, error), data json.RawMessage, grants Grants, n Net, limits Limits) (*Process, error) {
	boot := bootstrap{Data: data, Secrets: map[string]secretHandle{}}
	for name, value := range grants.Secrets {
		boot.Secrets[name] = secretHandle{value.Configured, value.Placeholder}
	}
	if grants.HostKey != nil {
		boot.HostKey = grants.HostKey.PublicKey().Marshal()
	}
	raw, err := json.Marshal(boot)
	if err != nil {
		return nil, err
	}
	if len(raw) > maxMessage {
		return nil, errors.New("worker configuration exceeds size limit")
	}
	grants.Secrets = maps.Clone(grants.Secrets)
	running := &Process{grants: grants, net: n, limits: limits, streams: map[string]*stream{}}
	running.Endpoint, err = start(ctx, raw, running.broker())
	if err != nil {
		return nil, err
	}
	running.transport = dialFunc(running.Dial).transport(limits)
	err = call(ctx, running.transport, readyPath, nil, &running.details)
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		running.Close()
		return nil, fmt.Errorf("connector worker startup: %w", err)
	}
	if string(running.details) == "null" {
		running.details = nil
	}
	return running, nil
}

func (p *Process) Ready() error { return p.Context.Err() }

func (p *Process) Close() error {
	p.Endpoint.Close()
	<-p.Done
	p.transport.CloseIdleConnections()
	return nil
}

// Serve relays one admitted stream into the worker and answers its gate calls with gate.
func (p *Process) Serve(ctx context.Context, conn net.Conn, name, host string, port uint32, gate func(context.Context, facts.Event) error) {
	defer conn.Close()
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(p.Context, cancel)
	defer func() { stop(); cancel() }()
	p.mu.Lock()
	if ctx.Err() != nil || len(p.streams) >= p.limits.Streams {
		p.mu.Unlock()
		return
	}
	p.next++
	id := fmt.Sprint(p.next)
	p.streams[id] = &stream{ctx, host, gate}
	p.mu.Unlock()
	defer func() { p.mu.Lock(); delete(p.streams, id); p.mu.Unlock() }()
	raw, _ := json.Marshal(streamInfo{id, name, host, port})
	header := http.Header{streamHeader: {base64.RawStdEncoding.EncodeToString(raw)}, "Connection": {"Upgrade"}, "Upgrade": {upgradeProtocol}}
	request := &http.Request{Method: "GET", URL: &url.URL{Path: "/stream"}, Host: "worker", Header: header}
	upstream, err := connect(ctx, p.Dial, request, http.StatusSwitchingProtocols, p.net, p.limits.Handshake)
	if err != nil {
		return
	}
	p.net.Relay(ctx, conn, upstream)
}

func (p *Process) Details() json.RawMessage { return p.details }

func (p *Process) Control() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithCancel(r.Context())
		stop := context.AfterFunc(p.Context, cancel)
		defer func() { stop(); cancel() }()
		proxy := httputil.ReverseProxy{Transport: p.transport, Rewrite: func(r *httputil.ProxyRequest) {
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

func (p *Process) broker() http.Handler {
	mux := http.NewServeMux()
	// These capabilities belong to the connection, including setup and owner controls.
	mux.Handle("POST /credential/{name}", p.callback(func(ctx context.Context, r *http.Request, _ []byte) (any, error) {
		return p.credential(ctx, r.PathValue("name"))
	}))
	mux.Handle("POST /host-sign", p.callback(func(_ context.Context, _ *http.Request, raw []byte) (any, error) {
		return p.signHost(raw)
	}))
	// These operations additionally require a live stream admitted by the host.
	mux.Handle("POST /gate/{stream}", p.streamCallback(func(ctx context.Context, stream *stream, raw []byte) (any, error) {
		return nil, stream.gate(ctx, facts.Event(raw))
	}))
	mux.Handle("POST /certificate/{stream}", p.streamCallback(p.certificate))
	network := connectProxy(p.grants.Connect, p.limits.Upstreams)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodConnect {
			network.ServeHTTP(w, r)
		} else {
			mux.ServeHTTP(w, r)
		}
	})
}

func (p *Process) callback(fn func(context.Context, *http.Request, []byte) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw, err := readRequest(w, r, p.limits.Read)
		var value any
		if err == nil {
			value, err = fn(r.Context(), r, raw)
		}
		reply(w, value, err)
	}
}

func (p *Process) streamCallback(fn func(context.Context, *stream, []byte) (any, error)) http.HandlerFunc {
	return p.callback(func(ctx context.Context, r *http.Request, raw []byte) (any, error) {
		p.mu.Lock()
		stream := p.streams[r.PathValue("stream")]
		p.mu.Unlock()
		if stream == nil {
			return nil, errors.New("stream is not admitted")
		}
		if err := stream.ctx.Err(); err != nil {
			return nil, err
		}
		return fn(ctx, stream, raw)
	})
}

func (p *Process) credential(ctx context.Context, name string) (string, error) {
	if value, granted := p.grants.Secrets[name]; granted {
		return value.Value(ctx)
	}
	return "", errors.New("credential is not granted")
}

func (p *Process) signHost(raw []byte) (*ssh.Signature, error) {
	if p.grants.HostKey == nil {
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
		signer, ok := p.grants.HostKey.(ssh.AlgorithmSigner)
		if !ok {
			return nil, errors.New("unsupported signing algorithm")
		}
		return signer.SignWithAlgorithm(rand.Reader, in.Data, in.Algorithm)
	}
	return p.grants.HostKey.Sign(rand.Reader, in.Data)
}

func (p *Process) certificate(_ context.Context, stream *stream, raw []byte) (any, error) {
	var name string
	if err := facts.DecodeNumbers(raw, &name); err != nil {
		return nil, err
	}
	if len(name) > 253 || stream.host != "" && name != "" && !strings.EqualFold(name, stream.host) {
		return nil, errors.New("TLS name differs from admitted stream")
	}
	if p.grants.Certificate == nil {
		return nil, errors.New("TLS identity unavailable")
	}
	if name == "" {
		name = stream.host
	}
	cert, err := p.grants.Certificate(name)
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

// connectProxy bounds the worker's upstream connections, which connect opens through the host's dialer.
func connectProxy(connect http.Handler, limit int) http.Handler {
	slots := make(chan struct{}, limit)
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
		connect.ServeHTTP(w, r)
	})
}
