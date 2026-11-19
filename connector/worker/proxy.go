package worker

import (
	"cmp"
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
	"slices"
	"strings"
	"sync"

	"github.com/tinfoilsh/confidential-agent-monitor/core/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/netx"
	"golang.org/x/crypto/ssh"
)

type Endpoint struct {
	Context context.Context
	Dial    func(context.Context) (net.Conn, error)
	Done    <-chan struct{}
	Close   func()
}

type Secret struct {
	Configured  bool
	OAuth       bool
	Placeholder string
	Value       func(context.Context) (string, error)
}

type Grants struct {
	Dial        func(ctx context.Context, network, address string) (net.Conn, error)
	Secrets     map[string]Secret
	Certificate func(name string) (*tls.Certificate, error)
	HostKey     ssh.Signer
}

func (g Grants) Host() Host {
	return Host{Dial: g.Dial, HostKey: g.HostKey, Secret: g.secret,
		Configured:  func(name string) bool { return g.Secrets[name].Configured },
		OAuth:       func(name string) bool { return g.Secrets[name].OAuth },
		Placeholder: func(name string) string { return g.Secrets[name].Placeholder },
		TLS: func(_ context.Context, host string) *tls.Config {
			return &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				return g.certificate(cmp.Or(hello.ServerName, host))
			}}
		}}
}

func (g Grants) secret(ctx context.Context, name string) (string, error) {
	if value, granted := g.Secrets[name]; granted {
		return value.Value(ctx)
	}
	return "", errors.New("credential is not granted")
}

func (g Grants) certificate(name string) (*tls.Certificate, error) {
	if g.Certificate == nil {
		return nil, errors.New("TLS identity unavailable")
	}
	return g.Certificate(name)
}

type Process struct {
	Endpoint
	grants    Grants
	limits    Limits
	transport *http.Transport
	details   json.RawMessage
	mu        sync.Mutex
	next      uint64
	streams   map[string]*stream
}

type stream struct {
	ctx  context.Context
	host string
	gate connector.Gate
}

func Launch(ctx context.Context, start func(ctx context.Context, config []byte, broker http.Handler) (Endpoint, error), data json.RawMessage, grants Grants, limits Limits) (*Process, error) {
	boot := bootstrap{Data: data, Secrets: map[string]secretHandle{}}
	for name, value := range grants.Secrets {
		boot.Secrets[name] = secretHandle{value.Configured, value.OAuth, value.Placeholder}
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
	running := &Process{grants: grants, limits: limits, streams: map[string]*stream{}}
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

func (p *Process) Serve(ctx context.Context, conn net.Conn, name string, target connector.Target, gate connector.Gate) {
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
	p.streams[id] = &stream{ctx, target.Host, gate}
	p.mu.Unlock()
	defer func() { p.mu.Lock(); delete(p.streams, id); p.mu.Unlock() }()
	raw, _ := json.Marshal(streamInfo{id, name, target})
	header := http.Header{streamHeader: {base64.RawStdEncoding.EncodeToString(raw)}, "Connection": {"Upgrade"}, "Upgrade": {upgradeProtocol}}
	request := &http.Request{Method: "GET", URL: &url.URL{Path: "/stream"}, Host: "worker", Header: header}
	upstream, err := connect(ctx, p.Dial, request, http.StatusSwitchingProtocols, p.limits.Handshake)
	if err != nil {
		return
	}
	netx.Relay(ctx, conn, upstream, p.limits.Drain)
}

func (p *Process) Instance() connector.Instance {
	return connector.Instance{Serve: p.Serve, Close: p.Close, Ready: p.Ready, Details: p.details, Control: p.Control()}
}

func (p *Process) Control() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithCancel(r.Context())
		stop := context.AfterFunc(p.Context, cancel)
		defer func() { stop(); cancel() }()
		proxy := httputil.ReverseProxy{Transport: p.transport, Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme, r.Out.URL.Host, r.Out.Host = "http", "connector", "connector"
			r.Out.URL.Path = "/control" + r.Out.URL.Path
			r.Out.URL.RawPath = ""
			for _, name := range []string{"Authorization", "Proxy-Authorization", "Cookie", streamHeader} {
				r.Out.Header.Del(name)
			}
		}, FlushInterval: -1}
		proxy.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (p *Process) broker() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /credential/{name}", p.callback(func(ctx context.Context, r *http.Request, _ []byte) (any, error) {
		return p.grants.secret(ctx, r.PathValue("name"))
	}))
	mux.Handle("POST /host-sign", p.callback(func(_ context.Context, _ *http.Request, raw []byte) (any, error) {
		return p.signHost(raw)
	}))
	mux.Handle("POST /gate/{stream}", p.streamCallback(func(ctx context.Context, stream *stream, raw []byte) (any, error) {
		return nil, stream.gate(ctx, facts.Event(raw))
	}))
	mux.Handle("POST /certificate/{stream}", p.streamCallback(p.certificate))
	network := connectProxy(p.grants.Dial, p.limits)
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
	if name == "" {
		name = stream.host
	}
	cert, err := p.grants.certificate(name)
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

func connectProxy(dial func(context.Context, string, string) (net.Conn, error), l Limits) http.Handler {
	slots := make(chan struct{}, l.Upstreams)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		network := r.Header.Get(netx.NetworkHeader)
		if r.Method != http.MethodConnect || r.URL.Host != r.Host || len(r.Host) > 8192 || !slices.Contains(brokerNetworks, network) {
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
		netx.Connect(netx.Dial(dial, l.Drain)).ServeHTTP(w, r)
	})
}
