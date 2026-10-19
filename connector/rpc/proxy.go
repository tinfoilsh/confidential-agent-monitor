// Package rpc adapts the connector interface to a private HTTP connection.
package rpc

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
	"golang.org/x/crypto/ssh"
)

const (
	maxSessions            = 128
	maxUpstreamConnections = 32
)

// Endpoint is a running service. Close stops it; Done closes after cleanup,
// including after a crash or lost connection. Close must be safe to repeat.
type Endpoint struct {
	Dial  DialFunc
	Done  <-chan struct{}
	Close func()
}

// Launcher starts a service with opaque configuration and a callback handler.
// It owns isolation and endpoint lifetime; cancellation must stop the service.
// Readiness and the connector protocol belong to Proxy.
type Launcher interface {
	Start(context.Context, []byte, http.Handler) (Endpoint, error)
}

// Proxy runs one connector through a launcher and forwards streams and controls.
type Proxy struct {
	Kind       string
	Config     json.RawMessage
	Secrets    map[string]*credential.Value
	Definition connector.Definition
	Launcher   Launcher
	env        *connector.Env
	ctx        context.Context
	endpoint   Endpoint
	transport  *http.Transport
	mu         sync.Mutex
	next       uint64
	sessions   map[string]*connector.Stream
	details    json.RawMessage
}

func (p *Proxy) Run(ctx context.Context, host *connector.Env, serve func(context.Context)) error {
	if p.Launcher == nil || host.Dialer == nil {
		return errors.New("connector worker is not configured")
	}
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	p.ctx, p.env, p.sessions = ctx, host, map[string]*connector.Stream{}
	settings, err := json.Marshal(p.Definition.Settings)
	if err != nil {
		return err
	}
	boot := bootstrap{Version: protocolVersion, Kind: p.Kind, Config: p.Config, Settings: settings, Secrets: map[string]secretHandle{}}
	for name, v := range p.Secrets {
		if v != nil {
			boot.Secrets[name] = secretHandle{len(v.Raw()) > 0, v.Placeholder}
		}
	}
	if p.Definition.HostKey && host.HostKey != nil {
		boot.HostKey = host.HostKey.PublicKey().Marshal()
	}
	raw, err := json.Marshal(boot)
	if err != nil {
		return err
	}
	if len(raw) > maxMessage {
		return errors.New("worker configuration exceeds size limit")
	}
	network := broker(p.ctx, host.Dialer)
	callbacks := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		stop := context.AfterFunc(p.ctx, cancel)
		defer stop()
		r = r.WithContext(ctx)
		if r.Method == http.MethodConnect {
			network.ServeHTTP(w, r)
		} else if r.Method == http.MethodPost {
			value, err := p.dispatch(r)
			reply(w, value, err)
		} else {
			http.NotFound(w, r)
		}
	})
	p.endpoint, err = p.Launcher.Start(p.ctx, raw, callbacks)
	if err != nil {
		return err
	}
	go func() {
		select {
		case <-p.endpoint.Done:
			cancel(errors.New("connector worker stopped"))
		case <-p.ctx.Done():
		}
	}()
	defer func() { p.endpoint.Close(); <-p.endpoint.Done }()
	p.transport = p.endpoint.Dial.Transport()
	defer p.transport.CloseIdleConnections()
	readyCtx, cancelReady := context.WithTimeout(p.ctx, time.Minute)
	defer cancelReady()
	if err := call(readyCtx, p.transport, readyPath, nil, &p.details); err != nil {
		return fmt.Errorf("connector worker startup: %w", err)
	}
	if string(p.details) == "null" {
		p.details = nil
	}
	serve(ctx)
	return context.Cause(ctx)
}

// Serve binds callbacks to caller authority until the stream closes.
func (p *Proxy) Serve(s *connector.Stream, _ *connector.Env) {
	defer s.Close()
	p.mu.Lock()
	if p.ctx.Err() != nil || s.Context.Err() != nil || len(p.sessions) >= maxSessions {
		p.mu.Unlock()
		return
	}
	p.next++
	id := fmt.Sprint(p.next)
	p.sessions[id] = s
	p.mu.Unlock()
	stop := context.AfterFunc(p.ctx, func() { s.Close() })
	defer func() {
		stop()
		p.mu.Lock()
		delete(p.sessions, id)
		p.mu.Unlock()
	}()
	raw, _ := json.Marshal(sessionInfo{id, s.Name, s.Host, s.Port})
	header := http.Header{sessionHeader: {base64.RawStdEncoding.EncodeToString(raw)}, "Connection": {"Upgrade"}, "Upgrade": {"monitor-connector"}}
	r := &http.Request{Method: "GET", URL: &url.URL{Path: "/stream"}, Host: "worker", Header: header}
	upstream, err := connect(s.Context, p.endpoint.Dial, r, http.StatusSwitchingProtocols)
	if err != nil {
		return
	}
	connector.Relay(s.Context, s.Conn, upstream)
}

func (p *Proxy) Details() json.RawMessage { return p.details }

func (p *Proxy) Control() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithCancel(r.Context())
		defer cancel()
		stop := context.AfterFunc(p.ctx, cancel)
		defer stop()
		proxy := httputil.ReverseProxy{Transport: p.transport, Rewrite: func(r *httputil.ProxyRequest) {
			r.Out.URL.Scheme, r.Out.URL.Host, r.Out.Host = "http", "connector", "connector"
			r.Out.URL.Path = "/control" + r.Out.URL.Path
			r.Out.URL.RawPath = ""
			// Caller authentication belongs to Monitor; controls carry no stream authority.
			r.Out.Header.Del("Authorization")
			r.Out.Header.Del("Proxy-Authorization")
			r.Out.Header.Del("Cookie")
			r.Out.Header.Del(sessionHeader)
		}, FlushInterval: -1}
		proxy.ServeHTTP(w, r.WithContext(ctx))
	})
}

func (r *Proxy) dispatch(request *http.Request) (any, error) {
	op, name, _ := strings.Cut(strings.TrimPrefix(request.URL.Path, "/"), "/")
	ctx := request.Context()
	switch op {
	case "credential":
		v := r.Secrets[name]
		if v == nil {
			return nil, errors.New("credential is not granted")
		}
		return v.Value(ctx)
	case "host-sign":
		if !r.Definition.HostKey || r.env.HostKey == nil {
			return nil, errors.New("host identity is not granted")
		}
		var in signing
		if err := readJSON(request.Body, &in); err != nil {
			return nil, err
		}
		if len(in.Data) > 1024 {
			return nil, errors.New("signing input exceeds limit")
		}
		if in.Algorithm != "" {
			signer, ok := r.env.HostKey.(ssh.AlgorithmSigner)
			if !ok {
				return nil, errors.New("unsupported signing algorithm")
			}
			return signer.SignWithAlgorithm(rand.Reader, in.Data, in.Algorithm)
		}
		return r.env.HostKey.Sign(rand.Reader, in.Data)
	}
	r.mu.Lock()
	s := r.sessions[name]
	r.mu.Unlock()
	if s == nil {
		return nil, errors.New("session is not admitted")
	}
	if s.Context.Err() != nil {
		return nil, s.Context.Err()
	}
	switch op {
	case "gate":
		var input event
		if err := readJSON(request.Body, &input); err != nil {
			return nil, err
		}
		e, err := decode(r.Definition, input)
		if err != nil {
			return nil, err
		}
		return nil, s.Gate(ctx, e)
	case "certificate":
		var name string
		if err := readJSON(request.Body, &name); err != nil {
			return nil, err
		}
		if len(name) > 253 || s.Host != "" && name != "" && !strings.EqualFold(name, s.Host) {
			return nil, errors.New("TLS name differs from admitted stream")
		}
		if r.env.TLS == nil || r.env.TLS.GetCertificate == nil {
			return nil, errors.New("TLS identity unavailable")
		}
		if name == "" {
			name = s.Host
		}
		cert, err := r.env.TLS.GetCertificate(&tls.ClientHelloInfo{ServerName: name})
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
	default:
		return nil, errors.New("unknown host operation")
	}
}

func broker(ctx context.Context, dialer connector.Dialer) http.Handler {
	slots := make(chan struct{}, maxUpstreamConnections)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect || r.URL.Host != r.Host {
			http.Error(w, "worker upstream was refused", http.StatusForbidden)
			return
		}
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "worker connection limit", http.StatusServiceUnavailable)
			return
		}
		up, err := dialer.DialContext(r.Context(), "tcp", r.Host)
		if err != nil {
			http.Error(w, "worker upstream unavailable", http.StatusBadGateway)
			return
		}
		defer up.Close()
		client, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer client.Close()
		stop := context.AfterFunc(ctx, func() { up.Close(); client.Close() })
		defer stop()
		if _, err := rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
			return
		}
		if err := rw.Flush(); err != nil {
			return
		}
		connector.Relay(ctx, &bufferedConn{Conn: client, reader: rw.Reader}, up)
	})
}
