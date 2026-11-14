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

	"github.com/tinfoilsh/confidential-agent-monitor/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/credential"
	"github.com/tinfoilsh/confidential-agent-monitor/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/netx"
	"golang.org/x/crypto/ssh"
)

const (
	maxStreams             = 128
	maxUpstreamConnections = 32
)

// endpoint owns one actual process. Context ends when it stops; Done closes
// after process and broker callbacks have joined. Close is safe to repeat.
type endpoint struct {
	Context context.Context
	Dial    dialFunc
	Done    <-chan struct{}
	Close   func()
}

// proxy is stable across setup changes. Update and Close are serialized by its
// owner; calls already handed off retain their original process capabilities.
type proxy struct {
	Protocol string
	Kind     connector.Kind
	Launcher *Local
	connector.Resource[*process]
}

type process struct {
	endpoint
	env       *connector.Env
	secrets   map[string]*credential.Value
	transport *http.Transport
	details   json.RawMessage
	mu        sync.Mutex
	next      uint64
	streams   map[string]*connector.Stream
}

func (p *proxy) Update(ctx context.Context, prepared connector.Prepared, secrets map[string]*credential.Value, env *connector.Env) error {
	return p.Replace(func() (*process, error) {
		if p.Launcher == nil || env.Dialer == nil {
			return nil, errors.New("connector worker is not configured")
		}
		settings, err := json.Marshal(p.Kind.Settings)
		if err != nil {
			return nil, err
		}
		boot := bootstrap{Setup: prepared.Source, Protocol: p.Protocol, Settings: settings, Secrets: map[string]secretHandle{}}
		for name, value := range secrets {
			boot.Secrets[name] = secretHandle{value.Configured(), value.Placeholder}
		}
		if env.HostKey != nil {
			boot.HostKey = env.HostKey.PublicKey().Marshal()
		}
		raw, err := json.Marshal(boot)
		if err != nil {
			return nil, err
		}
		if len(raw) > maxMessage {
			return nil, errors.New("worker configuration exceeds size limit")
		}
		running := &process{env: env, secrets: maps.Clone(secrets), streams: map[string]*connector.Stream{}}
		running.endpoint, err = p.Launcher.start(ctx, raw, running.broker())
		if err != nil {
			return nil, err
		}
		running.transport = running.Dial.transport()
		ready, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		err = call(ready, running.transport, readyPath, nil, &running.details)
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
	})
}

func (p *proxy) Ready() error {
	running := p.Load()
	if running == nil {
		return errors.New("connector worker is unavailable")
	}
	return running.Context.Err()
}

func (p *process) Close() error {
	p.endpoint.Close()
	<-p.Done
	p.transport.CloseIdleConnections()
	return nil
}

func (p *proxy) Serve(s *connector.Stream, _ *connector.Env) {
	defer s.Close()
	running := p.Load()
	if running == nil {
		return
	}
	ctx, cancel := netx.Bind(s.Context, running.Context)
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
	header := http.Header{streamHeader: {base64.RawStdEncoding.EncodeToString(raw)}, "Connection": {"Upgrade"}, "Upgrade": {upgradeProtocol}}
	request := &http.Request{Method: "GET", URL: &url.URL{Path: "/stream"}, Host: "worker", Header: header}
	upstream, err := connect(ctx, running.Dial, request, http.StatusSwitchingProtocols)
	if err != nil {
		return
	}
	netx.Relay(ctx, s.Conn, upstream)
}

func (p *proxy) Details() json.RawMessage {
	if running := p.Load(); running != nil {
		return running.details
	}
	return nil
}

func (p *proxy) Control() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		running := p.Load()
		if running == nil {
			http.Error(w, "connector worker is unavailable", 503)
			return
		}
		ctx, cancel := netx.Bind(r.Context(), running.Context)
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
	if p.env.HostKey == nil {
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
		netx.Tunnel(w, r, upstream)
	})
}
