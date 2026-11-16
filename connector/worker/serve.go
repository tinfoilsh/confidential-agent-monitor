package worker

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"golang.org/x/crypto/ssh"
)

type streamKey struct{}

// Host is what a worker's connector may use; every call goes to the host, which checks it against its grants.
type Host struct {
	// Dial opens TCP through the host's dialer. TLS, including certificate pinning, runs in the worker.
	Dial func(ctx context.Context, network, address string) (net.Conn, error)
	// Secret asks the host for a granted value; stored grants and refresh tokens never leave the host.
	Secret      func(ctx context.Context, name string) (string, error)
	Configured  func(name string) bool
	Placeholder func(name string) string
	// TLS terminates the TLS of the admitted stream ctx carries with the host's leaf for it.
	TLS     func(ctx context.Context, host string) *tls.Config
	HostKey ssh.Signer
}

// Instance is the connector a worker serves. Only Serve is required.
type Instance struct {
	Serve   func(ctx context.Context, conn net.Conn, name, host string, port uint32, gate func(context.Context, facts.Event) error)
	Close   func() error
	Details json.RawMessage
	Control http.Handler
}

// Serve runs a worker using a supplied listener and connection to host services. factory opens the one
// connector the host prepared data for. The launcher establishes isolation and authenticates both directions
// before calling Serve. Serve closes ln and stops the connector when ctx ends.
func Serve(ctx context.Context, factory func(ctx context.Context, data json.RawMessage, host Host) (Instance, error), config io.Reader, ln net.Listener, broker func(context.Context) (net.Conn, error), limits Limits) error {
	defer ln.Close()
	var boot bootstrap
	if err := readJSON(config, &boot); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	callbacks := dialFunc(broker).transport(limits)
	defer callbacks.CloseIdleConnections()
	host := Host{
		Dial: brokerDialer{broker, limits.Handshake}.DialContext,
		Secret: func(ctx context.Context, name string) (string, error) {
			ctx, cancel := context.WithTimeout(ctx, limits.Credential)
			defer cancel()
			var value string
			err := call(ctx, callbacks, "/credential/"+url.PathEscape(name), nil, &value)
			return value, err
		},
		Configured:  func(name string) bool { return boot.Secrets[name].Configured },
		Placeholder: func(name string) string { return boot.Secrets[name].Placeholder },
		TLS: func(ctx context.Context, _ string) *tls.Config {
			return &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
				id, ok := ctx.Value(streamKey{}).(string)
				if !ok {
					return nil, errors.New("TLS handshake has no admitted stream")
				}
				var cert certificate
				if err := call(ctx, callbacks, "/certificate/"+id, hello.ServerName, &cert); err != nil {
					return nil, err
				}
				key, err := x509.ParsePKCS8PrivateKey(cert.Key)
				if err != nil {
					return nil, err
				}
				return &tls.Certificate{Certificate: cert.Chain, PrivateKey: key}, nil
			}}
		},
	}
	if len(boot.HostKey) != 0 {
		key, err := ssh.ParsePublicKey(boot.HostKey)
		if err != nil {
			return err
		}
		host.HostKey = &remoteSigner{ctx, callbacks, key, limits.Sign}
	}
	instance, startErr := factory(ctx, boot.Data, host)
	if startErr == nil && instance.Close != nil {
		defer instance.Close()
	}
	return serveRPC(ctx, ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == readyPath {
			reply(w, instance.Details, startErr)
			return
		}
		if startErr != nil {
			http.Error(w, "worker stopped", 503)
			return
		}
		control := strings.HasPrefix(r.URL.Path, "/control/")
		if !control && (r.Method != "GET" || r.URL.Path != "/stream") {
			http.NotFound(w, r)
			return
		}
		if control {
			r.URL.Path = strings.TrimPrefix(r.URL.Path, "/control")
			r.URL.RawPath = ""
			if instance.Control == nil {
				http.NotFound(w, r)
				return
			}
			instance.Control.ServeHTTP(w, r)
			return
		}
		raw, err := base64.RawStdEncoding.DecodeString(r.Header.Get(streamHeader))
		var info streamInfo
		if err != nil || len(raw) > 8192 || facts.DecodeNumbers(raw, &info) != nil || info.ID == "" {
			http.Error(w, "invalid stream", 400)
			return
		}
		conn, err := accept(w, r)
		if err != nil {
			return
		}
		// Keep upgraded work in this handler so shutdown, which ends its context, joins its actual return.
		ctx := context.WithValue(r.Context(), streamKey{}, info.ID)
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		defer func() { stop(); conn.Close() }()
		instance.Serve(ctx, conn, info.Name, info.Host, info.Port, func(ctx context.Context, event facts.Event) error {
			return call(ctx, callbacks, "/gate/"+info.ID, json.RawMessage(event), nil)
		})
	}), limits)
}

type remoteSigner struct {
	ctx       context.Context
	transport http.RoundTripper
	key       ssh.PublicKey
	timeout   time.Duration
}

func (s *remoteSigner) PublicKey() ssh.PublicKey { return s.key }
func (s *remoteSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	return s.SignWithAlgorithm(nil, data, "")
}
func (s *remoteSigner) SignWithAlgorithm(_ io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	ctx, cancel := context.WithTimeout(s.ctx, s.timeout)
	defer cancel()
	var signature ssh.Signature
	err := call(ctx, s.transport, "/host-sign", signing{data, algorithm}, &signature)
	return &signature, err
}

// brokerDialer carries TCP over a connection to the host. TLS, including
// certificate pinning, runs in the worker on the resulting byte stream.
type brokerDialer struct {
	dial    dialFunc
	timeout time.Duration
}

func (d brokerDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errors.New("worker broker supports TCP only")
	}
	r := &http.Request{Method: http.MethodConnect, URL: &url.URL{Host: address}, Host: address, Header: make(http.Header)}
	return connect(ctx, d.dial, r, http.StatusOK, d.timeout)
}
