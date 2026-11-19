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
	"slices"
	"strings"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/core/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/netx"
	"golang.org/x/crypto/ssh"
)

type streamKey struct{}

type Host struct {
	Dial        func(ctx context.Context, network, address string) (net.Conn, error)
	Secret      func(ctx context.Context, name string) (string, error)
	Configured  func(name string) bool
	OAuth       func(name string) bool
	Placeholder func(name string) string
	TLS         func(ctx context.Context, host string) *tls.Config
	HostKey     ssh.Signer
}

func Serve(ctx context.Context, factory func(ctx context.Context, data json.RawMessage, host Host) (connector.Instance, error), config io.Reader, ln net.Listener, broker func(context.Context) (net.Conn, error), limits Limits) error {
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
		OAuth:       func(name string) bool { return boot.Secrets[name].OAuth },
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
		ctx := context.WithValue(r.Context(), streamKey{}, info.ID)
		stop := context.AfterFunc(ctx, func() { conn.Close() })
		defer func() { stop(); conn.Close() }()
		instance.Serve(ctx, conn, info.Name, info.Target, func(ctx context.Context, event facts.Event) error {
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

type brokerDialer struct {
	dial    dialFunc
	timeout time.Duration
}

func (d brokerDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if !slices.Contains(brokerNetworks, network) {
		return nil, errors.New("worker broker supports TCP and UDP only")
	}
	r := &http.Request{Method: http.MethodConnect, URL: &url.URL{Host: address}, Host: address, Header: http.Header{netx.NetworkHeader: {network}}}
	conn, err := connect(ctx, d.dial, r, http.StatusOK, d.timeout)
	if err == nil && strings.HasPrefix(network, "udp") {
		conn = netx.Datagrams(conn)
	}
	return conn, err
}
