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

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/facts"
	"golang.org/x/crypto/ssh"
)

type sessionKey struct{}

// Serve runs a worker using a supplied listener and connection to host services.
// The launcher establishes isolation and authenticates both directions before
// calling Serve. Serve closes ln and stops the connector when ctx ends.
func Serve(ctx context.Context, definitions map[string]connector.Definition, config io.Reader, ln net.Listener, host DialFunc) error {
	defer ln.Close()
	var boot bootstrap
	if err := readJSON(config, &boot); err != nil {
		return err
	}
	if boot.Version != protocolVersion {
		return errors.New("unsupported worker protocol")
	}
	def := definitions[boot.Kind]
	if def.New == nil || def.Parse == nil {
		return errors.New("unknown connector")
	}
	if def.Settings != nil {
		if err := facts.DecodeNumbers(boot.Settings, def.Settings); err != nil {
			return err
		}
	}
	prepared, err := def.Parse(boot.Setup)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	callbacks := host.Transport()
	defer callbacks.CloseIdleConnections()
	env := connector.Env{Dialer: BrokerDialer{Dial: host}}
	secrets := map[string]*credential.Value{}
	for name, handle := range boot.Secrets {
		secrets[name] = credential.Remote(handle.Configured, func(ctx context.Context) (string, error) {
			var value string
			err := call(ctx, callbacks, "/credential/"+url.PathEscape(name), nil, &value)
			return value, err
		})
		secrets[name].Placeholder = handle.Placeholder
	}
	if len(boot.HostKey) != 0 {
		key, err := ssh.ParsePublicKey(boot.HostKey)
		if err != nil {
			return err
		}
		env.HostKey = &remoteSigner{ctx, callbacks, key}
	}
	env.TLS = &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		s, ok := hello.Conn.(*connector.Stream)
		if !ok {
			return nil, errors.New("TLS handshake has no admitted stream")
		}
		id, _ := s.Context.Value(sessionKey{}).(string)
		var cert certificate
		if err := call(s.Context, callbacks, "/certificate/"+id, hello.ServerName, &cert); err != nil {
			return nil, err
		}
		key, err := x509.ParsePKCS8PrivateKey(cert.Key)
		if err != nil {
			return nil, err
		}
		return &tls.Certificate{Certificate: cert.Chain, PrivateKey: key}, nil
	}}
	instance := def.New()
	if closer, ok := instance.(io.Closer); ok {
		defer closer.Close()
	}
	startErr := instance.Update(ctx, prepared, secrets, &env)
	var details json.RawMessage
	if d, ok := instance.(connector.Detailer); ok {
		details = d.Details()
	}
	return serve(ctx, ln, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == readyPath {
			reply(w, details, startErr)
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
			connector.Control(instance).ServeHTTP(w, r)
			return
		}
		raw, err := base64.RawStdEncoding.DecodeString(r.Header.Get(sessionHeader))
		var info sessionInfo
		if err != nil || len(raw) > 8192 || facts.DecodeNumbers(raw, &info) != nil || info.ID == "" {
			http.Error(w, "invalid session", 400)
			return
		}
		conn, err := Accept(w, r)
		if err != nil {
			return
		}
		// Keep upgraded work in this handler so shutdown joins its actual return.
		stream := connector.NewStream(context.WithValue(r.Context(), sessionKey{}, info.ID), conn)
		defer stream.Close()
		stream.Name, stream.Host, stream.Port = info.Name, info.Host, info.Port
		stream.Gate = func(ctx context.Context, event facts.Event) error {
			return call(ctx, callbacks, "/gate/"+info.ID, json.RawMessage(event), nil)
		}
		instance.Serve(stream, &env)
	}))
}

type remoteSigner struct {
	ctx       context.Context
	transport http.RoundTripper
	key       ssh.PublicKey
}

func (s *remoteSigner) PublicKey() ssh.PublicKey { return s.key }
func (s *remoteSigner) Sign(_ io.Reader, data []byte) (*ssh.Signature, error) {
	return s.SignWithAlgorithm(nil, data, "")
}
func (s *remoteSigner) SignWithAlgorithm(_ io.Reader, data []byte, algorithm string) (*ssh.Signature, error) {
	ctx, cancel := context.WithTimeout(s.ctx, 10*time.Second)
	defer cancel()
	var signature ssh.Signature
	err := call(ctx, s.transport, "/host-sign", signing{data, algorithm}, &signature)
	return &signature, err
}

// BrokerDialer carries TCP over a connection to the host. TLS, including
// certificate pinning, runs in the worker on the resulting byte stream.
type BrokerDialer struct{ Dial DialFunc }

func (d BrokerDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errors.New("worker broker supports TCP only")
	}
	r := &http.Request{Method: http.MethodConnect, URL: &url.URL{Host: address}, Host: address, Header: make(http.Header)}
	return connect(ctx, d.Dial, r, http.StatusOK)
}
