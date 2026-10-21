// Package tinfoil connects HTTP inference clients to an attested Tinfoil enclave.
package tinfoil

import (
	"context"
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/web"
	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/tinfoil-go/verifier"
)

var Definition = connector.Definition{PerMessage: true, NewConfig: func() connector.Server { return new(Server) }, Requests: []connector.Request{new(web.Request), new(web.WebSocketReceive)}}

type Server struct {
	connector.SecretConfig
	Enclave   string `json:"enclave"`
	Repo      string `json:"repo"`
	http      *web.HTTP
	transport http.RoundTripper
}

func (s *Server) UnmarshalJSON(raw []byte) error {
	type plain Server
	if err := facts.DecodeNumbers(raw, (*plain)(s)); err != nil {
		return err
	}
	u, err := url.Parse("https://" + s.Enclave)
	if err != nil || !web.ValidOrigin("https://"+s.Enclave) || u.Port() != "" || strings.Trim(s.Enclave, "abcdefghijklmnopqrstuvwxyz0123456789.-") != "" {
		return errors.New("Tinfoil enclave must be a lowercase HTTPS hostname without a port")
	}
	if _, _, _, err := verifier.ParseReference(s.Repo); err != nil {
		return err
	}
	s.http = &web.HTTP{Credentials: web.Credentials{
		SecretConfig: connector.SecretConfig{Secrets: s.SecretValues()},
		Slots:        []web.Slot{{Value: "TINFOIL_API_KEY", Origin: "https://" + s.Enclave, Path: "/v1", Header: "Authorization", Prefix: "Bearer "}},
	}}
	return s.http.Validate(false)
}

// HTTPConfig exposes only the existing client routing and placeholder contract.
func (s *Server) HTTPConfig() *web.HTTP              { return s.http }
func (s *Server) Claim(host string, port uint32) int { return s.http.Claim(host, port) }

func (s *Server) Run(ctx context.Context, e *connector.Env, serve func(context.Context)) error {
	key := s.Secrets["TINFOIL_API_KEY"]
	if key == nil || key.Raw() == nil {
		return errors.New("Tinfoil API key is not configured")
	}
	base := e.Transport()
	defer base.CloseIdleConnections()
	t, err := newAttestedTransport(s, base)
	if err != nil {
		return err
	}
	defer t.CloseIdleConnections()
	if _, err := t.current(ctx, nil); err != nil {
		return err
	}
	s.transport = apiTransport{t}
	serve(ctx)
	return nil
}

func (s *Server) Serve(stream *connector.Stream, e *connector.Env) {
	s.http.ServeWithTransport(stream, e, s.transport)
}

// Control uses the same attested transport and credential handle for Monitor's
// own inference. Private controls also work through an isolated connector worker.
func (s *Server) Control() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /chat/completions", &httputil.ReverseProxy{Transport: s.transport, Rewrite: func(r *httputil.ProxyRequest) {
		key, _ := s.Secrets["TINFOIL_API_KEY"].Value(r.In.Context())
		r.Out.URL, r.Out.Host = &url.URL{Scheme: "https", Host: s.Enclave, Path: "/v1/chat/completions"}, ""
		r.Out.Header = http.Header{"Authorization": {"Bearer " + key}, "Content-Type": {"application/json"}}
	}})
	return mux
}
