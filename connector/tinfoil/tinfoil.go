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
	if err := validateEnclave(s.Enclave, s.Repo); err != nil {
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
	t, err := newAttestedTransport(ctx, s.Enclave, s.Repo, base)
	if err != nil {
		return err
	}
	defer t.CloseIdleConnections()
	s.transport = t
	serve(ctx)
	return nil
}

func (s *Server) Serve(stream *connector.Stream, e *connector.Env) {
	if stream.Host != "" {
		s.http.ServeWithTransport(stream, e, apiTransport{RoundTripper: s.transport})
		return
	}
	// The existing .monitor route has already authenticated and selected this
	// connection. Parse the private HTTP(S) request, then gate its upstream meaning.
	privateHost := stream.Name + ".monitor"
	local := *stream
	local.Gate = func(ctx context.Context, request connector.Request) error {
		if r, ok := request.(*web.Request); ok && r.Invalid == "" && r.HTTP.Host == privateHost {
			if r.HTTP.Path != "/v1" && !strings.HasPrefix(r.HTTP.Path, "/v1/") {
				r.Invalid = "Tinfoil API requests must use a /v1 path"
			} else {
				r.HTTP.Origin, r.HTTP.Host = "https://"+s.Enclave, s.Enclave
				r.HTTP.Secrets = []string{"TINFOIL_API_KEY"}
			}
		}
		return stream.Gate(ctx, request)
	}
	h := *s.http
	h.Hosts = []string{privateHost}
	h.ServeWithTransport(&local, e, apiTransport{RoundTripper: s.transport, privateHost: privateHost, enclave: s.Enclave, key: s.Secrets["TINFOIL_API_KEY"]})
}

// Control uses the same attested transport and credential handle for Monitor's
// own inference. Private controls also work through an isolated connector worker.
func (s *Server) Control() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /chat/completions", &httputil.ReverseProxy{Transport: apiTransport{RoundTripper: s.transport}, Rewrite: func(r *httputil.ProxyRequest) {
		key, _ := s.Secrets["TINFOIL_API_KEY"].Value(r.In.Context())
		r.Out.URL, r.Out.Host = &url.URL{Scheme: "https", Host: s.Enclave, Path: "/v1/chat/completions"}, ""
		r.Out.Header = http.Header{"Authorization": {"Bearer " + key}, "Content-Type": {"application/json"}}
	}})
	return mux
}
