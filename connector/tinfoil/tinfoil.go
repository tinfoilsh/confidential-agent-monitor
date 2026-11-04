// Package tinfoil connects HTTP inference clients to an attested Tinfoil enclave.
package tinfoil

import (
	"context"
	"errors"
	"maps"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/connector/web"
)

var Kind = connector.Kind{PerMessage: true, Parse: parseHTTP, New: func() connector.Server { return new(Server) }}

type httpSetup struct {
	connector.SecretConfig
	Enclave string `json:"enclave"`
	Repo    string `json:"repo"`
	http    *web.Setup
}

func parseHTTP(source connector.Setup) (connector.Prepared, error) {
	setup := new(httpSetup)
	preset := struct {
		*connector.Semantics
		HTTP *web.Preset `json:"http"`
	}{Semantics: &setup.Semantics}
	if err := connector.ParseSetup(source, setup, &preset, &setup.Semantics); err != nil {
		return connector.Prepared{}, err
	}
	if err := validateEnclave(setup.Enclave, setup.Repo); err != nil {
		return connector.Prepared{}, err
	}
	names, err := setup.Declarations("TINFOIL_API_KEY")
	if err != nil {
		return connector.Prepared{}, err
	}
	setup.http = &web.Setup{Preset: preset.HTTP, Credentials: web.Credentials{
		SecretConfig: setup.SecretConfig,
		Slots:        []web.Slot{{Value: "TINFOIL_API_KEY", Origin: "https://" + setup.Enclave, Path: "/v1", Header: "Authorization", Prefix: "Bearer "}},
	}}
	if err := setup.http.Validate(false); err != nil {
		return connector.Prepared{}, err
	}
	route := &web.Setup{Credentials: web.Credentials{Slots: setup.http.Slots}}
	return connector.Prepared{Source: source, Value: setup, SecretNames: names, Claim: route.Claim,
		Discovery: connector.Discovery{Slots: setup.http.Slots, Placeholders: map[string]string{}}}, nil
}

type httpState struct {
	httpSetup
	transport      http.RoundTripper
	closeTransport func()
}

// Server pins its attested pool for all stream and owner-control uses. Monitor
// revokes their contexts before Update; the write lock joins those actual uses.
type Server struct {
	mu      sync.RWMutex
	current *httpState
}

func (s *Server) Update(ctx context.Context, prepared connector.Prepared, secrets map[string]*credential.Value, env *connector.Env) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.close()
	setup := *prepared.Value.(*httpSetup)
	setup.Secrets = maps.Clone(secrets)
	h := *setup.http
	h.Secrets = setup.Secrets
	setup.http = &h
	base := env.Transport()
	transport, err := newAttestedTransport(ctx, setup.Secrets["TINFOIL_API_KEY"], setup.Enclave, setup.Repo, base)
	if err != nil {
		base.CloseIdleConnections()
		return err
	}
	s.current = &httpState{httpSetup: setup, transport: transport,
		closeTransport: func() { transport.CloseIdleConnections(); base.CloseIdleConnections() }}
	return nil
}

func (s *Server) close() {
	if s.current != nil {
		s.current.closeTransport()
		s.current = nil
	}
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.close()
	return nil
}

func (s *Server) Serve(stream *connector.Stream, env *connector.Env) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if current := s.current; current != nil {
		current.serve(stream, env)
	}
}

func (s *httpState) serve(stream *connector.Stream, e *connector.Env) {
	h := *s.http
	privateHost := ""
	if stream.Host == "" {
		privateHost = stream.Name + ".monitor"
		h.Hosts = []string{privateHost}
	}
	prepare := func(r *http.Request, original *web.HTTPFacts) (http.RoundTripper, error) {
		if privateHost != "" && r.URL.Host == privateHost {
			if r.URL.Path != "/v1" && !strings.HasPrefix(r.URL.Path, "/v1/") {
				return nil, errors.New("Tinfoil API requests must use a /v1 path")
			}
			// Put a public placeholder in the normal slot. The shared HTTP path
			// captures the enclave target and resolves the key only after the gate.
			placeholder := h.Placeholder("TINFOIL_API_KEY")
			if placeholder == "" {
				return nil, errors.New("Tinfoil credential is unavailable")
			}
			r.URL.Scheme, r.URL.Host, r.Host = "https", s.Enclave, s.Enclave
			r.Header.Del("X-Api-Key")
			r.Header.Set("Authorization", "Bearer "+placeholder)
		}
		return prepareAPIRequest(r, original, s.transport)
	}
	h.ServeWithTransport(stream, e, s.transport, prepare)
}

func (s *Server) Control() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.RLock()
		defer s.mu.RUnlock()
		if s.current == nil {
			http.Error(w, "connector unavailable", http.StatusServiceUnavailable)
			return
		}
		s.current.control().ServeHTTP(w, r)
	})
}

// Development review, when compiled in, shares this control transport and
// credential identity.
func (s *httpState) control() http.Handler {
	mux := http.NewServeMux()
	registerDevelopmentControl(mux, s)
	mux.Handle("POST /chat/completions", &httputil.ReverseProxy{Transport: s.transport, Rewrite: func(r *httputil.ProxyRequest) {
		key, _ := s.Secrets["TINFOIL_API_KEY"].Value(r.In.Context())
		r.Out.URL, r.Out.Host = &url.URL{Scheme: "https", Host: s.Enclave, Path: "/v1/chat/completions"}, ""
		r.Out.Header = http.Header{"Authorization": {"Bearer " + key}, "Content-Type": {"application/json"}}
	}})
	return mux
}
