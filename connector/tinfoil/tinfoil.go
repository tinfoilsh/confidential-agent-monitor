// Package tinfoil connects HTTP inference clients to an attested Tinfoil enclave.
package tinfoil

import (
	"context"
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/connector/web"
)

var Kind = connector.Kind{PerMessage: true, Placeholders: true, Parse: parseHTTP, New: func() connector.Server { return new(Server) }}

const apiKeyName = "TINFOIL_API_KEY"

type httpSetup struct {
	Enclave string `json:"enclave"`
	Repo    string `json:"repo"`
	http    web.Setup
}

func parseHTTP(source connector.Setup) (connector.Prepared, error) {
	setup := new(httpSetup)
	preset := struct {
		*connector.Semantics
		HTTP *web.Preset `json:"http"`
	}{Semantics: &setup.http.Semantics}
	if err := connector.ParseSetup(source, setup, &preset); err != nil {
		return connector.Prepared{}, err
	}
	if err := validateEnclave(setup.Enclave, setup.Repo); err != nil {
		return connector.Prepared{}, err
	}
	setup.http.Preset = preset.HTTP
	setup.http.Slots = []web.Slot{apiKeySlot(setup.Enclave)}
	if err := setup.http.Validate(false); err != nil {
		return connector.Prepared{}, err
	}
	return connector.Prepared{Value: setup, SecretNames: []string{apiKeyName}, Claim: setup.http.Claim,
		Discovery: connector.Discovery{Slots: setup.http.Slots}}, nil
}

func apiKeySlot(enclave string) web.Slot {
	return web.Slot{Value: apiKeyName, Origin: "https://" + enclave, Path: "/v1", Header: "Authorization", Prefix: "Bearer "}
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
	setup.http.Bind(secrets)
	base := env.Transport()
	transport, err := newAttestedTransport(ctx, setup.http.Secrets[apiKeyName], setup.Enclave, setup.Repo, base)
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
	h := s.http
	privateHost := ""
	if stream.Host == "" {
		privateHost = stream.Name + connector.Domain
		h.Hosts = []string{privateHost}
	}
	prepare := func(r *http.Request, original *web.HTTPFacts) (http.RoundTripper, error) {
		if privateHost != "" && r.URL.Host == privateHost {
			slot := apiKeySlot(s.Enclave)
			if r.URL.Path != slot.Path && !strings.HasPrefix(r.URL.Path, slot.Path+"/") {
				return nil, errors.New("Tinfoil API requests must use a " + slot.Path + " path")
			}
			// Put a public placeholder in the normal slot. The shared HTTP path
			// captures the enclave target and resolves the key only after the gate.
			placeholder := h.Placeholder(apiKeyName)
			if placeholder == "" {
				return nil, errors.New("Tinfoil credential is unavailable")
			}
			r.URL.Scheme, r.URL.Host, r.Host = "https", s.Enclave, s.Enclave
			r.Header.Del("X-Api-Key")
			r.Header.Set(slot.Header, slot.Prefix+placeholder)
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

func (s *httpState) control() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /chat/completions", &httputil.ReverseProxy{Transport: s.transport, Rewrite: func(r *httputil.ProxyRequest) {
		key, _ := s.http.Secrets[apiKeyName].Value(r.In.Context())
		r.Out.URL, r.Out.Host = &url.URL{Scheme: "https", Host: s.Enclave, Path: "/v1/chat/completions"}, ""
		r.Out.Header = http.Header{"Authorization": {"Bearer " + key}, "Content-Type": {"application/json"}}
	}})
	return mux
}
