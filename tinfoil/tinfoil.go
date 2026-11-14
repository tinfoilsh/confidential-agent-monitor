// Package tinfoil connects HTTP inference clients to an attested Tinfoil enclave.
package tinfoil

import (
	"context"
	"embed"
	"errors"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/tinfoilsh/confidential-agent-monitor/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/credential"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/web"
)

var Kind = connector.Kind{PerMessage: true, Placeholders: true, Parse: parseHTTP, New: func() connector.Server { return new(Server) }}

//go:embed *.json
var Presets embed.FS

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

func (s *httpState) Close() error {
	s.closeTransport()
	return nil
}

// Server owns its attested pool; Monitor revokes the pool's uses before Update closes it.
type Server struct{ connector.Resource[*httpState] }

func (s *Server) Update(ctx context.Context, prepared connector.Prepared, secrets map[string]*credential.Value, env *connector.Env) error {
	return s.Replace(func() (*httpState, error) {
		setup := *prepared.Value.(*httpSetup)
		setup.http.Bind(secrets)
		base := env.Transport()
		transport, err := newAttestedTransport(ctx, setup.http.Secrets[apiKeyName], setup.Enclave, setup.Repo, base)
		if err != nil {
			base.CloseIdleConnections()
			return nil, err
		}
		return &httpState{httpSetup: setup, transport: transport,
			closeTransport: func() { transport.CloseIdleConnections(); base.CloseIdleConnections() }}, nil
	})
}

func (s *Server) Serve(stream *connector.Stream, env *connector.Env) {
	if current := s.Load(); current != nil {
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
		current := s.Load()
		if current == nil {
			http.Error(w, "connector unavailable", http.StatusServiceUnavailable)
			return
		}
		current.control().ServeHTTP(w, r)
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
