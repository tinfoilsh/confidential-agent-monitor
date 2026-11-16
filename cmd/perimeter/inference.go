package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/messages"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/mcp"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/slots"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/web"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/worker"
	"github.com/tinfoilsh/confidential-agent-monitor/core"
	"github.com/tinfoilsh/confidential-agent-monitor/core/attestation"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/netx"
	"github.com/tinfoilsh/tinfoil-go/verify"
	tinfoildoc "github.com/tinfoilsh/tinfoil-go/verify/document"
)

// Tinfoil inference: HTTP and MCP connectors to an attested enclave.

const (
	tinfoilKey             = "TINFOIL_API_KEY"
	attestationTimeout     = 30 * time.Second
	maxAttestationBytes    = 32 << 20
	tinfoilAPIPath         = "/v1"
	countTokensUnsupported = "Tinfoil does not expose token counting"
)

// messageLimits bound the inference responses converted for Messages clients.
var messageLimits = messages.Limits{ErrorBytes: 1 << 20, ResultBytes: 16 << 20, EventBytes: 8 << 20}

type tinfoilSetup struct {
	Enclave string `json:"enclave"`
	Repo    string `json:"repo"`
}

func validateEnclave(enclave, repo string) error {
	if !slots.ValidOrigin("https://"+enclave) || strings.Trim(enclave, web.HostChars) != "" || strings.Contains(enclave, ":") {
		return errors.New("Tinfoil enclave must be a lowercase HTTPS hostname without a port")
	}
	_, _, _, err := verify.ParseReference(repo)
	return err
}

func tinfoilKeySlot(enclave string) slots.Slot {
	return slots.Slot{Value: tinfoilKey, Origin: "https://" + enclave, Path: tinfoilAPIPath, Header: "Authorization", Prefix: "Bearer "}
}

// parseTinfoil reads an inference setup: the enclave's HTTP API, with its key in one fixed slot.
func parseTinfoil(spec ConnectionSpec) (*tinfoilSetup, *web.Setup, slots.Set, error) {
	t := new(tinfoilSetup)
	if err := facts.DecodeNumbers(spec.Config, t); err != nil {
		return nil, nil, slots.Set{}, err
	}
	if err := validateEnclave(t.Enclave, t.Repo); err != nil {
		return nil, nil, slots.Set{}, err
	}
	set, err := slots.New([]slots.Slot{tinfoilKeySlot(t.Enclave)}, httpSlots)
	if err != nil {
		return nil, nil, slots.Set{}, err
	}
	setup, err := web.New(spec.Definition, spec.Options, nil, web.Slots{Claim: set.Claim, Covers: set.Covers, Bind: set.Bind})
	return t, setup, set, err
}

// parseTinfoilMCP reads an MCP setup whose HTTPS server is an attested enclave, and its repository.
func parseTinfoilMCP(spec ConnectionSpec) (*mcp.Setup, string, error) {
	var config struct {
		mcp.Setup
		Repo string `json:"repo"`
	}
	if err := mcp.Decode(spec.Config, spec.Definition, &config, &config.Setup); err != nil {
		return nil, "", err
	}
	u, _ := url.Parse(config.URL)
	if u.Scheme != "https" || u.User != nil {
		return nil, "", errors.New("Tinfoil MCP requires an HTTPS URL without user information")
	}
	return &config.Setup, config.Repo, validateEnclave(u.Host, config.Repo)
}

// attest verifies the enclave before callers can send credentials or MCP discovery.
// Inference and MCP share the same attestation, renewal and TLS key binding.
func attest(ctx context.Context, h worker.Host, key, enclave, repo string, base *http.Transport) (*attestation.Transport, error) {
	if !h.Configured(key) {
		return nil, errors.New("Tinfoil API key is not configured")
	}
	verifier, err := verify.NewVerifier()
	if err != nil {
		return nil, err
	}
	return attestation.New(ctx, attestation.Config{Host: enclave, Path: attestationPath, Nonce: tinfoildoc.RandomNonce, Base: base,
		Timeout: attestationTimeout, MaxBytes: maxAttestationBytes,
		Verify: func(evidence, nonce []byte) (string, time.Time, error) {
			verified, err := verifier.VerifyV3(evidence, nonce, repo)
			if err != nil {
				return "", time.Time{}, fmt.Errorf("verify Tinfoil attestation: %w", err)
			}
			pin, ok := verified.TLSPublicKeyFP()
			if !ok {
				return "", time.Time{}, errors.New("invalid attested Tinfoil TLS key")
			}
			return pin, verified.FreshnessExpiresAt, nil
		}})
}

// open attests the enclave once per setup; its pool serves every stream and owner chat.
func (t *tinfoilSetup) open(ctx context.Context, setup *web.Setup, h worker.Host) (worker.Instance, error) {
	base := upstreamTransport(h.Dial)
	transport, err := attest(ctx, h, tinfoilKey, t.Enclave, t.Repo, base)
	if err != nil {
		base.CloseIdleConnections()
		return worker.Instance{}, err
	}
	control := http.NewServeMux()
	control.Handle("POST /chat/completions", &httputil.ReverseProxy{Transport: transport, Rewrite: func(r *httputil.ProxyRequest) {
		key, _ := h.Secret(r.In.Context(), tinfoilKey)
		r.Out.URL, r.Out.Host = &url.URL{Scheme: "https", Host: t.Enclave, Path: "/v1/chat/completions"}, ""
		r.Out.Header = http.Header{"Authorization": {"Bearer " + key}, "Content-Type": {"application/json"}}
	}})
	serve := func(ctx context.Context, conn net.Conn, name, host string, port uint32, gate core.Gate) {
		handler := web.Handler{Setup: setup, Transport: transport, CheckRedirect: refuseRedirects, Accept: websocket.AcceptOptions{}, UpstreamReadLimit: websocketResponseLimit,
			TLS: h.TLS, Placeholder: h.Placeholder, Secret: h.Secret, MaxBody: maxBodyBytes,
			ServeHTTP: func(ctx context.Context, c net.Conn, server *http.Server) error {
				return netx.ServeConn(ctx, c, server)
			}}
		privateHost := ""
		if host == "" {
			privateHost = name + connectionDomain
			named := *setup
			named.Hosts = []string{privateHost}
			handler.Setup = &named
		}
		handler.Prepare = func(r *http.Request, original *web.HTTPFacts) (http.RoundTripper, error) {
			if privateHost != "" && r.URL.Host == privateHost {
				slot := tinfoilKeySlot(t.Enclave)
				if r.URL.Path != slot.Path && !strings.HasPrefix(r.URL.Path, slot.Path+"/") {
					return nil, errors.New("Tinfoil API requests must use a " + slot.Path + " path")
				}
				// Put a public placeholder in the normal slot. The shared HTTP path
				// captures the enclave target and resolves the key only after the gate.
				placeholder := h.Placeholder(tinfoilKey)
				if placeholder == "" {
					return nil, errors.New("Tinfoil credential is unavailable")
				}
				r.URL.Scheme, r.URL.Host, r.Host = "https", t.Enclave, t.Enclave
				r.Header.Del("X-Api-Key")
				r.Header.Set(slot.Header, slot.Prefix+placeholder)
			}
			return prepareAPIRequest(r, original, transport)
		}
		handler.Serve(ctx, conn, name, host, port, gate)
	}
	return worker.Instance{Serve: serve, Control: control, Close: func() error {
		transport.CloseIdleConnections()
		base.CloseIdleConnections()
		return nil
	}}, nil
}

// apiTransport only adapts responses. Request normalization is complete before
// the gate, and every upstream request uses the original attested transport.
type apiTransport struct {
	http.RoundTripper
	messages    bool
	streaming   bool
	model       any
	countTokens bool
}

func (t apiTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	// The deployed router has no token-count endpoint. Let Claude use its local
	// estimate instead of making a billed completion disguised as token counting.
	if t.countTokens {
		return messages.Error(r, http.StatusNotImplemented, "not_supported_error", countTokensUnsupported), nil
	}
	resp, err := t.RoundTripper.RoundTrip(r)
	if err != nil || !t.messages {
		return resp, err
	}
	return messages.Response(r, resp, t.model, t.streaming, messageLimits)
}

// prepareAPIRequest consumes the web parser's unambiguous JSON, normalizes the
// deployed coding clients and leaves response conversion for after execution.
func prepareAPIRequest(r *http.Request, original *web.HTTPFacts, transport http.RoundTripper) (http.RoundTripper, error) {
	if r.Method != http.MethodPost {
		return nil, nil
	}
	switch r.URL.Path {
	case "/v1/messages", "/v1/messages/count_tokens", "/v1/responses":
	default:
		return nil, nil
	}
	body, ok := original.Body.(map[string]any)
	if original.BodyKind != web.BodyJSON || !ok {
		return nil, fmt.Errorf("inference requests require an unambiguous JSON object of at most %d MiB", maxBodyBytes>>20)
	}
	response := apiTransport{RoundTripper: transport}
	if r.URL.Path == "/v1/responses" {
		// Codex 0.153.4 emits developer messages. Tinfoil's Responses backend
		// accepts these instructions under the system role instead.
		input, _ := body["input"].([]any)
		for _, item := range input {
			if message, ok := item.(map[string]any); ok && message["role"] == "developer" {
				message["role"] = "system"
			}
		}
	} else {
		response.messages, response.model = true, body["model"]
		response.streaming, _ = body["stream"].(bool)
		var err error
		body, err = messages.Request(body)
		if err != nil {
			return nil, err
		}
		if r.URL.Path == "/v1/messages/count_tokens" {
			response.countTokens = true
			return response, nil
		}
		r.URL.Path, r.URL.RawPath, r.URL.RawQuery = "/v1/chat/completions", "", ""
		r.Header.Del("Anthropic-Version")
		r.Header.Del("Anthropic-Beta")
		// Response conversion reads uncompressed bytes, including streamed events.
		r.Header.Set("Accept-Encoding", "identity")
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil }
	r.ContentLength = int64(len(raw))
	r.TransferEncoding = nil
	r.Header.Del("Content-Length")
	return response, nil
}
