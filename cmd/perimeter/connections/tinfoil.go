package connections

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
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/config"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/messages"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/sandbox"
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

const (
	tinfoilKey             = "TINFOIL_API_KEY"
	attestationTimeout     = 30 * time.Second
	maxAttestationBytes    = 32 << 20
	tinfoilAPIPath         = "/v1"
	chatCompletionsPath    = "/v1/chat/completions"
	messagesPath           = "/v1/messages"
	countTokensPath        = "/v1/messages/count_tokens"
	responsesPath          = "/v1/responses"
	countTokensUnsupported = "Tinfoil does not expose token counting"
)

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

func parseTinfoil(spec config.ConnectionSpec, p *Setup) error {
	t := new(tinfoilSetup)
	if err := facts.DecodeNumbers(spec.Config, t); err != nil {
		return err
	}
	if err := validateEnclave(t.Enclave, t.Repo); err != nil {
		return err
	}
	set, err := slots.New([]slots.Slot{tinfoilKeySlot(t.Enclave)}, httpSlots)
	if err != nil {
		return err
	}
	setup, err := web.New(spec.Definition, spec.Options, nil, web.Slots{Claim: set.Claim, Covers: set.Covers, Bind: set.Bind})
	if err != nil {
		return err
	}
	p.Open = func(ctx context.Context, h worker.Host) (worker.Instance, error) { return t.open(ctx, setup, h) }
	return httpSetup(p, setup, set)
}

func parseTinfoilMCP(spec config.ConnectionSpec, p *Setup) error {
	var cfg struct {
		mcp.Setup
		Repo string `json:"repo"`
	}
	if err := mcp.Decode(spec.Config, spec.Definition, &cfg, &cfg.Setup); err != nil {
		return err
	}
	u, _ := url.Parse(cfg.URL)
	if u.Scheme != "https" || u.User != nil {
		return errors.New("Tinfoil MCP requires an HTTPS URL without user information")
	}
	if err := validateEnclave(u.Host, cfg.Repo); err != nil {
		return err
	}
	return mcpSetup(p, &cfg.Setup, cfg.Repo)
}

func attest(ctx context.Context, h worker.Host, secret, enclave, repo string, base *http.Transport) (*attestation.Transport, error) {
	if !h.Configured(secret) {
		return nil, errors.New("Tinfoil API key is not configured")
	}
	verifier, err := verify.NewVerifier()
	if err != nil {
		return nil, err
	}
	return attestation.New(ctx, attestation.Config{Host: enclave, Path: sandbox.AttestationPath, Nonce: tinfoildoc.RandomNonce, Base: base,
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

func (t *tinfoilSetup) open(ctx context.Context, setup *web.Setup, h worker.Host) (worker.Instance, error) {
	base := UpstreamTransport(h.Dial)
	transport, err := attest(ctx, h, tinfoilKey, t.Enclave, t.Repo, base)
	if err != nil {
		base.CloseIdleConnections()
		return worker.Instance{}, err
	}
	control := http.NewServeMux()
	control.Handle("POST /chat/completions", &httputil.ReverseProxy{Transport: transport, Rewrite: func(r *httputil.ProxyRequest) {
		key, _ := h.Secret(r.In.Context(), tinfoilKey)
		r.Out.URL, r.Out.Host = &url.URL{Scheme: "https", Host: t.Enclave, Path: chatCompletionsPath}, ""
		r.Out.Header = http.Header{"Authorization": {"Bearer " + key}, "Content-Type": {"application/json"}}
	}})
	serve := func(ctx context.Context, conn net.Conn, name, host string, port uint32, gate core.Gate) {
		handler := web.Handler{Setup: setup, Transport: transport, CheckRedirect: RefuseRedirects, Accept: websocket.AcceptOptions{}, UpstreamReadLimit: websocketResponseLimit,
			TLS: h.TLS, ServeHTTP: netx.ServeConn, Placeholder: h.Placeholder, Secret: h.Secret, MaxBody: maxBodyBytes}
		privateHost := ""
		if host == "" {
			privateHost = name + Domain
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
				placeholder := h.Placeholder(tinfoilKey)
				if placeholder == "" {
					return nil, errors.New("Tinfoil credential is unavailable")
				}
				r.URL.Scheme, r.URL.Host = "https", t.Enclave
				r.Host = t.Enclave
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

type apiTransport struct {
	http.RoundTripper
	translate   bool
	streaming   bool
	model       any
	countTokens bool
}

func (t apiTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.countTokens {
		return messages.Error(r, http.StatusNotImplemented, "not_supported_error", countTokensUnsupported), nil
	}
	resp, err := t.RoundTripper.RoundTrip(r)
	if err != nil || !t.translate {
		return resp, err
	}
	return messages.Response(r, resp, t.model, t.streaming, messageLimits)
}

func prepareAPIRequest(r *http.Request, original *web.HTTPFacts, transport http.RoundTripper) (http.RoundTripper, error) {
	if r.Method != http.MethodPost {
		return nil, nil
	}
	rt := apiTransport{RoundTripper: transport}
	switch r.URL.Path {
	case responsesPath:
	case messagesPath:
		rt.translate = true
	case countTokensPath:
		rt.translate, rt.countTokens = true, true
	default:
		return nil, nil
	}
	body, ok := original.Body.(map[string]any)
	if original.BodyKind != web.BodyJSON || !ok {
		return nil, fmt.Errorf("inference requests require an unambiguous JSON object of at most %d MiB", maxBodyBytes>>20)
	}
	if !rt.translate {
		input, _ := body["input"].([]any)
		for _, item := range input {
			if message, ok := item.(map[string]any); ok && message["role"] == "developer" {
				message["role"] = "system"
			}
		}
	} else {
		rt.model = body["model"]
		rt.streaming, _ = body["stream"].(bool)
		var err error
		body, err = messages.Request(body)
		if err != nil {
			return nil, err
		}
		if rt.countTokens {
			return rt, nil
		}
		r.URL.Path, r.URL.RawPath, r.URL.RawQuery = chatCompletionsPath, "", ""
		r.Header.Del("Anthropic-Version")
		r.Header.Del("Anthropic-Beta")
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
	return rt, nil
}
