package tinfoil

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

	"github.com/tinfoilsh/confidential-agent-monitor/connector/slots"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/tinfoil/messages"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/web"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/worker"
	"github.com/tinfoilsh/confidential-agent-monitor/core/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/netx"
	"github.com/tinfoilsh/tinfoil-go/verify"
)

const (
	AttestationPath        = "/.well-known/tinfoil-attestation"
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

type Setup struct {
	Enclave string `json:"enclave"`
	Repo    string `json:"repo"`
}

func Validate(enclave, repo string) error {
	if !slots.ValidOrigin("https://"+enclave) || strings.Trim(enclave, web.HostChars) != "" || strings.Contains(enclave, ":") {
		return errors.New("Tinfoil enclave must be a lowercase HTTPS hostname without a port")
	}
	_, _, _, err := verify.ParseReference(repo)
	return err
}

func (t *Setup) Slot() slots.Slot {
	return slots.Slot{Value: tinfoilKey, Origin: "https://" + t.Enclave, Path: tinfoilAPIPath, Header: "Authorization", Prefix: "Bearer "}
}

func Parse(config json.RawMessage) (*Setup, error) {
	t := new(Setup)
	if err := facts.DecodeNumbers(config, t); err != nil {
		return nil, err
	}
	return t, Validate(t.Enclave, t.Repo)
}

func (t *Setup) Open(ctx context.Context, setup *web.Setup, h worker.Host, domain string, maxBody int64) (connector.Instance, error) {
	base := netx.Transport(h.Dial)
	transport, err := Attest(ctx, h, tinfoilKey, t.Enclave, t.Repo, base)
	if err != nil {
		base.CloseIdleConnections()
		return connector.Instance{}, err
	}
	control := http.NewServeMux()
	control.Handle("POST /chat/completions", &httputil.ReverseProxy{Transport: transport, Rewrite: func(r *httputil.ProxyRequest) {
		key, _ := h.Secret(r.In.Context(), tinfoilKey)
		r.Out.URL, r.Out.Host = &url.URL{Scheme: "https", Host: t.Enclave, Path: chatCompletionsPath}, ""
		r.Out.Header = http.Header{"Authorization": {"Bearer " + key}, "Content-Type": {"application/json"}}
	}})
	serve := func(ctx context.Context, conn net.Conn, name string, target connector.Target, gate connector.Gate) {
		handler := web.Handler{Setup: setup, Transport: transport, TLS: h.TLS, Placeholder: h.Placeholder, Secret: h.Secret, MaxBody: maxBody}
		privateHost := ""
		if target.Host == "" {
			privateHost = name + domain
			named := *setup
			named.Hosts = []string{privateHost}
			handler.Setup = &named
		}
		handler.Prepare = func(r *http.Request, original *web.HTTPFacts) (http.RoundTripper, error) {
			if privateHost != "" && r.URL.Host == privateHost {
				slot := t.Slot()
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
			return prepareAPIRequest(r, original, transport, maxBody)
		}
		handler.Serve(ctx, conn, name, target, gate)
	}
	return connector.Instance{Serve: serve, Control: control, Close: func() error {
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

func prepareAPIRequest(r *http.Request, original *web.HTTPFacts, transport http.RoundTripper, maxBody int64) (http.RoundTripper, error) {
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
		return nil, fmt.Errorf("inference requests require an unambiguous JSON object of at most %d MiB", maxBody>>20)
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
