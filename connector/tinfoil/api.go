package tinfoil

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/tinfoilsh/monitor/connector/web"
)

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
		return messageError(r, 501, "not_supported_error", "Tinfoil does not expose token counting"), nil
	}
	resp, err := t.RoundTripper.RoundTrip(r)
	if err != nil || !t.messages {
		return resp, err
	}
	return messageResponse(r, resp, t.model, t.streaming)
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
		return nil, fmt.Errorf("inference requests require an unambiguous JSON object of at most %d MiB", web.MaxBodyBytes>>20)
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
		body, err = chatRequest(body)
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
	if err := setJSONBody(r, body); err != nil {
		return nil, err
	}
	return response, nil
}

func setJSONBody(r *http.Request, body object) error {
	raw, err := json.Marshal(body)
	if err != nil {
		return err
	}
	r.Body = io.NopCloser(bytes.NewReader(raw))
	r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil }
	r.ContentLength = int64(len(raw))
	r.TransferEncoding = nil
	r.Header.Del("Content-Length")
	return nil
}
