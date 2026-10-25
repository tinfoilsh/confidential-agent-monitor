package tinfoil

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/facts"
)

// apiTransport adapts the deployed coding clients after the original request
// passes policy. Every upstream request still uses the attested transport.
type apiTransport struct {
	http.RoundTripper
	privateHost string
	enclave     string
	key         *credential.Value
}

func (t apiTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.privateHost != "" && r.URL.Host == t.privateHost {
		// Private .monitor requests need no client credential. Resolve the owner's
		// key only after the request has passed the normal per-operation gate.
		key, err := t.key.Value(r.Context())
		if err != nil {
			return nil, err
		}
		r = r.Clone(r.Context())
		r.URL.Scheme, r.URL.Host, r.Host = "https", t.enclave, ""
		r.Header.Del("X-Api-Key")
		r.Header.Set("Authorization", "Bearer "+key)
	}
	if r.Method == http.MethodPost {
		switch r.URL.Path {
		case "/v1/messages", "/v1/messages/count_tokens":
			return t.messages(r)
		case "/v1/responses":
			body, err := requestObject(r)
			if err != nil {
				return messageError(r, 400, "invalid_request_error", err.Error()), nil
			}
			// Codex 0.153.4 emits developer messages. Tinfoil's Responses backend
			// accepts these instructions under the system role instead.
			input, _ := body["input"].([]any)
			for _, item := range input {
				if message, ok := item.(map[string]any); ok && message["role"] == "developer" {
					message["role"] = "system"
				}
			}
			upstream, err := jsonRequest(r, body)
			if err != nil {
				return nil, err
			}
			return t.RoundTripper.RoundTrip(upstream)
		}
	}
	return t.RoundTripper.RoundTrip(r)
}

func requestObject(r *http.Request) (object, error) {
	defer r.Body.Close()
	const limit = 8 << 20
	raw, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > limit {
		return nil, errors.New("inference request exceeds 8 MiB")
	}
	var body object
	if facts.DecodeNumbers(raw, &body) != nil {
		return nil, errors.New("invalid inference JSON")
	}
	return body, nil
}

func jsonRequest(r *http.Request, body object) (*http.Request, error) {
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	out := r.Clone(r.Context())
	out.Body = io.NopCloser(bytes.NewReader(raw))
	out.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(raw)), nil }
	out.ContentLength = int64(len(raw))
	out.Header.Del("Content-Length")
	return out, nil
}
