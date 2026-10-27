package web

import (
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"strings"

	"github.com/coder/websocket"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/facts"
)

// Only RFC 6455 upgrades are supported. The preset must separately recognize
// the handshake and every JSON message; HTTP approvals never authorize them.
func websocketUpgrade(r *http.Request) (bool, error) {
	if r.Header["Upgrade"] == nil {
		return false, nil
	}
	if len(r.Header.Values("Upgrade")) != 1 || !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") {
		return false, errors.New("protocol upgrades other than WebSocket are refused")
	}
	key, err := base64.StdEncoding.DecodeString(r.Header.Get("Sec-WebSocket-Key"))
	if r.Method != http.MethodGet || r.ProtoMajor != 1 || r.ProtoMinor != 1 ||
		len(r.Header.Values("Sec-WebSocket-Key")) != 1 || err != nil || len(key) != 16 ||
		len(r.Header.Values("Sec-WebSocket-Version")) != 1 || r.Header.Get("Sec-WebSocket-Version") != "13" {
		return false, errors.New("invalid WebSocket handshake")
	}
	for _, token := range strings.Split(strings.Join(r.Header.Values("Connection"), ","), ",") {
		if strings.EqualFold(strings.TrimSpace(token), "upgrade") {
			return true, nil
		}
	}
	return false, errors.New("WebSocket handshake requires Connection: Upgrade")
}

func (h *Setup) serveWebSocket(w http.ResponseWriter, r *http.Request, handshake *Request, s *connector.Stream, transport http.RoundTripper) {
	var protocols []string
	for _, protocol := range strings.Split(strings.Join(r.Header.Values("Sec-WebSocket-Protocol"), ","), ",") {
		if protocol = strings.TrimSpace(protocol); protocol != "" {
			protocols = append(protocols, protocol)
		}
	}
	upstream, response, err := websocket.Dial(s.Context, r.URL.String(), &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error {
			return errors.New("redirects are refused")
		}},
		HTTPHeader: websocketHeaders(r.Header), Subprotocols: protocols,
	})
	if response != nil {
		// Preserve provider metadata (including Codex turn state), while each
		// side negotiates its own framing, key, and optional subprotocol.
		for name, values := range websocketHeaders(response.Header) {
			w.Header()[name] = values
		}
	}
	if err != nil {
		// Dial errors can contain the credential-bearing upstream URL.
		status := http.StatusBadGateway
		if response != nil && response.StatusCode >= 400 && response.StatusCode <= 599 {
			status = response.StatusCode
		}
		http.Error(w, "the upstream WebSocket handshake failed", status)
		return
	}
	defer upstream.CloseNow()
	options := &websocket.AcceptOptions{}
	if protocol := upstream.Subprotocol(); protocol != "" {
		options.Subprotocols = []string{protocol}
	}
	client, err := websocket.Accept(w, r, options)
	if err != nil {
		return
	}
	// A hijacked HTTP connection no longer triggers http.Server's closed state.
	defer s.Close()
	defer client.CloseNow()
	client.SetReadLimit(maxBodyBytes)
	// Responses may include large images; copy replies without buffering them.
	upstream.SetReadLimit(-1)
	defer connector.PumpReplies(s, func() {
		for {
			kind, reader, err := upstream.Reader(s.Context)
			if err != nil {
				return
			}
			// Classify the whole delivery using the account's contents and trust.
			// Its payload is opaque to policy and can stream after admission,
			// including large images, without an unbounded allocation.
			if err := s.Gate(s.Context, h.Capture((&WebSocketReceive{Origin: handshake.HTTP.Origin, Host: handshake.HTTP.Host, Path: handshake.HTTP.Path}).Describe())); err != nil {
				client.Close(websocket.StatusPolicyViolation, "delivery refused by monitor; see activity")
				return
			}
			writer, err := client.Writer(s.Context, kind)
			if err != nil {
				return
			}
			if _, err := io.Copy(writer, reader); err != nil {
				return
			}
			if err := writer.Close(); err != nil {
				return
			}
		}
	})()
	for {
		kind, body, err := client.Read(s.Context)
		if err != nil {
			return
		}
		request := websocketMessage(handshake, kind, body)
		if err := s.Gate(s.Context, h.Capture((request).Describe(h))); err != nil {
			client.Close(websocket.StatusPolicyViolation, "request refused by monitor; see activity")
			return
		}
		if err := upstream.Write(s.Context, kind, body); err != nil {
			return
		}
	}
}

// WebSocketReceive admits one upstream message. Receiving does not repeat the
// request's effects (such as paying for inference) or send data to the upstream.
// The account supplies a conservative label for the entire opaque payload.
type WebSocketReceive struct {
	Origin string `json:"origin"`
	Host   string `json:"host"`
	Path   string `json:"path"`
}

func (r *WebSocketReceive) Describe() (facts.Facts, error) {
	return facts.Facts{
		Operation:  &facts.Operation{ID: "websocket.receive", Action: "receive", Effects: []string{"read"}},
		Title:      "Receive WebSocket message from " + r.Host + r.Path,
		Parameters: map[string]any{"origin": r.Origin, "path": r.Path},
		Details:    Details{HTTP: &HTTPFacts{WebSocket: true, Origin: r.Origin, Host: r.Host, Path: r.Path, BodyKind: "opaque"}},
		Context:    facts.Context{Sends: "me"},
	}, nil
}

func websocketHeaders(header http.Header) http.Header {
	header = header.Clone()
	for _, token := range strings.Split(strings.Join(header.Values("Connection"), ","), ",") {
		header.Del(strings.TrimSpace(token))
	}
	for _, name := range []string{"Connection", "Upgrade", "Keep-Alive", "Proxy-Connection", "Proxy-Authorization", "Proxy-Authenticate", "Te", "Trailer", "Transfer-Encoding", "Content-Length", "Sec-WebSocket-Key", "Sec-WebSocket-Version", "Sec-WebSocket-Accept", "Sec-WebSocket-Extensions", "Sec-WebSocket-Protocol"} {
		header.Del(name)
	}
	return header
}

func websocketMessage(handshake *Request, kind websocket.MessageType, body []byte) *Request {
	layer := *handshake.HTTP
	layer.BodyKind = "json"
	request := &Request{HTTP: &layer}
	var err error
	layer.Body, err = decodeJSON(body)
	if _, object := layer.Body.(map[string]any); kind != websocket.MessageText || len(body) > maxBodyBytes || err != nil || !object {
		layer.Body, layer.BodyKind = nil, "opaque"
		request.Invalid = "WebSocket messages must be unambiguous JSON objects of at most 8 MiB"
	}
	return request
}
