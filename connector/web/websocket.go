package web

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/coder/websocket"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
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

// serveWebSocket ends the stream, conn, when either side closes.
func (h Handler) serveWebSocket(ctx context.Context, conn net.Conn, w http.ResponseWriter, r *http.Request, handshake *Request, gate func(context.Context, facts.Event) error, transport http.RoundTripper) {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	end := func() { cancel(); conn.Close() }
	var protocols []string
	for _, protocol := range strings.Split(strings.Join(r.Header.Values("Sec-WebSocket-Protocol"), ","), ",") {
		if protocol = strings.TrimSpace(protocol); protocol != "" {
			protocols = append(protocols, protocol)
		}
	}
	upstream, response, err := websocket.Dial(ctx, r.URL.String(), &websocket.DialOptions{
		HTTPClient: &http.Client{Transport: transport, CheckRedirect: h.CheckRedirect},
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
	defer end()
	defer client.CloseNow()
	client.SetReadLimit(h.MaxBody)
	// Responses may include large images; copy replies without buffering them.
	upstream.SetReadLimit(-1)
	replies := make(chan struct{})
	defer func() { end(); <-replies }()
	go func() {
		defer close(replies)
		defer end()
		for {
			kind, reader, err := upstream.Reader(ctx)
			if err != nil {
				return
			}
			// Classify the whole delivery using the connection's contents and trust.
			// Its payload is opaque to policy and can stream after admission,
			// including large images, without an unbounded allocation.
			if err := gate(ctx, facts.Capture((&WebSocketReceive{Origin: handshake.HTTP.Origin, Host: handshake.HTTP.Host, Path: handshake.HTTP.Path}).Describe(), nil)); err != nil {
				client.Close(websocket.StatusPolicyViolation, "delivery refused")
				return
			}
			writer, err := client.Writer(ctx, kind)
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
	}()
	for {
		kind, body, err := client.Read(ctx)
		if err != nil {
			return
		}
		request := websocketMessage(handshake, kind, body, h.MaxBody)
		if err := gate(ctx, facts.Capture(request.Describe(h.Setup))); err != nil {
			client.Close(websocket.StatusPolicyViolation, "request refused")
			return
		}
		if err := upstream.Write(ctx, kind, body); err != nil {
			return
		}
	}
}

// WebSocketReceive admits one upstream message. Receiving does not repeat the
// request's effects (such as paying for inference) or send data to the upstream.
// Its details carry no method, which no request has.
type WebSocketReceive struct {
	Origin string `json:"origin"`
	Host   string `json:"host"`
	Path   string `json:"path"`
}

func (r *WebSocketReceive) Describe() facts.Observation {
	return facts.Observation{
		Operation:  &facts.Operation{ID: "websocket.receive", Action: "receive"},
		Title:      "Receive WebSocket message from " + r.Host + r.Path,
		Parameters: map[string]any{"origin": r.Origin, "path": r.Path},
		Details:    Details{HTTP: &HTTPFacts{WebSocket: true, Origin: r.Origin, Host: r.Host, Path: r.Path, BodyKind: bodyOpaque}},
	}
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

func websocketMessage(handshake *Request, kind websocket.MessageType, body []byte, limit int64) *Request {
	layer := *handshake.HTTP
	layer.BodyKind = BodyJSON
	request := &Request{HTTP: &layer}
	var err error
	layer.Body, err = decodeJSON(body)
	if _, object := layer.Body.(map[string]any); kind != websocket.MessageText || int64(len(body)) > limit || err != nil || !object {
		layer.Body, layer.BodyKind = nil, bodyOpaque
		request.Invalid = fmt.Sprintf("WebSocket messages must be unambiguous JSON objects of at most %d MiB", limit>>20)
	}
	return request
}
