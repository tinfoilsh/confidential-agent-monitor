package web

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/coder/websocket"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

const (
	httpsPort = 443
	httpPort  = 80

	bodyNone    = "none"
	bodyOpaque  = "opaque"
	BodyJSON    = "json"
	bodyForm    = "form"
	bodyAny     = "any"
	bodyGraphQL = "graphql"

	HostChars = "abcdefghijklmnopqrstuvwxyz0123456789.-:"
)

var (
	methods = []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions}
	// Some servers let these replace the method the policy saw.
	methodOverrides = []string{"X-Http-Method-Override", "X-Http-Method", "X-Method-Override"}
)

// HTTP forwards unauthenticated requests for Hosts on ports 80 and 443, and authenticated ones for slot origins.
type Setup struct {
	Hosts         []string
	Preset        *Preset
	title, origin string
	slots         Slots
}

// Handler serves a setup's streams with the host's capabilities.
type Handler struct {
	*Setup
	// Transport sends admitted requests, after credential placement, exactly as they were captured.
	Transport http.RoundTripper
	// TLS terminates a stream's TLS with a certificate for host, the stream's host.
	TLS       func(ctx context.Context, host string) *tls.Config
	ServeHTTP func(ctx context.Context, conn net.Conn, server *http.Server) error
	// Placeholder is the public reference agents send in place of a credential; "" if it has none.
	Placeholder func(name string) string
	Secret      func(ctx context.Context, name string) (string, error)
	Prepare     PrepareRequest
	// CheckRedirect decides a WebSocket handshake's redirects, as http.Client's does. A followed redirect is a
	// request the gate never admitted, with credentials placed again, so it must not be followed unless admitted.
	CheckRedirect func(req *http.Request, via []*http.Request) error
	// MaxBody bounds the bodies and WebSocket messages it decodes; larger bodies are opaque.
	MaxBody int64

	// Accept accepts agent WebSockets; its Subprotocols are replaced by the one the upstream agreed.
	Accept websocket.AcceptOptions
	// UpstreamReadLimit bounds each upstream WebSocket message as websocket.Conn.SetReadLimit does;
	// replies stream to the agent unbuffered.
	UpstreamReadLimit int64
}

// PrepareRequest may normalize validated input before its final capture. It must
// perform no I/O or credential resolution. An optional returned transport may
// adapt the response, but must send the prepared request without rewriting it.
type PrepareRequest func(*http.Request, *HTTPFacts) (http.RoundTripper, error)

// Serve validates client input, prepares and captures the upstream request,
// gates it, then places credentials and sends those admitted bytes.
func (h Handler) Serve(ctx context.Context, conn net.Conn, _, host string, port uint32, gate func(context.Context, facts.Event) error) {
	c := conn
	if port != httpPort {
		c = tls.Server(conn, h.TLS(ctx, host))
	}
	h.ServeHTTP(ctx, c, &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := h.parseRequest(r, host, port)
		upstreamTransport := h.Transport
		if h.Prepare != nil && request.Invalid == "" {
			prepared := r.Clone(r.Context())
			responseTransport, err := h.Prepare(prepared, request.HTTP)
			if err != nil {
				request.Invalid = strings.ToValidUTF8(err.Error(), "�")
			} else {
				r = prepared
				// Capture the actual prepared request, including its credential slots.
				// This also checks that normalization kept the target in this setup.
				request = newRequest(r)
				if err := request.capture(&h, r); err != nil {
					request.Invalid = strings.ToValidUTF8(err.Error(), "�")
				}
				if responseTransport != nil {
					upstreamTransport = responseTransport
				}
			}
		}
		if err := gate(r.Context(), facts.Capture(request.Describe(h.Setup))); err != nil {
			log.Printf("refused %s %s%s: %v", r.Method, r.Host, r.URL.Path, err)
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		upstream := placing{upstreamTransport, request.place, h.Secret}
		if request.HTTP.WebSocket {
			h.serveWebSocket(ctx, conn, w, r, request, gate, upstream)
			return
		}
		proxy(upstream).ServeHTTP(w, r)
	})})
}

// placing writes the admitted request's credentials into it as the last change before it is sent.
type placing struct {
	base   http.RoundTripper
	place  func(*http.Request, func(context.Context, string) (string, error)) (*http.Request, error)
	secret func(context.Context, string) (string, error)
}

func (t placing) RoundTrip(r *http.Request) (*http.Response, error) {
	if t.place != nil {
		var err error
		if r, err = t.place(r, t.secret); err != nil {
			return nil, err
		}
	}
	return t.base.RoundTrip(r)
}

// The parsed request already names its upstream; placement is the last change before it is sent.
func proxy(transport http.RoundTripper) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Transport: transport,
		Rewrite:   func(*httputil.ProxyRequest) {},
		// The error may quote the request with its credentials in place.
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, _ error) {
			log.Printf("upstream %s %s failed", r.Method, r.Host)
			http.Error(w, "the upstream request failed", http.StatusBadGateway)
		},
	}
}

// Parsing retains errors as part of the connector request so the monitor records
// them through Describe. Unvalidated input is never interpreted as an operation.
func (h *Handler) parseRequest(r *http.Request, host string, port uint32) *Request {
	request := newRequest(r)
	if err := request.parse(h, r, host, port); err != nil {
		request.Invalid = strings.ToValidUTF8(err.Error(), "�")
	}
	return request
}

func newRequest(r *http.Request) *Request {
	return &Request{HTTP: &HTTPFacts{
		Method: strings.ToValidUTF8(r.Method, "�"), Host: strings.ToValidUTF8(r.Host, "�"),
		Path: strings.ToValidUTF8(r.URL.EscapedPath(), "�"),
	}}
}

// parse checks the original request against its authenticated channel before any
// normalization. A selected connection has no channel host to match.
func (request *Request) parse(h *Handler, r *http.Request, channel string, channelPort uint32) error {
	scheme, host, port, err := authority(r)
	if err != nil {
		return err
	}
	if channel != "" && (host != strings.ToLower(channel) || port != channelPort) {
		return fmt.Errorf("a channel to %s:%d cannot carry a request for %s:%d", channel, channelPort, host, port)
	}
	r.URL.Scheme, r.URL.Host = scheme, strings.TrimPrefix(origin(scheme, host, port), scheme+"://")
	r.Host = r.URL.Host
	return request.capture(h, r)
}

// capture validates and describes an upstream request without changing its
// meaning. Both the original and any prepared request use the same checks.
func (request *Request) capture(h *Handler, r *http.Request) error {
	if r.URL.Opaque != "" || r.URL.User != nil || r.URL.Fragment != "" || r.Host != r.URL.Host {
		return errors.New("invalid upstream request target")
	}
	scheme := r.URL.Scheme
	host, port, err := canonicalAuthority(scheme, r.URL.Host)
	if err != nil {
		return err
	}
	switch {
	case h.Claim(host, port) < 0:
		return fmt.Errorf("this service does not serve %s:%d", host, port)
	case !slices.Contains(methods, r.Method):
		return fmt.Errorf("method %s is refused", r.Method)
	case len(r.Trailer) > 0:
		return errors.New("trailers are refused")
	}
	upgrade, err := websocketUpgrade(r)
	if err != nil {
		return err
	}
	// The proxy drops headers that Connection names, after the gate would have seen them.
	for _, token := range strings.FieldsFunc(strings.Join(r.Header.Values("Connection"), ","), func(c rune) bool { return c == ',' || c == ' ' }) {
		if !strings.EqualFold(token, "keep-alive") && !strings.EqualFold(token, "close") && !(upgrade && strings.EqualFold(token, "upgrade")) {
			return fmt.Errorf("Connection: %s is refused", token)
		}
	}
	for _, name := range methodOverrides {
		if r.Header[name] != nil {
			return fmt.Errorf("%s is refused", name)
		}
	}
	if err := canonicalPath(r.URL); err != nil {
		return err
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || !validText(query) || !validText(r.Header) {
		return errors.New("the query or headers are not valid UTF-8 text")
	}
	origin := origin(scheme, host, port)
	r.URL.Scheme, r.URL.Host, r.URL.RawPath, r.URL.RawQuery = scheme, strings.TrimPrefix(origin, scheme+"://"), "", encodeQuery(query)
	r.Host = r.URL.Host
	layer := &HTTPFacts{WebSocket: upgrade, Method: r.Method, Origin: origin, Host: host, Path: r.URL.Path, Query: query, Headers: r.Header.Clone()}
	request.HTTP = layer
	if err := inspect(r, layer, h.MaxBody); err != nil {
		return err
	}
	if upgrade && layer.BodyKind != bodyNone {
		return errors.New("WebSocket handshakes cannot carry a body")
	}
	// Binding uses the stream's immutable settings. Replacing them cancels the stream.
	layer.Secrets, request.place, err = h.slots.Bind(r, origin, h.Placeholder)
	if err != nil {
		return err
	}
	for name, values := range r.Header {
		if len(values) == 1 && strings.HasPrefix(values[0], "{") {
			if v, err := decodeJSON([]byte(values[0])); err == nil {
				if layer.HeaderJSON == nil {
					layer.HeaderJSON = map[string]any{}
				}
				layer.HeaderJSON[name] = v
			}
		}
	}
	request.GraphQL = graphql(layer.Body, query)
	return nil
}

// authority returns the request's scheme, host and effective port, refusing any other spelling of them.
func authority(r *http.Request) (scheme, host string, port uint32, err error) {
	if r.URL.Host != "" || r.URL.Opaque != "" {
		return "", "", 0, errors.New("only origin-form request targets are accepted")
	}
	scheme = "http"
	if r.TLS != nil {
		scheme = "https"
	}
	host, port, err = canonicalAuthority(scheme, r.Host)
	if err == nil && r.TLS != nil && r.TLS.ServerName != "" && !strings.EqualFold(r.TLS.ServerName, host) {
		err = fmt.Errorf("TLS server name %s differs from host %s", r.TLS.ServerName, host)
	}
	return
}

func canonicalAuthority(scheme, authority string) (string, uint32, error) {
	port := uint32(httpPort)
	if scheme == "https" {
		port = httpsPort
	} else if scheme != "http" {
		return "", 0, errors.New("only HTTP and HTTPS request targets are accepted")
	}
	u := url.URL{Host: authority}
	host := strings.ToLower(u.Hostname())
	spelled := host
	if strings.Contains(host, ":") {
		spelled = "[" + host + "]"
	}
	if text := u.Port(); text != "" {
		n, err := strconv.ParseUint(text, 10, 16)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != text {
			return "", 0, fmt.Errorf("invalid port in %q", authority)
		}
		port, spelled = uint32(n), spelled+":"+text
	}
	switch {
	case host == "" || strings.Trim(host, HostChars) != "" || !strings.EqualFold(authority, spelled):
		return "", 0, fmt.Errorf("noncanonical host %q", authority)
	case (scheme == "http") != (port == httpPort):
		return "", 0, fmt.Errorf("%s cannot use port %d", scheme, port)
	}
	return host, port, nil
}

func origin(scheme, host string, port uint32) string {
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if (scheme == "https" && port != httpsPort) || (scheme == "http" && port != httpPort) {
		host += ":" + strconv.Itoa(int(port))
	}
	return scheme + "://" + host
}

// canonicalPath refuses paths whose segments an upstream could split, unescape again or resolve differently.
func canonicalPath(u *url.URL) error {
	if !strings.HasPrefix(u.Path, "/") || !utf8.ValidString(u.Path) || strings.ContainsAny(u.Path, "\\%\x00") {
		return errors.New("the path is not canonical")
	}
	segments := strings.Split(u.Path[1:], "/")
	for i, segment := range segments {
		if segment == "." || segment == ".." || (segment == "" && i < len(segments)-1) {
			return errors.New("the path is not canonical")
		}
	}
	return nil
}

// validText refuses names and values that JSON would alter, so policy compares what is sent.
func validText(values map[string][]string) bool {
	for key, entries := range values {
		if !utf8.ValidString(key) {
			return false
		}
		for _, entry := range entries {
			if !utf8.ValidString(entry) {
				return false
			}
		}
	}
	return true
}

// Spaces become %20, since not every upstream reads + as a space.
func encodeQuery(q url.Values) string {
	return strings.ReplaceAll(q.Encode(), "+", "%20")
}

// inspect decodes a complete body of at most limit bytes without repeated names; anything else is opaque and still forwarded.
func inspect(r *http.Request, layer *HTTPFacts, limit int64) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, limit+1))
	if err != nil {
		return err
	}
	r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), r.Body))
	if int64(len(body)) <= limit {
		r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	}
	layer.BodyKind = bodyOpaque
	types := r.Header.Values("Content-Type")
	switch {
	case len(body) == 0:
		layer.BodyKind = bodyNone
		return nil
	case int64(len(body)) > limit || len(r.Header.Values("Content-Encoding")) > 0 || len(types) != 1 || !utf8.Valid(body):
		return nil
	}
	mediaType, params, err := mime.ParseMediaType(types[0])
	if err != nil || (params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8")) {
		return nil
	}
	switch {
	case mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"):
		if layer.Body, err = decodeJSON(body); err == nil {
			layer.BodyKind = BodyJSON
		}
	case mediaType == "application/x-www-form-urlencoded":
		form, err := url.ParseQuery(string(body))
		if err == nil {
			seen := map[string]bool{}
			for key, values := range form {
				name := strings.Map(fold, key)
				if len(values) != 1 || seen[name] || !utf8.ValidString(key) || !utf8.ValidString(values[0]) {
					return nil
				}
				seen[name] = true
			}
			layer.Form, layer.BodyKind = form, bodyForm
		}
	}
	return nil
}

var errAmbiguousJSON = errors.New("ambiguous JSON")

// decodeJSON accepts one valid value whose names are unique under case folding, refusing unpaired surrogate escapes.
func decodeJSON(body []byte) (any, error) {
	if !jsontext.Value(body).IsValid() || !unique(json.NewDecoder(bytes.NewReader(body))) {
		return nil, errAmbiguousJSON
	}
	var v any
	return v, facts.DecodeNumbers(body, &v)
}

// fold maps a rune to the least rune that strings.EqualFold, and so Go's JSON decoder, treats as equal.
func fold(r rune) rune {
	least := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		least = min(least, f)
	}
	return least
}

// unique walks one value already known to be valid JSON.
func unique(dec *json.Decoder) bool {
	t, err := dec.Token()
	if err != nil {
		return false
	}
	if t != json.Delim('{') && t != json.Delim('[') {
		return true
	}
	seen := map[string]bool{}
	for dec.More() {
		if t == json.Delim('{') {
			key, err := dec.Token()
			name := strings.Map(fold, fmt.Sprint(key))
			if err != nil || seen[name] {
				return false
			}
			seen[name] = true
		}
		if !unique(dec) {
			return false
		}
	}
	_, err = dec.Token()
	return err == nil
}
