package web

import (
	"bytes"
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
	"path"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/facts"
)

var Definition = connector.Definition{PerMessage: true, NewConfig: func() connector.Server { return new(HTTP) }, Requests: []connector.Request{new(Request), new(WebSocketReceive)}}

var _ connector.Claimer = (*HTTP)(nil)

type HTTPProvider interface{ HTTPConfig() *HTTP }

const (
	httpsPort    = 443
	httpPort     = 80
	maxBodyBytes = 8 << 20

	placeholderPrefix = "tfm_"
	authorization     = "Authorization"
	hostChars         = "abcdefghijklmnopqrstuvwxyz0123456789.-:"
)

var (
	Methods = []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions}
	// Some servers let these replace the method the policy saw.
	methodOverrides = []string{"X-Http-Method-Override", "X-Http-Method", "X-Method-Override"}
)

// HTTP forwards unauthenticated requests for Hosts on ports 80 and 443, and authenticated ones for slot origins.
type HTTP struct {
	Credentials
	Hosts []string `json:"hosts"`
}

func (h *HTTP) HTTPConfig() *HTTP { return h }

func (h *HTTP) Prepare() error {
	return h.Validate(false)
}

// HTTP and HTTPS arrive on the same tunnel; only port 80 is plain.
func (h *HTTP) Serve(s *connector.Stream, e *connector.Env) {
	transport := e.Transport()
	defer transport.CloseIdleConnections()
	h.ServeWithTransport(s, e, transport)
}

// ServeWithTransport shares HTTP parsing, gating and credential placement with connectors
// that own their upstream transport.
func (h *HTTP) ServeWithTransport(s *connector.Stream, e *connector.Env, transport http.RoundTripper) {
	var c net.Conn = s
	if s.Port != httpPort {
		c = tls.Server(s, e.TLS)
	}
	connector.ServeHTTP(s, c, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := h.parseRequest(r, s)
		if err := s.Gate(r.Context(), request); err != nil {
			log.Printf("refused %s %s%s: %v", r.Method, r.Host, r.URL.Path, err)
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		upstream := substitution{transport, h.Secrets, request.slots}
		if request.HTTP.WebSocket {
			serveWebSocket(w, r, request, s, upstream)
			return
		}
		proxy(upstream).ServeHTTP(w, r)
	}))
}

// The parsed request already names its upstream; substitution is the last change before it is sent.
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
func (h *HTTP) parseRequest(r *http.Request, s *connector.Stream) *Request {
	request := &Request{HTTP: &facts.HTTP{
		Method: strings.ToValidUTF8(r.Method, "�"), Host: strings.ToValidUTF8(r.Host, "�"),
		Path: strings.ToValidUTF8(r.URL.EscapedPath(), "�"),
	}}
	if err := request.parse(h, r, s); err != nil {
		request.Invalid = strings.ToValidUTF8(err.Error(), "�")
	}
	return request
}

// parse fills facts only as their validation succeeds. A selected connection,
// unlike a routed one, has no channel host to match.
func (request *Request) parse(h *HTTP, r *http.Request, s *connector.Stream) error {
	scheme, host, port, err := authority(r)
	if err != nil {
		return err
	}
	switch {
	case s.Host != "" && (host != strings.ToLower(s.Host) || port != s.Port):
		return fmt.Errorf("a channel to %s:%d cannot carry a request for %s:%d", s.Host, s.Port, host, port)
	case h.Claim(host, port) < 0:
		return fmt.Errorf("this connection does not serve %s:%d", host, port)
	case !slices.Contains(Methods, r.Method):
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
	layer := &facts.HTTP{WebSocket: upgrade, Method: r.Method, Origin: origin, Host: host, Path: r.URL.Path, Query: query, Headers: r.Header.Clone()}
	request.HTTP = layer
	if err := inspect(r, layer); err != nil {
		return err
	}
	if upgrade && layer.BodyKind != "none" {
		return errors.New("WebSocket handshakes cannot carry a body")
	}
	// Binding uses the stream's immutable settings. Replacing them cancels the stream.
	request.slots, err = h.bind(r, origin)
	if err != nil {
		return err
	}
	for _, slot := range request.slots {
		if upgrade && strings.HasPrefix(strings.ToLower(slot.Header), "sec-websocket-") {
			return errors.New("WebSocket negotiation headers cannot carry credentials")
		}
		layer.Secrets = append(layer.Secrets, slot.Value)
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
	scheme, port = "http", httpPort
	if r.TLS != nil {
		scheme, port = "https", httpsPort
	}
	u := url.URL{Host: r.Host}
	host = strings.ToLower(u.Hostname())
	spelled := host
	if strings.Contains(host, ":") {
		spelled = "[" + host + "]"
	}
	if text := u.Port(); text != "" {
		n, err := strconv.ParseUint(text, 10, 16)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != text {
			return "", "", 0, fmt.Errorf("invalid port in %q", r.Host)
		}
		port, spelled = uint32(n), spelled+":"+text
	}
	switch {
	case host == "" || strings.Trim(host, hostChars) != "" || !strings.EqualFold(r.Host, spelled):
		return "", "", 0, fmt.Errorf("noncanonical host %q", r.Host)
	case (scheme == "http") != (port == httpPort):
		return "", "", 0, fmt.Errorf("%s cannot use port %d", scheme, port)
	case r.TLS != nil && r.TLS.ServerName != "" && !strings.EqualFold(r.TLS.ServerName, host):
		return "", "", 0, fmt.Errorf("TLS server name %s differs from host %s", r.TLS.ServerName, host)
	}
	return scheme, host, port, nil
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
	raw := strings.ToUpper(u.RawPath)
	if !strings.HasPrefix(u.Path, "/") || !utf8.ValidString(u.Path) || strings.Contains(raw, "%2F") || strings.ContainsAny(u.Path, "\\%\x00") {
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

// inspect decodes a complete body of at most maxBodyBytes without repeated names; anything else is opaque and still forwarded.
func inspect(r *http.Request, layer *facts.HTTP) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return err
	}
	r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), r.Body))
	if len(body) <= maxBodyBytes {
		r.GetBody = func() (io.ReadCloser, error) { return io.NopCloser(bytes.NewReader(body)), nil }
	}
	layer.BodyKind = "opaque"
	types := r.Header.Values("Content-Type")
	switch {
	case len(body) == 0:
		layer.BodyKind = "none"
		return nil
	case len(body) > maxBodyBytes || len(r.Header.Values("Content-Encoding")) > 0 || len(types) != 1 || !utf8.Valid(body):
		return nil
	}
	mediaType, params, err := mime.ParseMediaType(types[0])
	if err != nil || (params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8")) {
		return nil
	}
	switch {
	case mediaType == "application/json" || strings.HasSuffix(mediaType, "+json"):
		if layer.Body, err = decodeJSON(body); err == nil {
			layer.BodyKind = "json"
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
			layer.Form, layer.BodyKind = form, "form"
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

// Claim ranks exact slot origins by their length and host patterns, which serve only default ports, by theirs.
func (h *HTTP) Claim(host string, port uint32) int {
	host = strings.ToLower(host)
	score := -1
	for _, s := range h.Slots {
		if s.host == host && s.port == port {
			score = len(host)
		}
	}
	if port != httpPort && port != httpsPort {
		return score
	}
	for _, pattern := range h.Hosts {
		if ok, _ := path.Match(pattern, host); ok {
			score = max(score, len(pattern))
		}
	}
	return score
}
