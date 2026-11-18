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

	"github.com/tinfoilsh/confidential-agent-monitor/core/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/netx"
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

	SignInAction = "session.sign-in"
)

var (
	methods         = []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete, http.MethodOptions}
	methodOverrides = []string{"X-Http-Method-Override", "X-Http-Method", "X-Method-Override"}
)

type Setup struct {
	Hosts         []string
	Preset        *Preset
	title, origin string
	slots         Slots
}

type Handler struct {
	*Setup
	Transport   http.RoundTripper
	TLS         func(ctx context.Context, host string) *tls.Config
	Placeholder func(name string) string
	Secret      func(ctx context.Context, name string) (string, error)
	Prepare     PrepareRequest
	MaxBody     int64
}

type PrepareRequest func(*http.Request, *HTTPFacts) (http.RoundTripper, error)

func (h Handler) Serve(ctx context.Context, conn net.Conn, _ string, target connector.Target, gate connector.Gate) {
	c := conn
	if target.Port != httpPort {
		c = tls.Server(conn, h.TLS(ctx, target.Host))
	}
	netx.ServeConn(ctx, c, &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := h.parseRequest(r, target.Host, target.Port)
		upstreamTransport := h.Transport
		if h.Prepare != nil && request.Invalid == "" {
			prepared := r.Clone(r.Context())
			responseTransport, err := h.Prepare(prepared, request.HTTP)
			if err != nil {
				request.Invalid = strings.ToValidUTF8(err.Error(), "�")
			} else {
				r = prepared
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
		if request.answer != nil {
			request.answer(w, r)
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

func proxy(transport http.RoundTripper) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Transport: transport,
		Rewrite:   func(*httputil.ProxyRequest) {},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, _ error) {
			log.Printf("upstream %s %s failed", r.Method, r.Host)
			http.Error(w, "the upstream request failed", http.StatusBadGateway)
		},
	}
}

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
	case h.Claim(connector.Target{Host: host, Port: port}) < 0:
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
	layer.Secrets, request.place, err = h.slots.Bind(r, origin, h.Placeholder)
	if err != nil {
		return err
	}
	request.answer = h.slots.Answer(r, origin, layer.Form, h.Placeholder)
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
	request.GraphQL, request.gqlErr = graphql(layer.Body, query)
	return nil
}

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

func encodeQuery(q url.Values) string {
	return strings.ReplaceAll(q.Encode(), "+", "%20")
}

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

func decodeJSON(body []byte) (any, error) {
	if !jsontext.Value(body).IsValid() || !unique(json.NewDecoder(bytes.NewReader(body))) {
		return nil, errAmbiguousJSON
	}
	var v any
	return v, facts.DecodeNumbers(body, &v)
}

func fold(r rune) rune {
	least := r
	for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
		least = min(least, f)
	}
	return least
}

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
