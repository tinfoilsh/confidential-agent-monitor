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
	"path"
	"slices"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/facts"
)

const (
	httpsPort    = 443
	httpPort     = 80
	maxBodyBytes = 1 << 20

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

func (h *HTTP) UnmarshalJSON(raw []byte) error {
	type plain HTTP
	if err := facts.DecodeNumbers(raw, (*plain)(h)); err != nil {
		return err
	}
	return h.Validate(false)
}

func (h *HTTP) Run(ctx context.Context, e *connector.Env, in *connector.Listener, ready func()) error {
	transport := e.Transport()
	defer transport.CloseIdleConnections()
	proxy := h.proxy(transport)
	return connector.ServeHTTP(ctx, tlsListener{in, e}, ready, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r, err := h.screen(r, connector.RequestStream(r))
		if err != nil {
			log.Printf("refused %s %s%s: %v", r.Method, r.Host, r.URL.Path, err)
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
}

// The screened request already names its upstream; substitution is the last change before it is sent.
func (h *HTTP) proxy(base http.RoundTripper) *httputil.ReverseProxy {
	return &httputil.ReverseProxy{
		Transport: substitution{base, h.Secrets},
		Rewrite:   func(*httputil.ProxyRequest) {},
		// The error may quote the request with its credentials in place.
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, _ error) {
			log.Printf("upstream %s %s failed", r.Method, r.Host)
			http.Error(w, "the upstream request failed", http.StatusBadGateway)
		},
	}
}

// HTTP and HTTPS arrive on the same tunnel listener; only port 80 is plain.
type tlsListener struct {
	net.Listener
	env *connector.Env
}

func (l tlsListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil && connector.StreamOf(c).Port != httpPort {
		c = tls.Server(c, l.env.TLS)
	}
	return c, err
}

// screen gates the canonical request with its placeholders; a selected connection, unlike a routed one, has no host to match.
func (h *HTTP) screen(r *http.Request, s *connector.Stream) (*http.Request, error) {
	scheme, host, port, err := authority(r)
	if err != nil {
		return r, err
	}
	switch {
	case s.Host != "" && (host != strings.ToLower(s.Host) || port != s.Port):
		return r, fmt.Errorf("a channel to %s:%d cannot carry a request for %s:%d", s.Host, s.Port, host, port)
	case h.Claim(host, port) < 0:
		return r, fmt.Errorf("this connection does not serve %s:%d", host, port)
	case !slices.Contains(Methods, r.Method):
		return r, fmt.Errorf("method %s is refused", r.Method)
	case len(r.Trailer) > 0:
		return r, errors.New("trailers are refused")
	case r.Header["Upgrade"] != nil:
		return r, errors.New("protocol upgrades are refused")
	}
	// The proxy drops headers that Connection names, after the gate would have seen them.
	for _, token := range strings.FieldsFunc(strings.Join(r.Header.Values("Connection"), ","), func(c rune) bool { return c == ',' || c == ' ' }) {
		if !strings.EqualFold(token, "keep-alive") && !strings.EqualFold(token, "close") {
			return r, fmt.Errorf("Connection: %s is refused", token)
		}
	}
	for _, name := range methodOverrides {
		if r.Header[name] != nil {
			return r, fmt.Errorf("%s is refused", name)
		}
	}
	if err := canonicalPath(r.URL); err != nil {
		return r, err
	}
	query, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil || !validText(query) || !validText(r.Header) {
		return r, errors.New("the query or headers are not valid UTF-8 text")
	}
	origin := origin(scheme, host, port)
	r.URL.Scheme, r.URL.Host, r.URL.RawPath, r.URL.RawQuery = scheme, strings.TrimPrefix(origin, scheme+"://"), "", encodeQuery(query)
	r.Host = r.URL.Host
	layer := &facts.HTTP{Method: r.Method, Origin: origin, Host: host, Path: r.URL.Path, Query: query, Headers: r.Header.Clone()}
	if err := inspect(r, layer); err != nil {
		return r, err
	}
	used, err := h.bind(r, s.Name, origin)
	if err != nil {
		return r, err
	}
	for _, slot := range used {
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
	if err := s.Gate(&Request{HTTP: layer, GraphQL: graphql(layer.Body, query)}); err != nil {
		return r, err
	}
	return r.WithContext(context.WithValue(r.Context(), slotsKey{}, used)), nil
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

func Placeholder(connection, secret string) string {
	return placeholderPrefix + connection + "_" + secret
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
