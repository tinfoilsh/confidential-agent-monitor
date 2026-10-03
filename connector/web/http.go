package web

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"net/http"
	"net/http/httputil"
	"path"
	"slices"
	"strings"
	"sync"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
)

const (
	httpsPort    = 443
	httpPort     = 80
	maxBodyBytes = 1 << 20

	placeholderPrefix = "tfm_"
	authorization     = "Authorization"
)

type Location string

func (l *Location) UnmarshalText(text []byte) error {
	switch Location(text) {
	case "url", "headers", "body":
		*l = Location(text)
		return nil
	}
	return fmt.Errorf("unknown substitution location %q", text)
}

type HTTP struct {
	Values map[string]*credential.Value `json:"values"`
	Hosts  []string                     `json:"hosts"`
	// The Authorization header is always substituted; these locations are opt-in.
	Substitute []Location `json:"substitute"`
}

func (h *HTTP) Fields() (fields []connector.Field) {
	for name, value := range h.Values {
		fields = append(fields, connector.Field{Path: []string{"values", name}, Value: value, Redact: true})
	}
	return
}

func (h *HTTP) Run(ctx context.Context, e *connector.Env, in *connector.Listener, ready func()) error {
	transport := e.Transport()
	defer transport.CloseIdleConnections()
	proxy := &httputil.ReverseProxy{
		Transport: transport,
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			if pr.In.TLS != nil {
				pr.Out.URL.Scheme = "https"
			}
			pr.Out.URL.Host = pr.In.Host
		},
	}
	return connector.ServeHTTP(ctx, tlsListener{in, e}, ready, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := h.screen(r); err != nil {
			log.Printf("refused %s %s%s: %v", r.Method, r.Host, r.URL.Path, err)
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		proxy.ServeHTTP(w, r)
	}))
}

// HTTP and HTTPS arrive on the same tunnel listener.
type tlsListener struct {
	net.Listener
	env *connector.Env
}

func (l tlsListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err == nil && connector.StreamOf(c).Port == httpsPort {
		c = tls.Server(c, l.env.TLS)
	}
	return c, err
}

// The proxy dials the request's host, so it must be the one the channel's gate saw.
func (h *HTTP) screen(r *http.Request) error {
	s := connector.RequestStream(r)
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if !strings.EqualFold(host, s.Host) {
		return fmt.Errorf("a channel to %s cannot carry a request for %s", s.Host, host)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes+1))
	if err != nil {
		return err
	}
	layer := &connector.HTTPLayer{Method: r.Method, Host: host, Path: r.URL.Path, Query: r.URL.Query(), Headers: r.Header.Clone()}
	if mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mediaType == "application/json" || strings.HasSuffix(mediaType, "+json") {
		if json.Unmarshal(body, &layer.Body) != nil {
			layer.Body = nil
		}
	}
	if layer.Secrets, err = h.substitute(r, s.Name, body); err != nil {
		return err
	}
	if r.TLS == nil && len(layer.Secrets) > 0 {
		return fmt.Errorf("secret placeholders require HTTPS")
	}
	return s.Gate(connector.Event{HTTP: layer, GraphQL: graphql(layer.Body)})
}

func Placeholder(connection, secret string) string {
	return placeholderPrefix + connection + "_" + secret
}

// Leftover placeholders are refused everywhere but the body.
func (h *HTTP) substitute(r *http.Request, name string, body []byte) ([]string, error) {
	inURL, inHeaders, inBody := slices.Contains(h.Substitute, "url"), slices.Contains(h.Substitute, "headers"), slices.Contains(h.Substitute, "body")
	if inBody && len(body) > maxBodyBytes {
		return nil, fmt.Errorf("body substitution needs a body of at most %d bytes", maxBodyBytes)
	}
	used := []string{}
	for secret, v := range h.Values {
		ph := Placeholder(name, secret)
		found := false
		value := sync.OnceValues(func() (string, error) { return v.Value(r.Context()) })
		swap := func(s string) string {
			if !strings.Contains(s, ph) {
				return s
			}
			found = true
			v, _ := value()
			return strings.ReplaceAll(s, ph, v)
		}
		if inURL {
			r.URL.Path, r.URL.RawPath, r.URL.RawQuery = swap(r.URL.Path), swap(r.URL.RawPath), swap(r.URL.RawQuery)
		}
		for key, values := range r.Header {
			if key != authorization && !inHeaders {
				continue
			}
			for i := range values {
				values[i] = swap(values[i])
			}
		}
		if user, pass, ok := r.BasicAuth(); ok {
			r.SetBasicAuth(swap(user), swap(pass))
		}
		if inBody {
			body = []byte(swap(string(body)))
		}
		if found {
			if _, err := value(); err != nil {
				return nil, err
			}
			used = append(used, secret)
		}
	}
	values := []string{r.URL.Path, r.URL.RawPath, r.URL.RawQuery}
	for key, entries := range r.URL.Query() {
		values = append(values, key)
		values = append(values, entries...)
	}
	for key, entries := range r.Header {
		values = append(values, key)
		values = append(values, entries...)
	}
	if user, pass, ok := r.BasicAuth(); ok {
		values = append(values, user, pass)
	}
	for _, value := range values {
		if strings.Contains(value, placeholderPrefix) {
			return nil, fmt.Errorf("unresolved secret placeholder")
		}
	}
	if inBody {
		r.ContentLength = int64(len(body))
	}
	r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), r.Body))
	return used, nil
}

func (h *HTTP) Claim(host string, port uint32) int {
	if port != httpPort && port != httpsPort {
		return -1
	}
	score := -1
	for _, pattern := range h.Hosts {
		if ok, _ := path.Match(pattern, host); ok {
			score = max(score, len(pattern))
		}
	}
	return score
}

// Roots hidden behind a fragment spread yield no layer at all, so a policy can refuse the request.
func graphql(body any) *connector.GraphQLLayer {
	object, _ := body.(map[string]any)
	query, ok := object["query"].(string)
	if !ok {
		return nil
	}
	doc, err := parser.ParseQuery(&ast.Source{Input: query})
	if err != nil || len(doc.Operations) == 0 {
		return nil
	}
	op := doc.Operations[0]
	if name, _ := object["operationName"].(string); name != "" {
		if op = doc.Operations.ForName(name); op == nil {
			return nil
		}
	}
	names, ok := roots(op.SelectionSet)
	if !ok {
		return nil
	}
	return &connector.GraphQLLayer{Kind: string(op.Operation), Roots: names}
}

func roots(set ast.SelectionSet) ([]string, bool) {
	names := []string{}
	for _, s := range set {
		switch s := s.(type) {
		case *ast.Field:
			names = append(names, s.Name)
		case *ast.InlineFragment:
			inner, ok := roots(s.SelectionSet)
			if !ok {
				return nil, false
			}
			names = append(names, inner...)
		default:
			return nil, false
		}
	}
	return names, true
}
