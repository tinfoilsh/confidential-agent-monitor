package connector

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
	"net/url"
	"path"
	"strings"
	"time"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

// httpLayer is the request before substitution; secrets names the placeholders it carried.
type httpLayer struct {
	Method  string      `json:"method"`
	Host    string      `json:"host"`
	Path    string      `json:"path"`
	Query   url.Values  `json:"query"`
	Headers http.Header `json:"headers"`
	Secrets []string    `json:"secrets"`
	Body    any         `json:"body,omitempty"`
}

type graphqlLayer struct {
	Kind  string   `json:"kind"`
	Roots []string `json:"roots"`
}

const (
	httpsPort         = 443
	httpPort          = 80
	maxBodyBytes      = 1 << 20
	readHeaderTimeout = 30 * time.Second
	jsonType          = "application/json"
	jsonSuffix        = "+json"
	placeholderPrefix = "tfm_"
)

type connKey struct{}

type HTTP struct {
	Hosts   []string          `yaml:"hosts"`
	Secrets map[string]string `yaml:"secrets"`
	conns   chanListener
}

func (r *HTTP) Serve(s *Stream) {
	var c net.Conn = s
	if s.Port == httpsPort {
		c = tls.Server(s, s.TLS)
	}
	r.conns <- c
}

func (h *HTTP) Start(*Env) {
	h.conns = make(chanListener)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
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
	server := &http.Server{
		ReadHeaderTimeout: readHeaderTimeout,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connKey{}, streamOf(c))
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := h.screen(r); err != nil {
				log.Printf("refused %s %s%s: %v", r.Method, r.Host, r.URL.Path, err)
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
			proxy.ServeHTTP(w, r)
		}),
	}
	go func() { log.Fatal(server.Serve(h.conns)) }()
}

// screen snapshots the request for the policy before any secret enters it, swaps placeholders, then asks the gate.
// The proxy dials the request's host, so it must be the one the channel's gate saw.
func (h *HTTP) screen(r *http.Request) error {
	s := r.Context().Value(connKey{}).(*Stream)
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if !strings.EqualFold(host, s.Host) {
		return fmt.Errorf("a channel to %s cannot carry a request for %s", s.Host, host)
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		return err
	}
	r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), r.Body))
	layer := &httpLayer{Method: r.Method, Host: host, Path: r.URL.Path, Query: r.URL.Query(), Headers: r.Header.Clone()}
	if mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mediaType == jsonType || strings.HasSuffix(mediaType, jsonSuffix) {
		if json.Unmarshal(body, &layer.Body) != nil {
			layer.Body = nil
		}
	}
	if layer.Secrets, err = h.substitute(r, s.Name); err != nil {
		return err
	}
	if r.TLS == nil && len(layer.Secrets) > 0 {
		return fmt.Errorf("secret placeholders require HTTPS")
	}
	return s.Gate(Event{HTTP: layer, GraphQL: graphql(layer.Body)})
}

func Placeholder(connection, secret string) string {
	return placeholderPrefix + connection + "_" + secret
}

// substitute swaps this connection's placeholders in the path, query, headers, and basic auth.
// It refuses unresolved placeholders. Bodies are never rewritten.
func (h *HTTP) substitute(r *http.Request, name string) ([]string, error) {
	used := []string{}
	for secret, value := range h.Secrets {
		ph := Placeholder(name, secret)
		found := false
		swap := func(s string) string {
			found = found || strings.Contains(s, ph)
			return strings.ReplaceAll(s, ph, value)
		}
		r.URL.Path, r.URL.RawPath, r.URL.RawQuery = swap(r.URL.Path), swap(r.URL.RawPath), swap(r.URL.RawQuery)
		for _, values := range r.Header {
			for i := range values {
				values[i] = swap(values[i])
			}
		}
		if user, pass, ok := r.BasicAuth(); ok {
			r.SetBasicAuth(swap(user), swap(pass))
		}
		if found {
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
func graphql(body any) *graphqlLayer {
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
	return &graphqlLayer{Kind: string(op.Operation), Roots: names}
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
