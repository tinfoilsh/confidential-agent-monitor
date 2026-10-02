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
	"time"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
)

const (
	httpsPort         = 443
	httpPort          = 80
	maxBodyBytes      = 1 << 20
	readHeaderTimeout = 30 * time.Second
	jsonType          = "application/json"
	jsonSuffix        = "+json"
	placeholderPrefix = "tfm_"
	authorization     = "Authorization"
)

type location string

const (
	locationURL     location = "url"
	locationHeaders location = "headers"
	locationBody    location = "body"
)

func (l *location) UnmarshalText(text []byte) error {
	switch location(text) {
	case locationURL, locationHeaders, locationBody:
		*l = location(text)
		return nil
	}
	return fmt.Errorf("unknown substitution location %q", text)
}

type connKey struct{}

type HTTP struct {
	Hosts   []string                          `json:"hosts"`
	Secrets map[string]*credential.Credential `json:"secrets"`
	// The Authorization header is always substituted; these locations are opt-in.
	Substitute  []location `json:"substitute"`
	credentials credential.Store
	conns       *connector.Listener
	server      *http.Server
}

func (*HTTP) CredentialFields() []string { return []string{"secrets/*"} }

func (r *HTTP) Serve(s *connector.Stream) {
	var c net.Conn = s
	if s.Port == httpsPort {
		c = tls.Server(s, s.TLS)
	}
	r.conns.Hand(c)
}

func (h *HTTP) Start(_ context.Context, e *connector.Env) {
	h.credentials = e.Credentials
	h.conns = connector.NewListener()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = e.Dialer.DialContext
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
	h.server = &http.Server{
		ReadHeaderTimeout: readHeaderTimeout,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connKey{}, connector.StreamOf(c))
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
	go func() {
		if err := h.server.Serve(h.conns); err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()
}

func (h *HTTP) Stop() { h.server.Close() }

// The proxy dials the request's host, so it must be the one the channel's gate saw.
func (h *HTTP) screen(r *http.Request) error {
	s := r.Context().Value(connKey{}).(*connector.Stream)
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
	if mediaType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type")); mediaType == jsonType || strings.HasSuffix(mediaType, jsonSuffix) {
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
	inURL, inHeaders, inBody := slices.Contains(h.Substitute, locationURL), slices.Contains(h.Substitute, locationHeaders), slices.Contains(h.Substitute, locationBody)
	if inBody && len(body) > maxBodyBytes {
		return nil, fmt.Errorf("body substitution needs a body of at most %d bytes", maxBodyBytes)
	}
	used := []string{}
	for secret, cred := range h.Secrets {
		ph := Placeholder(name, secret)
		found := false
		value := sync.OnceValues(func() (string, error) { return cred.Value(r.Context(), h.credentials) })
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
