package main

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
	"strings"
	"time"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

const (
	maxBodyBytes      = 1 << 20
	readHeaderTimeout = 30 * time.Second
	jsonType          = "application/json"
	jsonSuffix        = "+json"
)

type connKey struct{}

func (m *monitor) serveHTTP() {
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
		TLSConfig:         m.tls,
		ConnContext: func(ctx context.Context, c net.Conn) context.Context {
			return context.WithValue(ctx, connKey{}, channelOf(c))
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := m.screen(r); err != nil {
				log.Printf("refused %s %s%s: %v", r.Method, r.Host, r.URL.Path, err)
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
			proxy.ServeHTTP(w, r)
		}),
	}
	go server.Serve(m.http)
	log.Fatal(server.ServeTLS(m.https, "", ""))
}

func channelOf(c net.Conn) *channelConn {
	if tc, ok := c.(*tls.Conn); ok {
		c = tc.NetConn()
	}
	return c.(*channelConn)
}

// screen snapshots the request for the policy before any secret enters it, swaps placeholders, then asks the gate.
// The proxy dials the request's host, so it must be the one the channel's gate saw.
func (m *monitor) screen(r *http.Request) error {
	cc := r.Context().Value(connKey{}).(*channelConn)
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if !strings.EqualFold(host, cc.host) {
		return fmt.Errorf("a channel to %s cannot carry a request for %s", cc.host, host)
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
	if layer.Secrets, err = m.substitute(r, host); err != nil {
		return err
	}
	return cc.gate(event{HTTP: layer, GraphQL: graphql(layer.Body)})
}

// substitute swaps placeholders for secrets in the path, query, headers, and basic auth, and refuses a
// request that carries a placeholder to a host its connection does not list. Bodies are never rewritten.
func (m *monitor) substitute(r *http.Request, host string) ([]string, error) {
	used := []string{}
	for name, c := range m.Connections {
		for secret, value := range c.Secrets {
			ph := placeholder(name, secret)
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
			if !found {
				continue
			}
			if !c.allows(host) {
				return nil, fmt.Errorf("%s secrets are not bound to %s", name, host)
			}
			used = append(used, secret)
		}
	}
	return used, nil
}

func (c *connection) allows(host string) bool {
	for _, pattern := range c.Hosts {
		if ok, _ := path.Match(pattern, host); ok {
			return true
		}
	}
	return false
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
