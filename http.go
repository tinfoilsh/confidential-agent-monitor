package main

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"path"
	"strings"
	"time"
)

const (
	maxRewriteBytes   = 1 << 20
	readHeaderTimeout = 30 * time.Second
)

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
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if err := m.substitute(r); err != nil {
				log.Printf("refused %s %s: %v", r.Method, r.Host, err)
				http.Error(w, err.Error(), http.StatusForbidden)
				return
			}
			proxy.ServeHTTP(w, r)
		}),
	}
	go server.Serve(m.http)
	log.Fatal(server.ServeTLS(m.https, "", ""))
}

// substitute swaps placeholders for secrets in the URL, headers, basic auth, and a body up to
// maxRewriteBytes, and refuses a request that carries a placeholder to a host its connection does not list.
func (m *monitor) substitute(r *http.Request) error {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxRewriteBytes+1))
	if err != nil {
		return err
	}
	rewritable := len(body) <= maxRewriteBytes
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	for name, c := range m.Connections {
		var pairs []string
		for secret, value := range c.Secrets {
			pairs = append(pairs, placeholder(name, secret), value)
		}
		if pairs == nil {
			continue
		}
		replacer := strings.NewReplacer(pairs...)
		changed := false
		swap := func(s string) string {
			out := replacer.Replace(s)
			changed = changed || out != s
			return out
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
		if rewritable {
			body = []byte(swap(string(body)))
		}
		if changed && !c.allows(host) {
			return fmt.Errorf("%s secrets are not bound to %s", name, host)
		}
	}
	if rewritable {
		r.Body, r.ContentLength = io.NopCloser(bytes.NewReader(body)), int64(len(body))
	} else {
		r.Body = io.NopCloser(io.MultiReader(bytes.NewReader(body), r.Body))
	}
	return nil
}

func (c *connection) allows(host string) bool {
	for _, pattern := range c.Hosts {
		if ok, _ := path.Match(pattern, host); ok {
			return true
		}
	}
	return false
}
