package main

import (
	"context"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/tinfoilsh/monitor/connector"
	"golang.org/x/crypto/ssh"
)

const ownerSSHChannel = "tinfoil-owner-http-v1"
const ownerGenerationRequest = "tinfoil-owner-generation-v1"
const ownerSSHExtension = "owner"

type ownerSSHContextKey struct{}

type ownerSSHContext struct {
	minimum     uint64
	acknowledge func() error
}

// This metadata is supplied by the authenticated owner CLI, never the browser.
type ownerChannelOptions struct {
	Host       string
	Token      string
	Generation uint64
}

func (m *monitor) forwardOwner(nc ssh.NewChannel) {
	if nc.ChannelType() != ownerSSHChannel {
		nc.Reject(ssh.Prohibited, "owner connections only serve the owner UI and API")
		return
	}
	var options ownerChannelOptions
	if err := ssh.Unmarshal(nc.ExtraData(), &options); err != nil || !options.valid() {
		nc.Reject(ssh.Prohibited, "invalid owner channel options")
		return
	}
	m.mu.Lock()
	current := m.doc.Generation
	m.mu.Unlock()
	if m.live.Load() != nil && current < options.Generation {
		nc.Reject(ssh.Prohibited, "Monitor state is older than the saved generation")
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	s := connector.NewStream(context.Background(), channelConn{ch})
	defer s.Close()
	go func() { ssh.DiscardRequests(reqs); s.Close() }()
	acknowledge := func() error {
		m.mu.Lock()
		generation := m.doc.Generation
		m.mu.Unlock()
		// Do not report success until the CLI has persisted the generation. Close
		// a stalled channel so an owner client cannot leave this goroutine behind.
		timer := time.AfterFunc(10*time.Second, func() { s.Close() })
		defer timer.Stop()
		ok, err := ch.SendRequest(ownerGenerationRequest, true, ssh.Marshal(struct{ Generation uint64 }{generation}))
		if err != nil || !ok {
			return errors.New("owner CLI did not save the generation")
		}
		return nil
	}
	server := &http.Server{Handler: m.ownerPanel(options, acknowledge), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: time.Minute, IdleTimeout: time.Minute, MaxHeaderBytes: 8192}
	defer server.Close()
	server.Serve(connector.Listen(s, s))
}

func (o ownerChannelOptions) valid() bool {
	token, err := base64.RawURLEncoding.DecodeString(o.Token)
	if err != nil || len(token) != 32 {
		return false
	}
	if o.Host == "owner.monitor" {
		return true
	}
	host, port, err := net.SplitHostPort(o.Host)
	return err == nil && host == "127.0.0.1" && port != "" && !strings.ContainsAny(port, "/?#@ ")
}

// Browser protections live with the measured UI. The CLI only forwards bytes.
func (m *monitor) ownerPanel(options ownerChannelOptions, acknowledge func() error) http.Handler {
	api := m.ownerHandler(true)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		panelPage := r.URL.Path == "/app/" || r.URL.Path == "/app/index.html" || r.URL.Path == "/app/fun_ui.html"
		navigation := r.Method == http.MethodGet && panelPage && r.Header.Get("Sec-Fetch-Mode") == "navigate" && r.Header.Get("Sec-Fetch-Dest") == "document"
		if r.Host != options.Host || (r.Header.Get("Origin") != "" && r.Header.Get("Origin") != "http://"+options.Host) || (r.Header.Get("Sec-Fetch-Site") == "cross-site" && !navigation) {
			http.Error(w, "foreign browser origin refused", http.StatusForbidden)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/app/") && r.Method == http.MethodGet {
			api.ServeHTTP(w, r)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/api/") {
			http.NotFound(w, r)
			return
		}
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Tinfoil-Session")), []byte(options.Token)) != 1 {
			http.Error(w, "local panel session required", http.StatusUnauthorized)
			return
		}
		// Only the CLI channel can send the storage key; the browser cannot unlock.
		path := strings.TrimPrefix(r.URL.Path, "/api")
		if (path == "/unlock" && options.Host != "owner.monitor") || strings.HasPrefix(path, "/owner/") || strings.HasPrefix(path, "/app/") || strings.Contains(path, "..") || strings.Contains(path, "\\") {
			http.NotFound(w, r)
			return
		}
		r = r.Clone(context.WithValue(r.Context(), ownerSSHContextKey{}, ownerSSHContext{options.Generation, acknowledge}))
		r.URL.Path = path
		r.URL.RawPath = ""
		api.ServeHTTP(w, r)
	})
}
