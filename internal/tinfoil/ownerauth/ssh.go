package ownerauth

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

const (
	ownerSSHChannel        = "tinfoil-owner-http-v1"
	ownerGenerationRequest = "tinfoil-owner-generation-v1"
)

// This metadata is supplied by the authenticated owner CLI, never the browser.
type channelOptions struct {
	Host       string
	Token      string
	Generation uint64
}

// ServeChannel serves api to the owner CLI over one SSH channel.
func ServeChannel(nc ssh.NewChannel, api http.Handler, generation Generation) {
	if nc.ChannelType() != ownerSSHChannel {
		nc.Reject(ssh.Prohibited, "owner connections only serve the owner UI and API")
		return
	}
	var options channelOptions
	if err := ssh.Unmarshal(nc.ExtraData(), &options); err != nil || !options.valid() {
		nc.Reject(ssh.Prohibited, "invalid owner channel options")
		return
	}
	if generation.stale(options.Generation) {
		nc.Reject(ssh.Prohibited, ErrStaleGeneration.Error())
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	conn := connector.NewChannelConn(ch, reqs)
	s := connector.NewStream(context.Background(), conn)
	defer s.Close()
	go func() { <-conn.Closed(); s.Close() }()
	acknowledge := func() error {
		current, unlocked := generation()
		if !unlocked {
			return nil
		}
		// Do not report success until the CLI has persisted the generation. Close
		// a stalled channel so an owner client cannot leave this goroutine behind.
		timer := time.AfterFunc(10*time.Second, func() { s.Close() })
		defer timer.Stop()
		ok, err := ch.SendRequest(ownerGenerationRequest, true, ssh.Marshal(struct{ Generation uint64 }{current}))
		if err != nil || !ok {
			return errors.New("owner CLI did not save the generation")
		}
		return nil
	}
	server := &http.Server{Handler: panel(api, options, acknowledge), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: time.Minute, IdleTimeout: time.Minute, MaxHeaderBytes: 8192}
	defer server.Close()
	server.Serve(connector.Listen(s, s))
}

func (o channelOptions) valid() bool {
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
func panel(api http.Handler, options channelOptions, acknowledge func() error) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'")
		panelPage := r.URL.Path == "/app/" || r.URL.Path == "/app/index.html"
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
		r = r.Clone(NewContext(r.Context(), Session{Minimum: options.Generation, Acknowledge: acknowledge, ID: options.Token}))
		r.URL.Path = path
		r.URL.RawPath = ""
		api.ServeHTTP(w, r)
	})
}
