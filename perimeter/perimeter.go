// Package perimeter runs a Perimeter from typed configuration on listeners its caller opens.
package perimeter

import (
	"context"
	"crypto/ed25519"
	"errors"
	"net"
	"net/http"
	"slices"
	"time"

	"github.com/coder/websocket"
	"github.com/flynn/noise"
	"github.com/tinfoilsh/confidential-agent-monitor/frontdoor"
	"github.com/tinfoilsh/confidential-agent-monitor/monitor"
	"github.com/tinfoilsh/confidential-agent-monitor/owner"
	"github.com/tinfoilsh/confidential-agent-monitor/routes"
	"golang.org/x/crypto/ssh"
)

const (
	readHeaderTimeout = 30 * time.Second
	preflightMaxAge   = "600"
	bearerMode        = "bearer"
	ownerMode         = "ssh"
)

type Config struct {
	SSH, API   net.Listener
	Monitor    *monitor.Monitor
	UI         http.Handler // serves GET /app/
	Owner      *Owner       // nil: the storage key authenticates bearer calls, for local development
	Origins    []string
	IdentityCA ssh.PublicKey
	Routes     *routes.Forwarder // nil refuses publishers and dials no route
}

type Owner struct {
	Key        ed25519.PublicKey
	SessionKey noise.DHKey
	Relay      func(ctx context.Context, instance string) (*websocket.Conn, error) // nil refuses relays
}

// Run serves on c.SSH and c.API and closes both before it returns.
func Run(ctx context.Context, c Config) error {
	defer c.SSH.Close()
	defer c.API.Close()
	if c.Owner != nil && c.Monitor.HostKey() == nil {
		return errors.New("an owner requires a host key")
	}
	m := c.Monitor
	admin, mode := m.AdminAPI(), bearerMode
	if c.Owner != nil {
		mode = ownerMode
	}
	if c.UI != nil {
		app := http.NewServeMux()
		app.Handle("/", admin)
		app.Handle("GET /app/auth.json", monitor.JSONHandler(0, func(_ *http.Request, _ struct{}) (any, error) {
			return map[string]string{"mode": mode}, nil
		}))
		app.HandleFunc("GET /app/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			c.UI.ServeHTTP(w, r)
		})
		admin = app
	}
	var sshAdmin *owner.SSH
	handler := http.NewServeMux()
	handler.Handle("GET /healthz", admin)
	if c.Owner == nil {
		handler.Handle("/", &owner.Bearer{API: admin, IsOwner: m.IsOwner})
	} else {
		handler.Handle("GET /owner/ws", &owner.Handler{Key: c.Owner.Key, SessionKey: c.Owner.SessionKey, MaxBytes: monitor.MaxCallBytes, API: admin, Generation: m.Generation, Relay: c.Owner.Relay})
		sshAdmin = &owner.SSH{Key: c.Owner.Key, API: admin, Generation: m.Generation}
	}
	door := &frontdoor.Server{Monitor: m, Owner: sshAdmin, IdentityCA: c.IdentityCA, Routes: c.Routes}
	go door.Serve(c.SSH)
	server := &http.Server{Handler: allowOrigins(c.Origins, handler), ReadHeaderTimeout: readHeaderTimeout}
	defer server.Close()
	audit, failed := context.WithCancelCause(ctx)
	go func() { failed(server.Serve(c.API)) }()
	m.RunAudit(audit)
	if ctx.Err() != nil {
		return nil
	}
	return context.Cause(audit)
}

// allowOrigins lets the listed origins call the owner API from a browser, such as a dashboard
// holding the owner key in memory. Only the bearer key authenticates; credentials are never allowed.
func allowOrigins(origins []string, next http.Handler) http.Handler {
	if len(origins) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Origin")
		origin := r.Header.Get("Origin")
		if !slices.Contains(origins, origin) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Expose-Headers", "ETag")
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, If-None-Match")
			w.Header().Set("Access-Control-Max-Age", preflightMaxAge)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
