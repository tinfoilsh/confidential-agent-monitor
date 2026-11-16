// Package perimeter runs a Perimeter from typed configuration on listeners its caller opens.
package perimeter

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/flynn/noise"
	"github.com/tinfoilsh/confidential-agent-monitor/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/core/frontdoor"
	"github.com/tinfoilsh/confidential-agent-monitor/core/netx"
	"github.com/tinfoilsh/confidential-agent-monitor/core/sshx"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/monitor"
	"golang.org/x/crypto/ssh"
)

const (
	readHeaderTimeout = 30 * time.Second
	preflightMaxAge   = "600"
	bearerMode        = "bearer"
	ownerMode         = "ssh"
	ownerHost         = "owner" + connector.Domain
	rpcMode           = "rpc"
	relayMode         = "relay"
)

type Config struct {
	SSH, API   net.Listener
	Monitor    *monitor.Monitor
	Streams    netx.Opener // serves each agent stream; its context carries the identity (identity.ID)
	Extensions []sshx.Extension
	UI         http.Handler // serves GET /app/
	Owner      *Owner       // nil: the storage key authenticates bearer calls, for local development
	Origins    []string
	IdentityCA ssh.PublicKey // signs expiring SSH certificates that name an identity and its groups; nil: only registered keys connect
}

type Owner struct {
	Key        ed25519.PublicKey
	SessionKey noise.DHKey
	// Relay opens an instance's owner socket, which the owner then runs its own session over; nil refuses relays.
	Relay func(ctx context.Context, instance string) (*websocket.Conn, error)
}

// Run serves on c.SSH and c.API and closes both before it returns.
func Run(ctx context.Context, c Config) error {
	defer c.SSH.Close()
	defer c.API.Close()

	if c.Owner != nil && c.Monitor.HostKey() == nil {
		return errors.New("an owner requires a host key")
	}

	m := c.Monitor
	api, mode := m.AdminAPI(), bearerMode
	if c.Owner != nil {
		mode = ownerMode
	}

	if c.UI != nil {
		app := http.NewServeMux()
		app.Handle("/", api)
		app.Handle("GET /app/auth.json", monitor.JSON(0, func(_ *http.Request, _ struct{}) (any, error) {
			return map[string]string{"mode": mode}, nil
		}))
		app.HandleFunc("GET /app/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			c.UI.ServeHTTP(w, r)
		})
		api = app
	}

	door := &frontdoor.Server{
		HostKey:    m.HostKey,
		Identities: m.Identities(),
		CA:         c.IdentityCA,
		Streams:    c.Streams,
	}

	handler := http.NewServeMux()
	handler.Handle("GET /healthz", api)

	if c.Owner == nil {
		handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if key, err := base64.StdEncoding.Strict().DecodeString(token); ok && err == nil && m.IsOwner(key) {
				r = r.WithContext(monitor.WithCaller(r.Context(), monitor.Caller{Name: monitor.Owner, Owner: true, Key: key}))
			}
			api.ServeHTTP(w, r)
		})
	} else {
		modes := map[string]sessionMode{rpcMode: rpcSession(monitor.MaxCallBytes, ownerRPC(api, m.Generation))}
		if c.Owner.Relay != nil {
			modes[relayMode] = relayOwner(c.Owner.Relay)
		}
		handler.Handle("GET /owner/ws", &ownerSocket{
			Key:        c.Owner.Key,
			SessionKey: c.Owner.SessionKey,
			Protocol:   ownerProtocol,
			Modes:      modes,
		})

		door.Extensions = append(door.Extensions, (&ownerSSH{
			Key:        c.Owner.Key,
			API:        api,
			Generation: m.Generation,
			Host:       ownerHost,
		}).Authenticate)
	}
	door.Extensions = append(door.Extensions, c.Extensions...)

	server := &http.Server{Handler: allowOrigins(c.Origins, handler), ReadHeaderTimeout: readHeaderTimeout}
	defer server.Close()

	serving, stop := context.WithCancelCause(ctx)
	go func() {
		stop(server.Serve(c.API))
	}()
	context.AfterFunc(serving, func() {
		c.SSH.Close()
	})

	var audit sync.WaitGroup
	audit.Go(func() {
		m.RunAudit(serving)
	})

	door.Serve(c.SSH)
	stop(errors.New("the SSH listener closed"))
	audit.Wait()

	if ctx.Err() != nil {
		return nil
	}
	return context.Cause(serving)
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
