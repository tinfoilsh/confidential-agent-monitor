// Package perimeter runs a Perimeter from typed configuration on listeners its caller opens.
package perimeter

import (
	"context"
	"crypto/ed25519"
	"errors"
	"log/slog"
	"net"
	"net/http"
	"os"
	"slices"
	"time"

	"github.com/flynn/noise"
	"github.com/tinfoilsh/confidential-agent-monitor/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/monitor"
	"github.com/tinfoilsh/confidential-agent-monitor/owner"
	"github.com/tinfoilsh/confidential-agent-monitor/presets"
	"gocloud.dev/blob"
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
	Bucket     *blob.Bucket
	Connectors map[string]connector.Kind
	Presets    presets.Set
	UI         http.Handler // serves GET /app/
	HostKey    ssh.Signer
	Owner      *Owner // nil: the storage key authenticates bearer calls, for local development
	Unlock     []byte // development storage key to unlock with at start
	Origins    []string
	IdentityCA ssh.PublicKey
	BasePolicy string
	Policy     func() (string, error) // read at each unlock in place of the stored policy
	Secrets    *os.Root
	Events     *slog.Logger
}

type Owner struct {
	Key        ed25519.PublicKey
	SessionKey noise.DHKey
}

// Run serves on c.SSH and c.API and closes both before it returns.
func Run(ctx context.Context, c Config) error {
	defer c.SSH.Close()
	defer c.API.Close()
	if c.Owner != nil && c.HostKey == nil {
		return errors.New("an owner requires a host key")
	}
	if c.Owner != nil && c.Unlock != nil {
		return errors.New("a development unlock key cannot be used with an owner")
	}
	m, err := monitor.New(monitor.Options{
		Bucket:         c.Bucket,
		HostKey:        c.HostKey,
		Connectors:     c.Connectors,
		StorageKeyAuth: c.Owner == nil,
		IdentityCA:     c.IdentityCA,
		Policy:         c.Policy,
		Presets:        c.Presets,
		BasePolicy:     c.BasePolicy,
		Secrets:        c.Secrets,
		Events:         c.Events,
	})
	if err != nil {
		return err
	}
	defer m.Close()
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
	var handler http.Handler
	var sshAdmin monitor.SSHAdmin
	if c.Owner == nil {
		handler = admin
	} else {
		mux := http.NewServeMux()
		mux.Handle("GET /healthz", admin)
		mux.Handle("GET /owner/ws", &owner.Handler{Key: c.Owner.Key, SessionKey: c.Owner.SessionKey, MaxBytes: monitor.MaxCallBytes, API: admin, Generation: m.Generation, Relay: m.DialBunkerOwner})
		handler, sshAdmin = mux, &owner.SSH{Key: c.Owner.Key, API: admin, Generation: m.Generation}
	}
	if c.Unlock != nil {
		if err := m.Unlock(ctx, c.Unlock); err != nil {
			return err
		}
	}
	go m.ServeSSH(c.SSH, sshAdmin)
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
