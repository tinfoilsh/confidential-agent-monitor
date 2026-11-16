package perimeter

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/core/netx"
	"github.com/tinfoilsh/confidential-agent-monitor/core/sshx"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/monitor"
	"golang.org/x/crypto/ssh"
)

const (
	sshChannel           = "tinfoil-owner-http-v1"
	sshGenerationRequest = "tinfoil-owner-generation-v1"
	// sessionHeader carries sshOptions.Token on each API request over the channel.
	sessionHeader = "X-Tinfoil-Session"
)

// sshOptions is the extra data of an sshChannel, in SSH wire encoding. The authenticated owner CLI supplies it, never the browser.
type sshOptions struct {
	Host       string
	Token      string
	Generation uint64
}

// sshGeneration is the payload of an sshGenerationRequest, in SSH wire encoding.
type sshGeneration struct{ Generation uint64 }

type ownerSSH struct {
	Key        ed25519.PublicKey
	API        http.Handler
	Generation liveGeneration
	Host       string
}

func (o *ownerSSH) Authenticate(_ ssh.ConnMetadata, key ssh.PublicKey) (sshx.Session, error) {
	if raw, ok := key.(ssh.CryptoPublicKey); ok {
		if public, ok := raw.CryptoPublicKey().(ed25519.PublicKey); ok && o.Key.Equal(public) {
			return o.Serve, nil
		}
	}
	return nil, nil
}

func (o *ownerSSH) Serve(_ *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		go o.serveChannel(nc)
	}
}

// serveChannel serves API to the owner CLI over one SSH channel.
func (o *ownerSSH) serveChannel(nc ssh.NewChannel) {
	if nc.ChannelType() != sshChannel {
		nc.Reject(ssh.Prohibited, "owner connections only serve the owner UI and API")
		return
	}
	var options sshOptions
	if err := ssh.Unmarshal(nc.ExtraData(), &options); err != nil || !validOptions(options, o.Host) {
		nc.Reject(ssh.Prohibited, "invalid owner channel options")
		return
	}
	if o.Generation.stale(options.Generation) {
		nc.Reject(ssh.Prohibited, errStaleGeneration.Error())
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	conn := sshx.NewConn(ch, reqs)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { <-conn.Closed(); cancel() }()
	acknowledge := func() error {
		current, unlocked := o.Generation()
		if !unlocked {
			return nil
		}
		// Do not report success until the CLI has persisted the generation. Close
		// a stalled channel so an owner client cannot leave this goroutine behind.
		timer := time.AfterFunc(10*time.Second, cancel)
		defer timer.Stop()
		ok, err := ch.SendRequest(sshGenerationRequest, true, ssh.Marshal(sshGeneration{Generation: current}))
		if err != nil || !ok {
			return errors.New("owner CLI did not save the generation")
		}
		return nil
	}
	server := &http.Server{Handler: panel(o.API, options, o.Host, acknowledge), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: time.Minute, IdleTimeout: time.Minute, MaxHeaderBytes: 8192}
	netx.ServeConn(ctx, conn, server)
}

func validOptions(o sshOptions, ownerHost string) bool {
	token, err := base64.RawURLEncoding.DecodeString(o.Token)
	if err != nil || len(token) != 32 {
		return false
	}
	if o.Host == ownerHost {
		return true
	}
	host, port, err := net.SplitHostPort(o.Host)
	return err == nil && host == "127.0.0.1" && port != "" && !strings.ContainsAny(port, "/?#@ ")
}

// Browser protections live with the measured UI. The CLI only forwards bytes.
func panel(api http.Handler, options sshOptions, ownerHost string, acknowledge func() error) http.Handler {
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
		if subtle.ConstantTimeCompare([]byte(r.Header.Get(sessionHeader)), []byte(options.Token)) != 1 {
			http.Error(w, "local panel session required", http.StatusUnauthorized)
			return
		}
		// Only the CLI channel can send the storage key; the browser cannot unlock.
		path := strings.TrimPrefix(r.URL.Path, "/api")
		if (path == "/unlock" && options.Host != ownerHost) || !ownerPath(path) {
			http.NotFound(w, r)
			return
		}
		r = r.Clone(monitor.WithCaller(r.Context(), monitor.Caller{Name: monitor.Owner, Owner: true, Minimum: options.Generation, Acknowledge: acknowledge, ID: options.Token}))
		r.URL.Path = path
		r.URL.RawPath = ""
		api.ServeHTTP(w, r)
	})
}
