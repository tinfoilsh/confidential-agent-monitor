package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"slices"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/flynn/noise"
	"github.com/rs/cors"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/connections"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/sandbox"
	"github.com/tinfoilsh/confidential-agent-monitor/core"
	"github.com/tinfoilsh/confidential-agent-monitor/core/certificates"
	"github.com/tinfoilsh/confidential-agent-monitor/core/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/netx"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/noisetransport"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/sshtransport"
	"golang.org/x/crypto/ssh"
)

const (
	readHeaderTimeout = 30 * time.Second
	preflightMaxAge   = 600
	ownerHost         = "owner" + connections.Domain

	bearerMode = "bearer"
	sshMode    = "ssh"

	rpcMode   = "rpc"
	relayMode = "relay"

	sshChannel           = "tinfoil-owner-http-v1"
	sshGenerationRequest = "tinfoil-owner-generation-v1"
	sessionHeader        = "X-Tinfoil-Session"
	generationAckTimeout = 10 * time.Second

	ownerProtocol   = "monitor-owner-v1"
	ownerRPCSession = "owner-rpc"
	sessionContext  = "tinfoil owner session v1\x00"
	sessionTimeout  = 10 * time.Second
	maxCalls        = 4
)

var (
	sshLimits          = sshtransport.Limits{MaxAuthTries: 3, MaxHandshakes: 64, HandshakeTimeout: 10 * time.Second}
	errMalformed       = errors.New("malformed")
	errStaleGeneration = errors.New("Perimeter state is older than the saved generation")
)

type owner struct {
	publicKey  ed25519.PublicKey
	sessionKey noise.DHKey
}

func (s *state) serve(ctx context.Context, sshListener, apiListener net.Listener, o *owner, ui http.Handler) error {
	defer sshListener.Close()
	defer apiListener.Close()

	if o != nil && s.hostKey() == nil {
		return errors.New("an owner requires a host key")
	}

	api, mode := s.adminAPI(), bearerMode
	if o != nil {
		mode = sshMode
	}
	if ui != nil {
		app := http.NewServeMux()
		app.Handle("/", api)
		app.Handle("GET /app/auth.json", jsonHandler(0, func(_ *http.Request, _ struct{}) (any, error) {
			return map[string]string{"mode": mode}, nil
		}))
		app.HandleFunc("GET /app/", func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			ui.ServeHTTP(w, r)
		})
		api = app
	}

	handler := http.NewServeMux()
	handler.Handle("GET /healthz", api)
	if o == nil {
		handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if key, err := base64.StdEncoding.Strict().DecodeString(token); ok && err == nil && s.acceptsStorageKey(key) {
				r = r.WithContext(withCaller(r.Context(), caller{Name: ownerName, Owner: true, StorageKey: key}))
			}
			api.ServeHTTP(w, r)
		})
	} else {
		handler.HandleFunc("GET /owner/ws", func(w http.ResponseWriter, r *http.Request) {
			c, hello, err := noisetransport.Accept(w, r, noisetransport.Config{Key: o.sessionKey, Prologue: ownerProtocol, Timeout: sessionTimeout,
				Accept: &websocket.AcceptOptions{InsecureSkipVerify: true}}, noisetransport.Signed(o.publicKey, sessionContext))
			if err != nil {
				return
			}
			var open struct {
				Open       string `json:"open"`
				InstanceID string `json:"instance_id"`
			}
			err = json.Unmarshal(hello, &open)
			switch {
			case err == nil && open.Open == rpcMode:
				c.ServeRPC(r.Context(), maxCallBytes, maxCalls, s.ownerRPC(api))
			case err == nil && open.Open == relayMode:
				sandbox.RelayOwner(r.Context(), s.relays, c.Conn, open.InstanceID)
			default:
				c.Conn.Close(websocket.StatusPolicyViolation, errMalformed.Error())
			}
		})
	}

	ownerSSH := func(_ *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
		go ssh.DiscardRequests(reqs)
		for nc := range chans {
			go s.serveOwnerChannel(nc, api)
		}
	}

	server := &http.Server{Handler: allowOrigins(ownerOrigins, handler), ReadHeaderTimeout: readHeaderTimeout}
	defer server.Close()

	serving, stop := context.WithCancelCause(ctx)
	go func() {
		stop(server.Serve(apiListener))
	}()
	context.AfterFunc(serving, func() {
		sshListener.Close()
	})
	sshtransport.Serve(sshListener, s.hostKey, sshLimits, s.authenticate(o, ownerSSH), func(err error) { log.Printf("ssh: %v", err) })
	stop(errors.New("the SSH listener closed"))
	if ctx.Err() != nil {
		return nil
	}
	return context.Cause(serving)
}

func (s *state) authenticate(o *owner, ownerSSH sshtransport.Session) sshtransport.Authenticate {
	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (sshtransport.Session, func() error, error) {
		if o != nil {
			if raw, ok := key.(ssh.CryptoPublicKey); ok {
				if public, ok := raw.CryptoPublicKey().(ed25519.PublicKey); ok && o.publicKey.Equal(public) {
					return ownerSSH, nil, nil
				}
			}
		}
		if session, err := s.routes.Publisher(conn.User(), key, func(fingerprint string) (bool, error) {
			if _, unlocked := s.generation(); !unlocked {
				return false, errLocked
			}
			_, trusted := s.identities.Lookup(fingerprint)
			return trusted, nil
		}); session != nil || err != nil {
			return session, nil, err
		}
		if cert, ok := key.(*ssh.Certificate); ok && identityCA != nil {
			p, err := certificates.SSHUser(identityCA, cert)
			if err != nil {
				return nil, nil, err
			}
			fingerprint := ssh.FingerprintSHA256(cert.Key)
			return s.agentSession(fingerprint), func() error {
				end, err := s.identities.Register(fingerprint, p, false)
				if err == nil {
					time.AfterFunc(time.Until(time.Unix(int64(cert.ValidBefore), 0)), end)
				}
				return err
			}, nil
		}
		fingerprint := ssh.FingerprintSHA256(key)
		if st := s.settings.Load(); st == nil || st.Principals[fingerprint] == "" {
			return nil, nil, errNoAccess
		}
		return s.agentSession(fingerprint), nil, nil
	}
}

func (s *state) agentSession(fingerprint string) sshtransport.Session {
	return func(_ *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
		sshtransport.ServeDirect(chans, reqs, func(ctx context.Context, network, host string, port uint32, accept func() (net.Conn, error)) error {
			ctx, cancel, ok := s.identities.Hold(ctx, fingerprint)
			if !ok {
				return errNoAccess
			}
			defer cancel()
			return s.open(ctx, fingerprint, network, host, port, accept)
		})
	}
}

func (s *state) open(ctx context.Context, fingerprint, network, host string, port uint32, accept func() (net.Conn, error)) error {
	if network == "tcp" && sandbox.ReservedRoute(host) {
		if routed, release, ok := s.hold(context.WithoutCancel(ctx), fingerprint, capabilityRoutes); ok {
			defer release()
			if err := netx.Dial(s.routes.DialContext, connections.RelayDrain)(routed, network, host, port, accept); err != nil {
				return sandbox.ErrDirectUnavailable
			}
			return nil
		}
	}
	if s.settings.Load() == nil {
		return errLocked
	}
	p, known := s.identities.Lookup(fingerprint)
	if !known {
		return errNoAccess
	}
	if host != agentHost || network != "tcp" {
		return s.table.Open(p)(ctx, network, host, port, accept)
	}
	if port != agentPort {
		return fmt.Errorf("%s uses HTTP on port %d inside the SSH tunnel", agentHost, agentPort)
	}
	conn, err := accept()
	if err != nil {
		return err
	}
	netx.ServeConn(ctx, conn, &http.Server{Handler: s.agentAPI(fingerprint)})
	return nil
}

func selectTarget(target connector.Target, candidates []core.Candidate) (name string, explicit bool, err error) {
	if named, found := strings.CutSuffix(target.Host, connections.Domain); found {
		return named, true, nil
	}
	name, explicit, err = core.BestClaim(target, candidates)
	if errors.Is(err, core.ErrAmbiguous) {
		err = fmt.Errorf("%w as <connection>%s", err, connections.Domain)
	}
	return name, explicit, err
}

func (s *state) reaches(_ context.Context, p facts.Principal, connection string) bool {
	current, known := s.identities.Lookup(p.Key)
	return known && s.settings.Load().Reaches(current.Name, connection)
}

func allowOrigins(origins []string, next http.Handler) http.Handler {
	if len(origins) == 0 {
		return next
	}
	return cors.New(cors.Options{
		AllowOriginFunc: func(origin string) bool { return slices.Contains(origins, origin) },
		AllowedHeaders:  []string{"Authorization", "Content-Type", "If-None-Match"},
		ExposedHeaders:  []string{"ETag"},
		MaxAge:          preflightMaxAge,
	}).Handler(next)
}

func (s *state) stale(minimum uint64) bool {
	current, unlocked := s.generation()
	return unlocked && current < minimum
}

type sshOptions struct {
	Host       string
	Token      string
	Generation uint64
}

type sshGeneration struct{ Generation uint64 }

func (s *state) serveOwnerChannel(nc ssh.NewChannel, api http.Handler) {
	if nc.ChannelType() != sshChannel {
		nc.Reject(ssh.Prohibited, "owner connections only serve the owner UI and API")
		return
	}
	var options sshOptions
	if err := ssh.Unmarshal(nc.ExtraData(), &options); err != nil || !validOptions(options) {
		nc.Reject(ssh.Prohibited, "invalid owner channel options")
		return
	}
	if s.stale(options.Generation) {
		nc.Reject(ssh.Prohibited, errStaleGeneration.Error())
		return
	}
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	conn := sshtransport.NewConn(ch, reqs)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { <-conn.Closed(); cancel() }()
	acknowledge := func() error {
		current, unlocked := s.generation()
		if !unlocked {
			return nil
		}
		timer := time.AfterFunc(generationAckTimeout, cancel)
		defer timer.Stop()
		ok, err := ch.SendRequest(sshGenerationRequest, true, ssh.Marshal(sshGeneration{Generation: current}))
		if err != nil || !ok {
			return errors.New("owner CLI did not save the generation")
		}
		return nil
	}
	server := &http.Server{Handler: panel(api, options, acknowledge), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: time.Minute, IdleTimeout: time.Minute, MaxHeaderBytes: 8192}
	netx.ServeConn(ctx, conn, server)
}

func validOptions(o sshOptions) bool {
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

func panel(api http.Handler, options sshOptions, acknowledge func() error) http.Handler {
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
		apiPath := strings.TrimPrefix(r.URL.Path, "/api")
		if (apiPath == "/unlock" && options.Host != ownerHost) || !ownerPath(apiPath) {
			http.NotFound(w, r)
			return
		}
		r = r.Clone(withCaller(r.Context(), caller{Name: ownerName, Owner: true, MinGeneration: options.Generation, Acknowledge: acknowledge, Session: options.Token}))
		r.URL.Path = apiPath
		r.URL.RawPath = ""
		api.ServeHTTP(w, r)
	})
}

func (s *state) ownerRPC(api http.Handler) func(context.Context, noisetransport.Call) noisetransport.Reply {
	return func(ctx context.Context, call noisetransport.Call) noisetransport.Reply {
		if !validRPCPath(call.Path) || (call.Method != http.MethodGet && call.Method != http.MethodPost) || (call.Method == http.MethodGet && len(call.Body) != 0) {
			return noisetransport.Reply{Status: http.StatusBadRequest, Body: []byte(errMalformed.Error())}
		}
		if s.stale(call.Generation) {
			return noisetransport.Reply{Status: http.StatusConflict, Body: []byte(errStaleGeneration.Error())}
		}
		if call.Method == http.MethodPost {
			ctx = context.WithoutCancel(ctx)
		}
		ctx = withCaller(ctx, caller{Name: ownerName, Owner: true, MinGeneration: call.Generation, Session: ownerRPCSession})
		r, err := http.NewRequestWithContext(ctx, call.Method, call.Path, bytes.NewReader(call.Body))
		if err != nil {
			return noisetransport.Reply{Status: http.StatusBadRequest, Body: []byte(errMalformed.Error())}
		}
		if call.Method == http.MethodPost {
			r.Header.Set("Content-Type", "application/json")
		}
		recorder := httptest.NewRecorder()
		api.ServeHTTP(recorder, r)
		return noisetransport.Reply{Status: recorder.Code, Body: recorder.Body.Bytes()}
	}
}

func validRPCPath(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") && !strings.Contains(raw, "\\") &&
		u.Scheme == "" && u.Host == "" && u.User == nil && u.Opaque == "" && u.Fragment == "" &&
		path.Clean(u.Path) == u.Path && ownerPath(u.Path)
}

func ownerPath(p string) bool {
	return !strings.Contains(p, "..") && !strings.Contains(p, "\\") && !slices.ContainsFunc([]string{"/app", "/owner"}, func(reserved string) bool {
		return p == reserved || strings.HasPrefix(p, reserved+"/")
	})
}
