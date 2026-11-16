package main

import (
	"bytes"
	"cmp"
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

	"filippo.io/edwards25519"
	"github.com/coder/websocket"
	"github.com/flynn/noise"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/connections"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/sandbox"
	"github.com/tinfoilsh/confidential-agent-monitor/core"
	"github.com/tinfoilsh/confidential-agent-monitor/core/certificates"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/netx"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/noisetransport"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/sshtransport"
	"golang.org/x/crypto/ssh"
)

// Transports: SSH for agents, routes and the owner CLI; HTTP for the owner API, as bearer
// calls in local development or Noise sessions over a WebSocket in production.

const (
	readHeaderTimeout = 30 * time.Second
	preflightMaxAge   = "600"
	bearerMode        = "bearer"
	ownerMode         = "ssh"
	ownerHost         = "owner" + connections.Domain
	rpcMode           = "rpc"
	relayMode         = "relay"

	sshChannel           = "tinfoil-owner-http-v1"
	sshGenerationRequest = "tinfoil-owner-generation-v1"
	// sessionHeader carries sshOptions.Token on each API request over the channel.
	sessionHeader = "X-Tinfoil-Session"
	// generationAckTimeout closes a stalled owner channel so an owner client cannot leave its goroutine behind.
	generationAckTimeout = 10 * time.Second

	ownerProtocol   = "monitor-owner-v1"
	ownerRPCSession = "owner-rpc"
	sessionContext  = "tinfoil owner session v1\x00"
	// sessionTimeout bounds the handshake and hello, so unauthenticated sockets do not linger.
	sessionTimeout = 10 * time.Second
	maxCalls       = 4
)

var (
	sshLimits          = sshtransport.Limits{MaxAuthTries: 3, MaxHandshakes: 64, HandshakeTimeout: 10 * time.Second}
	errMalformed       = errors.New("malformed")
	errSignature       = errors.New("invalid_signature")
	errStaleGeneration = errors.New("Perimeter state is older than the saved generation")
	errCertificate     = errors.New("an identity certificate must be an expiring user certificate with a key ID from the identity CA")
)

// owner authenticates the owner's sessions; nil lets the storage key authenticate bearer calls, for local development.
type owner struct {
	key        ed25519.PublicKey
	sessionKey noise.DHKey
	// relay opens an instance's owner socket, which the owner then runs its own session over; nil refuses relays.
	relay func(ctx context.Context, instance string) (*websocket.Conn, error)
}

// serve runs the SSH and API listeners until ctx ends or either fails, and closes both before it returns.
func (s *state) serve(ctx context.Context, sshListener, apiListener net.Listener, o *owner, ui http.Handler) error {
	defer sshListener.Close()
	defer apiListener.Close()

	if o != nil && s.hostKey() == nil {
		return errors.New("an owner requires a host key")
	}

	api, mode := s.adminAPI(), bearerMode
	if o != nil {
		mode = ownerMode
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
	var ownerSSH sshtransport.Session
	if o == nil {
		handler.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
			if key, err := base64.StdEncoding.Strict().DecodeString(token); ok && err == nil && s.isOwner(key) {
				r = r.WithContext(withCaller(r.Context(), caller{Name: ownerName, Owner: true, Key: key}))
			}
			api.ServeHTTP(w, r)
		})
	} else {
		modes := map[string]func(context.Context, *noisetransport.Session, json.RawMessage){rpcMode: func(ctx context.Context, c *noisetransport.Session, _ json.RawMessage) {
			serveRPC(ctx, c, maxCallBytes, s.ownerRPC(api))
		}}
		if o.relay != nil {
			modes[relayMode] = func(ctx context.Context, c *noisetransport.Session, hello json.RawMessage) {
				relayOwner(ctx, c, hello, o.relay)
			}
		}
		handler.HandleFunc("GET /owner/ws", func(w http.ResponseWriter, r *http.Request) {
			c, hello, err := noisetransport.Accept(w, r, noisetransport.Config{Key: o.sessionKey, Prologue: ownerProtocol, Timeout: sessionTimeout,
				// The signed Noise channel authenticates the owner, not the browser origin.
				Accept: &websocket.AcceptOptions{InsecureSkipVerify: true}}, func(binding, first []byte) error {
				var signed struct {
					Signature []byte `json:"signature"`
				}
				if json.Unmarshal(first, &signed) != nil {
					return errMalformed
				}
				if !ed25519.Verify(o.key, append([]byte(sessionContext), binding...), signed.Signature) {
					return errSignature
				}
				return nil
			})
			if err != nil {
				return
			}
			var open struct {
				Open string `json:"open"`
			}
			if json.Unmarshal(hello, &open) != nil || modes[open.Open] == nil {
				c.Conn.Close(websocket.StatusPolicyViolation, errMalformed.Error())
				return
			}
			modes[open.Open](r.Context(), c, hello)
		})
		ownerSSH = func(_ *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
			go ssh.DiscardRequests(reqs)
			for nc := range chans {
				go s.serveOwnerChannel(nc, api)
			}
		}
	}

	// Extensions take whole connections before identities: the owner CLI, then route publishers.
	authenticate := func(conn ssh.ConnMetadata, key ssh.PublicKey) (sshtransport.Session, func() error, error) {
		if ownerSSH != nil {
			if raw, ok := key.(ssh.CryptoPublicKey); ok {
				if public, ok := raw.CryptoPublicKey().(ed25519.PublicKey); ok && o.key.Equal(public) {
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
			// Principals carry groups, not logins, so any listed one stands in for the login.
			claims, err := certificates.VerifySSHUser(identityCA, cert, cmp.Or(cert.ValidPrincipals...))
			if err == nil && (claims.KeyID == "" || claims.ValidBefore == ssh.CertTimeInfinity) {
				err = errCertificate
			}
			if err != nil {
				return nil, nil, err
			}
			// A certificate is public, so it is registered only once its key has signed.
			fingerprint := ssh.FingerprintSHA256(cert.Key)
			return s.agentSession(fingerprint), func() error {
				end, err := s.identities.Register(fingerprint, facts.Principal{Name: claims.KeyID, Groups: claims.Principals}, false)
				if err == nil {
					time.AfterFunc(time.Until(time.Unix(int64(claims.ValidBefore), 0)), end)
				}
				return err
			}, nil
		}
		fingerprint := ssh.FingerprintSHA256(key)
		if _, known := s.identities.Lookup(fingerprint); !known {
			return nil, nil, errNoAccess
		}
		return s.agentSession(fingerprint), nil, nil
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
	sshtransport.Serve(sshListener, s.hostKey, sshLimits, authenticate, func(err error) { log.Printf("ssh: %v", err) })
	stop(errors.New("the SSH listener closed"))
	if ctx.Err() != nil {
		return nil
	}
	return context.Cause(serving)
}

// agentSession serves an identity's direct-tcpip streams while its key stays registered.
func (s *state) agentSession(fingerprint string) sshtransport.Session {
	return func(_ *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
		sshtransport.ServeDirect(chans, reqs, func(ctx context.Context, host string, port uint32, accept func() (net.Conn, error)) error {
			held, cancel, ok := s.identities.Hold(ctx, fingerprint)
			if !ok {
				return errNoAccess
			}
			defer cancel()
			return s.open(held, fingerprint, host, port, accept)
		})
	}
}

// open serves one agent stream. An identity that holds the routes capability reaches a reserved
// route host directly; every other stream goes to the agent API or a connection.
func (s *state) open(ctx context.Context, key, host string, port uint32, accept func() (net.Conn, error)) error {
	if sandbox.ReservedRoute(host) {
		// Relay under the hold, not ctx, which ends when the stream's channel closes and would cut its drain.
		if held, release, ok := s.hold(context.WithoutCancel(ctx), key, capabilityRoutes); ok {
			defer release()
			if err := netx.Dial(s.routes.DialContext, connections.RelayDrain)(held, host, port, accept); err != nil {
				return sandbox.ErrDirectUnavailable
			}
			return nil
		}
	}
	if s.settings.Load() == nil {
		return errLocked
	}
	p, known := s.identities.Lookup(key)
	if !known {
		return errNoAccess
	}
	if host != agentHost {
		return s.table.Open(ctx, p, host, port, accept)
	}
	if port != agentPort {
		return fmt.Errorf("%s uses HTTP on port %d inside the SSH tunnel", agentHost, agentPort)
	}
	conn, err := accept()
	if err != nil {
		return err
	}
	netx.ServeConn(ctx, conn, &http.Server{Handler: s.agentAPI(key)})
	return nil
}

// selectTarget picks the connection a stream addresses: by name under connectionDomain, or else
// the single best claim among the candidates the identity reaches.
func selectTarget(host string, port uint32, candidates []core.Candidate) (string, bool, bool) {
	if name, named := strings.CutSuffix(host, connections.Domain); named {
		return name, true, slices.ContainsFunc(candidates, func(c core.Candidate) bool { return c.Name == name })
	}
	best, tied, selected := -1, false, ""
	for _, c := range candidates {
		if c.Claim == nil {
			continue
		}
		score := c.Claim(host, port)
		if score < 0 {
			continue
		}
		if score > best {
			selected, best, tied = c.Name, score, false
		} else if score == best {
			tied = true
		}
	}
	return selected, false, best >= 0 && !tied
}

func (s *state) reaches(_ context.Context, p facts.Principal, connection string) bool {
	current, known := s.identities.Lookup(p.Key)
	return known && s.settings.Load().Reaches(current.Name, connection)
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

// stale reports a live state older than a generation the owner has saved.
func (s *state) stale(minimum uint64) bool {
	current, unlocked := s.generation()
	return unlocked && current < minimum
}

// sshOptions is the extra data of an sshChannel, in SSH wire encoding. The authenticated owner CLI supplies it, never the browser.
type sshOptions struct {
	Host       string
	Token      string
	Generation uint64
}

// sshGeneration is the payload of an sshGenerationRequest, in SSH wire encoding.
type sshGeneration struct{ Generation uint64 }

// serveOwnerChannel serves the API to the owner CLI over one SSH channel.
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
		// Do not report success until the CLI has persisted the generation.
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

// panel keeps browser protections with the measured UI. The CLI only forwards bytes.
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
		// Only the CLI channel can send the storage key; the browser cannot unlock.
		path := strings.TrimPrefix(r.URL.Path, "/api")
		if (path == "/unlock" && options.Host != ownerHost) || !ownerPath(path) {
			http.NotFound(w, r)
			return
		}
		r = r.Clone(withCaller(r.Context(), caller{Name: ownerName, Owner: true, Minimum: options.Generation, Acknowledge: acknowledge, ID: options.Token}))
		r.URL.Path = path
		r.URL.RawPath = ""
		api.ServeHTTP(w, r)
	})
}

// ownerCall is one owner RPC request; its ownerReply carries the same ID.
type ownerCall struct {
	ID         uint64 `json:"id"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Generation uint64 `json:"generation"`
	Body       []byte `json:"body"`
}

type ownerReply struct {
	ID     uint64 `json:"id"`
	Status int    `json:"status"`
	Body   []byte `json:"body"`
}

// ownerRPC answers each call with api, as a request carrying the call's method, path and body.
func (s *state) ownerRPC(api http.Handler) func(context.Context, ownerCall) ownerReply {
	return func(ctx context.Context, call ownerCall) ownerReply {
		if !validRPCPath(call.Path) || (call.Method != http.MethodGet && call.Method != http.MethodPost) || (call.Method == http.MethodGet && len(call.Body) != 0) {
			return ownerReply{Status: http.StatusBadRequest, Body: []byte(errMalformed.Error())}
		}
		if s.stale(call.Generation) {
			return ownerReply{Status: http.StatusConflict, Body: []byte(errStaleGeneration.Error())}
		}
		// An admitted effect finishes even if its socket closes.
		if call.Method == http.MethodPost {
			ctx = context.WithoutCancel(ctx)
		}
		ctx = withCaller(ctx, caller{Name: ownerName, Owner: true, Minimum: call.Generation, ID: ownerRPCSession})
		r, err := http.NewRequestWithContext(ctx, call.Method, call.Path, bytes.NewReader(call.Body))
		if err != nil {
			return ownerReply{Status: http.StatusBadRequest, Body: []byte(errMalformed.Error())}
		}
		if call.Method == http.MethodPost {
			r.Header.Set("Content-Type", "application/json")
		}
		recorder := httptest.NewRecorder()
		api.ServeHTTP(recorder, r)
		return ownerReply{Status: recorder.Code, Body: recorder.Body.Bytes()}
	}
}

// validRPCPath accepts an origin-relative owner API path; it checks ownerPath after percent-decoding.
func validRPCPath(raw string) bool {
	u, err := url.Parse(raw)
	return err == nil && strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") && !strings.Contains(raw, "\\") &&
		u.Scheme == "" && u.Host == "" && u.User == nil && u.Opaque == "" && u.Fragment == "" &&
		path.Clean(u.Path) == u.Path && ownerPath(u.Path)
}

// ownerPath refuses the app, a nested owner session, and paths an upstream could resolve differently.
func ownerPath(p string) bool {
	return !strings.Contains(p, "..") && !strings.Contains(p, "\\") && !slices.ContainsFunc([]string{"/app", "/owner"}, func(reserved string) bool {
		return p == reserved || strings.HasPrefix(p, reserved+"/")
	})
}

// serveRPC answers calls of at most limit bytes, a few at once and in any order, until the socket ends.
func serveRPC(ctx context.Context, c *noisetransport.Session, limit int, serve func(context.Context, ownerCall) ownerReply) {
	running := make(chan struct{}, maxCalls)
	for {
		var call ownerCall
		message, err := c.Read(ctx, limit)
		if err == nil {
			err = json.Unmarshal(message, &call)
		}
		if err != nil {
			c.Conn.Close(websocket.StatusPolicyViolation, errMalformed.Error())
			return
		}
		running <- struct{}{}
		go func() {
			defer func() { <-running }()
			reply := serve(ctx, call)
			reply.ID = call.ID
			out, _ := json.Marshal(reply)
			c.Write(ctx, out)
		}()
	}
}

// relayOwner opens the owner socket of the hello's instance, which the owner then runs its own session over.
func relayOwner(ctx context.Context, c *noisetransport.Session, hello json.RawMessage, dial func(ctx context.Context, instance string) (*websocket.Conn, error)) {
	var open struct {
		InstanceID string `json:"instance_id"`
	}
	if json.Unmarshal(hello, &open) != nil {
		c.Conn.Close(websocket.StatusPolicyViolation, errMalformed.Error())
		return
	}
	upstream, err := dial(ctx, open.InstanceID)
	if err != nil {
		// The innermost cause fits the close frame's 123-byte reason; dial wrappers add the URL.
		for errors.Unwrap(err) != nil {
			err = errors.Unwrap(err)
		}
		c.Conn.Close(websocket.StatusInternalError, "relay unavailable: "+err.Error())
		return
	}
	upstream.SetReadLimit(noise.MaxMsgLen)
	defer c.Conn.CloseNow()
	go func() {
		copyMessages(ctx, upstream, c.Conn)
		upstream.CloseNow()
	}()
	copyMessages(ctx, c.Conn, upstream)
}

// copyMessages copies whole messages until either side ends, passing on its close.
func copyMessages(ctx context.Context, dst, src *websocket.Conn) {
	for {
		kind, message, err := src.Read(ctx)
		var closed websocket.CloseError
		if errors.As(err, &closed) {
			dst.Close(closed.Code, closed.Reason)
		}
		if err != nil || dst.Write(ctx, kind, message) != nil {
			return
		}
	}
}

// parseOwnerKey reads a measured owner key. A small-order point would verify forged
// signatures for any message, so only canonical keys outside the torsion subgroup pass.
func parseOwnerKey(value string) (ed25519.PublicKey, error) {
	encoded, ok := strings.CutPrefix(value, "ed25519:")
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if ok && err == nil && len(key) == ed25519.PublicKeySize && "ed25519:"+base64.StdEncoding.EncodeToString(key) == value {
		point, err := new(edwards25519.Point).SetBytes(key)
		if err == nil && bytes.Equal(point.Bytes(), key) && new(edwards25519.Point).MultByCofactor(point).Equal(edwards25519.NewIdentityPoint()) == 0 {
			return key, nil
		}
	}
	return nil, errors.New("owner public key must be ed25519: followed by the base64 of a valid Ed25519 public key")
}
