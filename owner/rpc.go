// Package owner authenticates Noise session, SSH and development bearer owner requests.
package owner

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"

	"github.com/coder/websocket"
	"github.com/flynn/noise"
	"github.com/tinfoilsh/confidential-agent-monitor/monitor"
	"github.com/tinfoilsh/confidential-agent-monitor/ownersession"
)

const (
	Protocol        = "monitor-owner-v1"
	ownerRPCSession = "owner-rpc"
)

// Handler serves the measured owner over Noise sessions on WebSockets.
type Handler struct {
	Key ed25519.PublicKey
	// SessionKey is this boot's attested static key for owner sessions.
	SessionKey noise.DHKey
	MaxBytes   int
	// API serves authenticated calls as the owner.
	API        http.Handler
	Generation Generation
	// Relay opens an instance's owner socket, which the owner then runs its own session over; nil refuses relays.
	Relay func(ctx context.Context, instance string) (*websocket.Conn, error)
}

type hello struct {
	Open       string `json:"open"`
	InstanceID string `json:"instance_id"`
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var open hello
	c, err := ownersession.Accept(w, r, h.SessionKey, Protocol, h.Key, &open)
	if err != nil {
		return
	}
	switch {
	case open.Open == "rpc":
		c.ServeRPC(r.Context(), h.MaxBytes, h.serve)
	case open.Open == "relay" && h.Relay != nil:
		upstream, err := h.Relay(r.Context(), open.InstanceID)
		if err != nil {
			// The innermost cause fits the close frame's 123-byte reason; dial wrappers add the URL.
			for errors.Unwrap(err) != nil {
				err = errors.Unwrap(err)
			}
			c.Conn.Close(websocket.StatusInternalError, "relay unavailable: "+err.Error())
			return
		}
		upstream.SetReadLimit(noise.MaxMsgLen)
		relay(r.Context(), c.Conn, upstream)
	default:
		c.Conn.Close(websocket.StatusPolicyViolation, ownersession.ErrMalformed.Error())
	}
}

func (h *Handler) serve(ctx context.Context, call ownersession.Call) ownersession.Reply {
	target, ok := ownerRPCTarget(call.Path)
	if !ok || (call.Method != http.MethodGet && call.Method != http.MethodPost) || (call.Method == http.MethodGet && len(call.Body) != 0) {
		return ownersession.Reply{Status: http.StatusBadRequest, Body: []byte(ownersession.ErrMalformed.Error())}
	}
	if h.Generation.stale(call.Generation) {
		return ownersession.Reply{Status: http.StatusConflict, Body: []byte(ErrStaleGeneration.Error())}
	}
	// An admitted effect finishes even if its socket closes.
	if call.Method == http.MethodPost {
		ctx = context.WithoutCancel(ctx)
	}
	session := monitor.Caller{Name: monitor.Owner, Owner: true, Minimum: call.Generation, ID: ownerRPCSession}
	inner := httptest.NewRequestWithContext(monitor.WithCaller(ctx, session), call.Method, "/", bytes.NewReader(call.Body))
	inner.URL = target
	if call.Method == http.MethodPost {
		inner.Header.Set("Content-Type", "application/json")
	}
	recorder := httptest.NewRecorder()
	h.API.ServeHTTP(recorder, inner)
	return ownersession.Reply{Status: recorder.Code, Body: recorder.Body.Bytes()}
}

// relay copies whole messages each way until either side ends, passing on its close.
func relay(ctx context.Context, owner, upstream *websocket.Conn) {
	defer owner.CloseNow()
	go func() {
		copyMessages(ctx, upstream, owner)
		upstream.CloseNow()
	}()
	copyMessages(ctx, owner, upstream)
}

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

// ownerRPCTarget accepts an origin-relative owner API path, never the app or a nested RPC.
// Like panel, it refuses ".." and backslashes, here also after percent-decoding.
func ownerRPCTarget(raw string) (*url.URL, bool) {
	u, err := url.Parse(raw)
	if err != nil || !strings.HasPrefix(raw, "/") || strings.HasPrefix(raw, "//") || strings.Contains(raw, "\\") ||
		u.Scheme != "" || u.Host != "" || u.User != nil || u.Opaque != "" || u.Fragment != "" ||
		strings.Contains(u.Path, "..") || strings.Contains(u.Path, "\\") || path.Clean(u.Path) != u.Path {
		return nil, false
	}
	for _, reserved := range []string{"/app", "/owner"} {
		if u.Path == reserved || strings.HasPrefix(u.Path, reserved+"/") {
			return nil, false
		}
	}
	return u, true
}

var ErrStaleGeneration = errors.New("Perimeter state is older than the saved generation")

// Generation reports the live generation, and false while the Monitor is locked.
type Generation func() (uint64, bool)

// stale reports a live state older than a generation the owner has saved.
func (g Generation) stale(minimum uint64) bool {
	current, unlocked := g()
	return unlocked && current < minimum
}
