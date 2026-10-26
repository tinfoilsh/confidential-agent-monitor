// Package ownerauth authenticates bearer, signed RPC and SSH owner requests and carries their session context.
package ownerauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"
	"time"
)

const (
	// SignatureContext prefixes the request bytes an envelope signature covers.
	SignatureContext = "monitor owner rpc v1\x00"
	NonceBytes       = 24

	ownerRPCSkew      = 2 * time.Minute
	maxOwnerRPCNonces = 1 << 14
	ownerRPCSession   = "owner-rpc"
)

type Envelope struct {
	Request   []byte `json:"request"`
	Signature []byte `json:"signature"`
}

type ownerRPCRequest struct {
	Monitor    string          `json:"monitor"`
	Method     string          `json:"method"`
	Path       string          `json:"path"`
	Body       json.RawMessage `json:"body"`
	Generation uint64          `json:"generation"`
	IssuedAt   int64           `json:"issued_at"`
	Nonce      []byte          `json:"nonce"`
}

// Handler serves owner calls through the shim. The signature, Monitor binding and replay
// checks authenticate each call but cannot prove it was EHBP-sealed: the shim forwards no
// trusted sealing marker, so confidentiality relies on the client always sealing.
type Handler struct {
	Key ed25519.PublicKey
	// Monitor is the storage URL that binds envelopes to this Monitor.
	Monitor  string
	MaxBytes int64
	// API serves authenticated calls as the owner.
	API        http.Handler
	Generation Generation

	mu     sync.Mutex
	nonces map[string]time.Time
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var envelope Envelope
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.MaxBytes))
	if err == nil {
		err = json.Unmarshal(raw, &envelope)
	}
	if err != nil || len(envelope.Signature) != ed25519.SignatureSize {
		http.Error(w, "malformed owner RPC envelope", http.StatusBadRequest)
		return
	}
	// Verify original request bytes.
	if !ed25519.Verify(h.Key, append([]byte(SignatureContext), envelope.Request...), envelope.Signature) {
		http.Error(w, "invalid owner RPC signature", http.StatusUnauthorized)
		return
	}
	var call ownerRPCRequest
	decoder := json.NewDecoder(bytes.NewReader(envelope.Request))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&call); err != nil || decoder.Decode(new(json.RawMessage)) != io.EOF || len(call.Nonce) != NonceBytes {
		http.Error(w, "malformed owner RPC request", http.StatusBadRequest)
		return
	}
	issued := time.Unix(call.IssuedAt, 0)
	if call.Monitor != h.Monitor {
		http.Error(w, "owner RPC is addressed to another Monitor", http.StatusUnauthorized)
		return
	}
	if time.Since(issued).Abs() > ownerRPCSkew {
		http.Error(w, "owner RPC expired; check this device's clock", http.StatusUnauthorized)
		return
	}
	target, ok := ownerRPCTarget(call.Path)
	hasBody := len(call.Body) != 0 && string(call.Body) != "null"
	if !ok || (call.Method != http.MethodGet && call.Method != http.MethodPost) || (call.Method == http.MethodGet && hasBody) {
		http.Error(w, "owner RPC needs GET or POST of an owner API path", http.StatusBadRequest)
		return
	}
	// Consume nonces before dispatch.
	if err := h.remember(call.Nonce, issued.Add(ownerRPCSkew)); err != nil {
		status := http.StatusConflict
		if !errors.Is(err, errReplayed) {
			status = http.StatusServiceUnavailable
		}
		http.Error(w, err.Error(), status)
		return
	}
	var body io.Reader
	if call.Method == http.MethodPost {
		body = bytes.NewReader(call.Body)
	}
	inner, err := http.NewRequestWithContext(r.Context(), call.Method, "/", body)
	if err != nil {
		http.Error(w, "malformed owner RPC request", http.StatusBadRequest)
		return
	}
	inner.URL, inner.RemoteAddr = target, r.RemoteAddr
	if body != nil {
		inner.Header.Set("Content-Type", "application/json")
	}
	if h.Generation.stale(call.Generation) {
		http.Error(w, ErrStaleGeneration.Error(), http.StatusConflict)
		return
	}
	session := Session{Minimum: call.Generation, Acknowledge: func() error { return nil }, ID: ownerRPCSession}
	h.API.ServeHTTP(w, inner.WithContext(NewContext(inner.Context(), session)))
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

var (
	errReplayed   = errors.New("owner RPC was already used")
	errReplayBusy = errors.New("too many recent owner RPC calls; retry shortly")
)

// remember admits each nonce once until its envelope expires. When full of
// unexpired nonces it refuses new calls rather than forgetting one that could replay.
func (h *Handler) remember(nonce []byte, expires time.Time) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, seen := h.nonces[string(nonce)]; seen {
		return errReplayed
	}
	if len(h.nonces) >= maxOwnerRPCNonces {
		now := time.Now()
		maps.DeleteFunc(h.nonces, func(_ string, expiry time.Time) bool { return !now.Before(expiry) })
	}
	if len(h.nonces) >= maxOwnerRPCNonces {
		return errReplayBusy
	}
	if h.nonces == nil {
		h.nonces = map[string]time.Time{}
	}
	h.nonces[string(nonce)] = expires
	return nil
}

var ErrStaleGeneration = errors.New("Monitor state is older than the saved generation")

// Generation reports the live generation, and false while the Monitor is locked.
type Generation func() (uint64, bool)

// stale reports a live state older than a generation the owner has saved.
func (g Generation) stale(minimum uint64) bool {
	current, unlocked := g()
	return unlocked && current < minimum
}

type sessionKey struct{}

// Session is a request authenticated with the owner key, at the generation its owner has saved.
type Session struct {
	Minimum     uint64
	Acknowledge func() error
	ID          string
}

func NewContext(ctx context.Context, s Session) context.Context {
	return context.WithValue(ctx, sessionKey{}, s)
}

func FromContext(ctx context.Context) (Session, bool) {
	s, ok := ctx.Value(sessionKey{}).(Session)
	return s, ok
}
