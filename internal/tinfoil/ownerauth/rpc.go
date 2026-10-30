// Package ownerauth authenticates bearer, signed RPC and SSH owner requests and carries their session context.
package ownerauth

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync"
	"time"

	"filippo.io/edwards25519"
)

const (
	// RequestContext prefixes the SHA-256 of the request bytes an envelope signature covers.
	RequestContext = "tinfoil owner request v3\x00"
	Protocol       = "monitor-owner-v2"
	// RequestWindow is how far, in milliseconds, a request's time may be from this
	// Monitor's clock in either direction.
	RequestWindow = 60_000

	nonceBytes      = 24
	maxSafeInteger  = 1<<53 - 1
	maxNonces       = 1 << 14
	maxOperations   = 4096
	maxResultBytes  = 4 << 20
	maxResultsBytes = 64 << 20
	ownerRPCSession = "owner-rpc"
)

type envelope struct {
	Request   string `json:"request"`
	Signature string `json:"signature"`
}

// request is the signed owner request; fields stay in contract order.
type request struct {
	Protocol   string `json:"protocol"`
	Owner      string `json:"owner"`
	Resource   string `json:"resource"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Body       string `json:"body"`
	Operation  string `json:"operation"`
	Session    string `json:"session"`
	Generation uint64 `json:"generation"`
	IssuedAt   int64  `json:"issued_at"`
	Nonce      string `json:"nonce"`
}

// Handler serves owner calls through the shim. The signature, Monitor binding and replay
// checks authenticate each call but cannot prove it was EHBP-sealed: the shim forwards no
// trusted sealing marker, so confidentiality relies on the client always sealing.
type Handler struct {
	Key ed25519.PublicKey
	// Resource is the storage URL that binds requests to this Monitor.
	Resource string
	MaxBytes int64
	// API serves authenticated calls as the owner.
	API        http.Handler
	Generation Generation
	// Untracked POST paths only forward bytes, so their results are not kept for retries.
	Untracked []string
	Now       func() time.Time

	mu          sync.Mutex
	nonces      map[string]int64
	operations  map[string]*operation
	resultBytes int
}

// operation is one effectful request; retries with fresh nonces share its result.
type operation struct {
	content  [sha256.Size]byte
	deadline int64
	done     chan struct{}
	result   *recorder
}

// rejection is an owner authentication failure; the class is the shared contract's name.
type rejection struct {
	class  string
	status int
}

func (r rejection) Error() string { return r.class }

var (
	errMalformed = rejection{"malformed", http.StatusBadRequest}
	errSignature = rejection{"invalid_signature", http.StatusUnauthorized}
	errOwner     = rejection{"wrong_owner", http.StatusUnauthorized}
	errProtocol  = rejection{"wrong_protocol", http.StatusUnauthorized}
	errResource  = rejection{"wrong_resource", http.StatusUnauthorized}
	errFuture    = rejection{"request_time_in_future", http.StatusUnauthorized}
	errExpired   = rejection{"request_expired", http.StatusUnauthorized}
	errStale     = rejection{"stale_generation", http.StatusConflict}
	errReplayed  = rejection{"replayed", http.StatusConflict}
	errConflict  = rejection{"operation_conflict", http.StatusConflict}
	errBusy      = rejection{"owner_busy", http.StatusServiceUnavailable}
)

func reject(w http.ResponseWriter, err error) {
	r, ok := err.(rejection)
	if !ok {
		r = errMalformed
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(r.status)
	// The Monitor's clock lets an owner whose clock differs re-sign on it.
	json.NewEncoder(w).Encode(map[string]any{"error": r.class, "now": time.Now().UnixMilli()})
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	now := func() int64 { return time.Now().UnixMilli() }
	if h.Now != nil {
		now = func() int64 { return h.Now().UnixMilli() }
	}
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, h.MaxBytes))
	if err != nil {
		reject(w, errMalformed)
		return
	}
	call, err := h.open(raw, now())
	if err != nil {
		reject(w, err)
		return
	}
	target, ok := ownerRPCTarget(call.Path)
	if !ok || call.Session != "" || (call.Method != http.MethodGet && call.Method != http.MethodPost) || (call.Method == http.MethodGet && call.Body != "") {
		reject(w, errMalformed)
		return
	}
	if h.Generation.stale(call.Generation) {
		reject(w, errStale)
		return
	}
	// Consume nonces before dispatch.
	if err := h.reserve(call, now); err != nil {
		reject(w, err)
		return
	}
	decoded, _ := decodeB64U(call.Body, -1)
	inner, err := http.NewRequestWithContext(r.Context(), call.Method, "/", bytes.NewReader(decoded))
	if err != nil {
		reject(w, errMalformed)
		return
	}
	inner.URL, inner.RemoteAddr = target, r.RemoteAddr
	if call.Method == http.MethodPost {
		inner.Header.Set("Content-Type", "application/json")
	}
	session := Session{Minimum: call.Generation, Acknowledge: func() error { return nil }, ID: ownerRPCSession}
	inner = inner.WithContext(NewContext(inner.Context(), session))
	if call.Method == http.MethodGet || slices.Contains(h.Untracked, target.Path) {
		h.API.ServeHTTP(w, inner)
		return
	}
	op, first, err := h.track(call, now)
	if err != nil {
		reject(w, err)
		return
	}
	if first {
		recorder := &recorder{ResponseWriter: w, header: http.Header{}}
		defer h.finish(op, recorder, now)
		// An admitted effect finishes even if its reply is lost. Keep its actual
		// result for the same-operation retry; relay requests remain cancelable.
		h.API.ServeHTTP(recorder, inner.WithContext(context.WithoutCancel(inner.Context())))
		return
	}
	select {
	case <-op.done:
	case <-r.Context().Done():
		return
	}
	if op.result == nil {
		reject(w, errBusy)
		return
	}
	maps.Copy(w.Header(), op.result.header)
	w.WriteHeader(op.result.status)
	w.Write(op.result.body)
}

// open checks an envelope in the shared contract's order and returns its request.
func (h *Handler) open(raw []byte, now int64) (request, error) {
	var e envelope
	var call request
	if decodeCanonical(raw, &e) != nil {
		return call, errMalformed
	}
	signed, requestErr := decodeB64U(e.Request, -1)
	signature, signatureErr := decodeB64U(e.Signature, ed25519.SignatureSize)
	if requestErr != nil || signatureErr != nil {
		return call, errMalformed
	}
	// Verify original request bytes.
	digest := sha256.Sum256(signed)
	if !ed25519.Verify(h.Key, append([]byte(RequestContext), digest[:]...), signature) {
		return call, errSignature
	}
	if decodeCanonical(signed, &call) != nil || !call.wellFormed() {
		return call, errMalformed
	}
	switch {
	case call.Owner != OwnerKey(h.Key):
		return call, errOwner
	case call.Protocol != Protocol:
		return call, errProtocol
	case call.Resource != h.Resource:
		return call, errResource
	case call.IssuedAt-now > RequestWindow:
		return call, errFuture
	case now-call.IssuedAt > RequestWindow:
		return call, errExpired
	}
	return call, nil
}

func (c request) wellFormed() bool {
	_, nonceErr := decodeB64U(c.Nonce, nonceBytes)
	_, bodyErr := decodeB64U(c.Body, -1)
	return nonceErr == nil && bodyErr == nil && validID16(c.Operation) && (c.Session == "" || validID16(c.Session)) &&
		strings.HasPrefix(c.Path, "/") && strings.IndexFunc(c.Path, func(r rune) bool { return r < 0x21 || r > 0x7e }) < 0 &&
		c.Generation <= maxSafeInteger && c.IssuedAt >= 0 && c.IssuedAt <= maxSafeInteger
}

// reserve admits each nonce once until its request's inclusive deadline. When full of
// live nonces it refuses new calls rather than forgetting one that could replay. Every
// entry shares this Monitor's protocol, owner and resource, so the nonce alone is the key.
// The clock is read under mu, so a purged nonce is also expired for every later check.
func (h *Handler) reserve(call request, clock func() int64) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	now := clock()
	if now-call.IssuedAt > RequestWindow {
		return errExpired
	}
	if _, seen := h.nonces[call.Nonce]; seen {
		return errReplayed
	}
	if len(h.nonces) >= maxNonces {
		maps.DeleteFunc(h.nonces, func(_ string, deadline int64) bool { return now > deadline })
	}
	if len(h.nonces) >= maxNonces {
		return errBusy
	}
	if h.nonces == nil {
		h.nonces = map[string]int64{}
	}
	h.nonces[call.Nonce] = call.IssuedAt + RequestWindow
	return nil
}

// track returns the operation a request belongs to and whether this request runs it.
// A retry must repeat the original content and time; only its nonce changes.
func (h *Handler) track(call request, clock func() int64) (*operation, bool, error) {
	call.Nonce = ""
	content, err := contractJSON(call)
	if err != nil {
		return nil, false, errMalformed
	}
	digest := sha256.Sum256(content)
	h.mu.Lock()
	defer h.mu.Unlock()
	now := clock()
	if now-call.IssuedAt > RequestWindow {
		return nil, false, errExpired
	}
	if op := h.operations[call.Operation]; op != nil {
		if op.content != digest {
			return nil, false, errConflict
		}
		return op, false, nil
	}
	if len(h.operations) >= maxOperations {
		h.forget(now)
	}
	if len(h.operations) >= maxOperations {
		return nil, false, errBusy
	}
	if h.operations == nil {
		h.operations = map[string]*operation{}
	}
	op := &operation{content: digest, deadline: call.IssuedAt + RequestWindow, done: make(chan struct{})}
	h.operations[call.Operation] = op
	return op, true, nil
}

// finish keeps a bounded result for retries until the operation's deadline.
func (h *Handler) finish(op *operation, result *recorder, clock func() int64) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if result.complete() && h.resultBytes+len(result.body) > maxResultsBytes {
		h.forget(clock())
	}
	if result.complete() && h.resultBytes+len(result.body) <= maxResultsBytes {
		op.result = result
		h.resultBytes += len(result.body)
	}
	close(op.done)
}

// forget drops finished operations past their deadline; the caller holds mu.
func (h *Handler) forget(now int64) {
	maps.DeleteFunc(h.operations, func(_ string, op *operation) bool {
		select {
		case <-op.done:
		default:
			return false
		}
		if now <= op.deadline {
			return false
		}
		if op.result != nil {
			h.resultBytes -= len(op.result.body)
		}
		return true
	})
}

// recorder passes a response through and keeps a copy of at most maxResultBytes.
type recorder struct {
	http.ResponseWriter
	header   http.Header
	status   int
	body     []byte
	overflow bool
}

func (r *recorder) WriteHeader(status int) {
	if r.status == 0 {
		r.status = status
		r.header = r.ResponseWriter.Header().Clone()
	}
	r.ResponseWriter.WriteHeader(status)
}

func (r *recorder) Write(p []byte) (int, error) {
	if r.status == 0 {
		r.WriteHeader(http.StatusOK)
	}
	if r.overflow = r.overflow || len(r.body)+len(p) > maxResultBytes; r.overflow {
		r.body = nil
	} else {
		r.body = append(r.body, p...)
	}
	return r.ResponseWriter.Write(p)
}

func (r *recorder) complete() bool { return r.status != 0 && !r.overflow }

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

// OwnerKey is the measured form of an owner public key.
func OwnerKey(key ed25519.PublicKey) string {
	return "ed25519:" + base64.StdEncoding.EncodeToString(key)
}

// ParseOwnerKey reads a measured owner key. A small-order point would verify forged
// signatures for any message, so only canonical keys outside the torsion subgroup pass.
func ParseOwnerKey(value string) (ed25519.PublicKey, error) {
	encoded, ok := strings.CutPrefix(value, "ed25519:")
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if ok && err == nil && len(key) == ed25519.PublicKeySize && OwnerKey(key) == value {
		point, err := new(edwards25519.Point).SetBytes(key)
		if err == nil && bytes.Equal(point.Bytes(), key) && new(edwards25519.Point).MultByCofactor(point).Equal(edwards25519.NewIdentityPoint()) == 0 {
			return key, nil
		}
	}
	return nil, errors.New("owner public key must be ed25519: followed by the base64 of a valid Ed25519 public key")
}

// decodeB64U requires the canonical encoding; Go's decoder alone skips CR and LF.
// A negative size accepts any length.
func decodeB64U(text string, size int) ([]byte, error) {
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(text)
	if err != nil || base64.RawURLEncoding.EncodeToString(decoded) != text || (size >= 0 && len(decoded) != size) {
		return nil, errors.New("invalid base64url value")
	}
	return decoded, nil
}

func validID16(id string) bool {
	_, err := decodeB64U(id, 16)
	return err == nil
}

// contractJSON is the deterministic encoding: declared field order, no HTML escaping.
func contractJSON(v any) ([]byte, error) {
	var out bytes.Buffer
	encoder := json.NewEncoder(&out)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}

// decodeCanonical accepts only the deterministic encoding, rejecting duplicate,
// unknown, reordered or reformatted members.
func decodeCanonical(data []byte, v any) error {
	if err := json.Unmarshal(data, v); err != nil {
		return err
	}
	if canonical, err := contractJSON(v); err != nil || !bytes.Equal(canonical, data) {
		return errors.New("not in canonical form")
	}
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
