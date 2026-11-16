package perimeter

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"time"

	"filippo.io/edwards25519"
	"github.com/coder/websocket"
	"github.com/flynn/noise"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	sessionContext = "tinfoil owner session v1\x00"
	// sessionTimeout bounds the handshake and hello, so unauthenticated sockets do not linger.
	sessionTimeout = 10 * time.Second
	maxCalls       = 4
	// A frame is a flag byte, then data filling the rest of one Noise message.
	frameBytes = noise.MaxMsgLen - 1 - chacha20poly1305.Overhead
	frameMore  = 0
	frameLast  = 1
)

var (
	suite        = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
	errMalformed = errors.New("malformed")
	errSignature = errors.New("invalid_signature")
)

// ownerSession is one authenticated owner session over a WebSocket.
type ownerSession struct {
	Conn       *websocket.Conn
	send, recv *noise.CipherState
	mu         sync.Mutex
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

// LoadSessionKey reads the CVM's attested X25519 key, PKCS#8 encoded as the CVM writes it.
func LoadSessionKey(path string) (noise.DHKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return noise.DHKey{}, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return noise.DHKey{}, errors.New("owner-session key is not a PEM private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	private, ok := parsed.(*ecdh.PrivateKey)
	if err != nil || !ok || private.Curve() != ecdh.X25519() {
		return noise.DHKey{}, errors.New("owner-session key must be an X25519 private key")
	}
	return noise.DHKey{Private: private.Bytes(), Public: private.PublicKey().Bytes()}, nil
}

// ownerKey is the measured form of an owner public key.
func ownerKey(key ed25519.PublicKey) string {
	return "ed25519:" + base64.StdEncoding.EncodeToString(key)
}

// ParseOwnerKey reads a measured owner key. A small-order point would verify forged
// signatures for any message, so only canonical keys outside the torsion subgroup pass.
func ParseOwnerKey(value string) (ed25519.PublicKey, error) {
	encoded, ok := strings.CutPrefix(value, "ed25519:")
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if ok && err == nil && len(key) == ed25519.PublicKeySize && ownerKey(key) == value {
		point, err := new(edwards25519.Point).SetBytes(key)
		if err == nil && bytes.Equal(point.Bytes(), key) && new(edwards25519.Point).MultByCofactor(point).Equal(edwards25519.NewIdentityPoint()) == 0 {
			return key, nil
		}
	}
	return nil, errors.New("owner public key must be ed25519: followed by the base64 of a valid Ed25519 public key")
}

// sessionMode serves one accepted session; hello is the owner's signed first message.
type sessionMode func(ctx context.Context, c *ownerSession, hello json.RawMessage)

type ownerSocket struct {
	Key        ed25519.PublicKey
	SessionKey noise.DHKey
	Protocol   string
	Modes      map[string]sessionMode // by the hello's "open"
}

func (s *ownerSocket) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var hello json.RawMessage
	c, err := acceptOwner(w, r, s.SessionKey, s.Protocol, s.Key, &hello)
	if err != nil {
		return
	}
	var open struct {
		Open string `json:"open"`
	}
	if json.Unmarshal(hello, &open) != nil || s.Modes[open.Open] == nil {
		c.Conn.Close(websocket.StatusPolicyViolation, errMalformed.Error())
		return
	}
	s.Modes[open.Open](r.Context(), c, hello)
}

func rpcSession(limit int, serve func(context.Context, ownerCall) ownerReply) sessionMode {
	return func(ctx context.Context, c *ownerSession, _ json.RawMessage) { c.ServeRPC(ctx, limit, serve) }
}

// callHandler answers each call with h, as a request carrying the call's method, path and body.
func callHandler(h http.Handler) func(context.Context, ownerCall) ownerReply {
	return func(ctx context.Context, call ownerCall) ownerReply {
		r, err := http.NewRequestWithContext(ctx, call.Method, call.Path, bytes.NewReader(call.Body))
		if err != nil {
			return ownerReply{Status: http.StatusBadRequest, Body: []byte(errMalformed.Error())}
		}
		if call.Method == http.MethodPost {
			r.Header.Set("Content-Type", "application/json")
		}
		recorder := httptest.NewRecorder()
		h.ServeHTTP(recorder, r)
		return ownerReply{Status: recorder.Code, Body: recorder.Body.Bytes()}
	}
}

// acceptOwner upgrades r and runs an NK handshake bound to prologue. The owner's first message
// signs the handshake hash with its measured key and is decoded into hello.
func acceptOwner(w http.ResponseWriter, r *http.Request, key noise.DHKey, prologue string, owner ed25519.PublicKey, hello any) (*ownerSession, error) {
	conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{InsecureSkipVerify: true})
	if err != nil {
		return nil, err
	}
	conn.SetReadLimit(noise.MaxMsgLen)
	ctx, cancel := context.WithTimeout(r.Context(), sessionTimeout)
	defer cancel()
	hs, err := noise.NewHandshakeState(noise.Config{CipherSuite: suite, Pattern: noise.HandshakeNK, Prologue: []byte(prologue), StaticKeypair: key})
	c := &ownerSession{Conn: conn}
	var message []byte
	if err == nil {
		_, message, err = conn.Read(ctx)
	}
	if err == nil {
		_, _, _, err = hs.ReadMessage(nil, message)
	}
	if err == nil {
		message, c.recv, c.send, err = hs.WriteMessage(nil, nil)
	}
	if err == nil {
		err = conn.Write(ctx, websocket.MessageBinary, message)
	}
	var signed struct {
		Signature []byte `json:"signature"`
	}
	if err == nil {
		message, err = c.Read(ctx, frameBytes)
	}
	if err != nil || json.Unmarshal(message, &signed) != nil || json.Unmarshal(message, hello) != nil {
		err = errMalformed
	} else if !ed25519.Verify(owner, append([]byte(sessionContext), hs.ChannelBinding()...), signed.Signature) {
		err = errSignature
	}
	if err != nil {
		conn.Close(websocket.StatusPolicyViolation, err.Error())
		return nil, err
	}
	return c, nil
}

// Read returns the next whole message, refusing one longer than limit.
func (c *ownerSession) Read(ctx context.Context, limit int) ([]byte, error) {
	var message []byte
	for {
		_, frame, err := c.Conn.Read(ctx)
		if err == nil {
			frame, err = c.recv.Decrypt(nil, nil, frame)
		}
		if err == nil && (len(frame) == 0 || frame[0] > frameLast || len(message)+len(frame)-1 > limit) {
			err = errMalformed
		}
		if err != nil {
			return nil, err
		}
		message = append(message, frame[1:]...)
		if frame[0] == frameLast {
			return message, nil
		}
	}
}

// Write sends message as frames no other message interleaves with.
func (c *ownerSession) Write(ctx context.Context, message []byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for {
		n := min(len(message), frameBytes)
		flag := byte(frameMore)
		if n == len(message) {
			flag = frameLast
		}
		frame, err := c.send.Encrypt(nil, nil, append([]byte{flag}, message[:n]...))
		if err == nil {
			err = c.Conn.Write(ctx, websocket.MessageBinary, frame)
		}
		if err != nil || flag == frameLast {
			return err
		}
		message = message[n:]
	}
}

// ServeRPC answers calls of at most limit bytes, a few at once and in any order, until the
// socket ends.
func (c *ownerSession) ServeRPC(ctx context.Context, limit int, serve func(context.Context, ownerCall) ownerReply) {
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
