package noisetransport

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
	FrameBytes   = noise.MaxMsgLen - 1 - chacha20poly1305.Overhead
	frameMore    = 0
	frameLast    = 1
	signerPrefix = "ed25519:"
)

var (
	suite        = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
	errMalformed = errors.New("malformed")
	errSignature = errors.New("invalid_signature")
)

type Session struct {
	Conn       *websocket.Conn
	send, recv *noise.CipherState
	mu         sync.Mutex
}

type Config struct {
	Key      noise.DHKey
	Prologue string
	Timeout  time.Duration
	Accept   *websocket.AcceptOptions
}

type Call struct {
	ID         uint64 `json:"id"`
	Method     string `json:"method"`
	Path       string `json:"path"`
	Generation uint64 `json:"generation"`
	Body       []byte `json:"body"`
}

type Reply struct {
	ID     uint64 `json:"id"`
	Status int    `json:"status"`
	Body   []byte `json:"body"`
}

func LoadKey(path string) (noise.DHKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return noise.DHKey{}, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return noise.DHKey{}, errors.New("session key is not a PEM private key")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	private, ok := parsed.(*ecdh.PrivateKey)
	if err != nil || !ok || private.Curve() != ecdh.X25519() {
		return noise.DHKey{}, errors.New("session key must be an X25519 private key")
	}
	return noise.DHKey{Private: private.Bytes(), Public: private.PublicKey().Bytes()}, nil
}

func ParseSigner(value string) (ed25519.PublicKey, bool) {
	encoded, ok := strings.CutPrefix(value, signerPrefix)
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if !ok || err != nil || len(key) != ed25519.PublicKeySize || signerPrefix+base64.StdEncoding.EncodeToString(key) != value {
		return nil, false
	}
	point, err := new(edwards25519.Point).SetBytes(key)
	if err != nil || !bytes.Equal(point.Bytes(), key) || new(edwards25519.Point).MultByCofactor(point).Equal(edwards25519.NewIdentityPoint()) == 1 {
		return nil, false
	}
	return key, true
}

func Signed(signer ed25519.PublicKey, context string) func(channelBinding, first []byte) error {
	return func(binding, first []byte) error {
		var signed struct {
			Signature []byte `json:"signature"`
		}
		if json.Unmarshal(first, &signed) != nil {
			return errMalformed
		}
		if !ed25519.Verify(signer, append([]byte(context), binding...), signed.Signature) {
			return errSignature
		}
		return nil
	}
}

func Accept(w http.ResponseWriter, r *http.Request, c Config, verify func(channelBinding, first []byte) error) (*Session, []byte, error) {
	conn, err := websocket.Accept(w, r, c.Accept)
	if err != nil {
		return nil, nil, err
	}
	conn.SetReadLimit(noise.MaxMsgLen)
	ctx, cancel := context.WithTimeout(r.Context(), c.Timeout)
	defer cancel()
	hs, err := noise.NewHandshakeState(noise.Config{CipherSuite: suite, Pattern: noise.HandshakeNK, Prologue: []byte(c.Prologue), StaticKeypair: c.Key})
	s := &Session{Conn: conn}
	var message []byte
	if err == nil {
		_, message, err = conn.Read(ctx)
	}
	if err == nil {
		_, _, _, err = hs.ReadMessage(nil, message)
	}
	if err == nil {
		message, s.recv, s.send, err = hs.WriteMessage(nil, nil)
	}
	if err == nil {
		err = conn.Write(ctx, websocket.MessageBinary, message)
	}
	if err == nil {
		message, err = s.Read(ctx, FrameBytes)
	}
	if err != nil {
		err = errMalformed
	} else {
		err = verify(hs.ChannelBinding(), message)
	}
	if err != nil {
		conn.Close(websocket.StatusPolicyViolation, err.Error())
		return nil, nil, err
	}
	return s, message, nil
}

func (s *Session) Read(ctx context.Context, limit int) ([]byte, error) {
	var message []byte
	for {
		_, frame, err := s.Conn.Read(ctx)
		if err == nil {
			frame, err = s.recv.Decrypt(nil, nil, frame)
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

func (s *Session) Write(ctx context.Context, message []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for {
		n := min(len(message), FrameBytes)
		flag := byte(frameMore)
		if n == len(message) {
			flag = frameLast
		}
		frame, err := s.send.Encrypt(nil, nil, append([]byte{flag}, message[:n]...))
		if err == nil {
			err = s.Conn.Write(ctx, websocket.MessageBinary, frame)
		}
		if err != nil || flag == frameLast {
			return err
		}
		message = message[n:]
	}
}

func (s *Session) ServeRPC(ctx context.Context, limit, concurrent int, serve func(context.Context, Call) Reply) {
	running := make(chan struct{}, concurrent)
	for {
		var call Call
		message, err := s.Read(ctx, limit)
		if err == nil {
			err = json.Unmarshal(message, &call)
		}
		if err != nil {
			s.Conn.Close(websocket.StatusPolicyViolation, errMalformed.Error())
			return
		}
		running <- struct{}{}
		go func() {
			defer func() { <-running }()
			reply := serve(ctx, call)
			reply.ID = call.ID
			out, _ := json.Marshal(reply)
			s.Write(ctx, out)
		}()
	}
}
