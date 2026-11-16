// Package noisetransport runs Noise NK sessions over WebSockets, as whole messages split into frames.
package noisetransport

import (
	"context"
	"crypto/ecdh"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/flynn/noise"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	// FrameBytes is the most data one frame carries: a flag byte, then data filling the rest of one Noise message.
	FrameBytes = noise.MaxMsgLen - 1 - chacha20poly1305.Overhead
	frameMore  = 0
	frameLast  = 1
)

var (
	suite        = noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s)
	errMalformed = errors.New("malformed")
)

// Session is one accepted Noise session over a WebSocket.
type Session struct {
	Conn       *websocket.Conn
	send, recv *noise.CipherState
	mu         sync.Mutex
}

// Config is the responder's static key, the prologue both sides bind, the time allowed
// for the handshake and the first message, and how the WebSocket upgrade is accepted.
type Config struct {
	Key      noise.DHKey
	Prologue string
	Timeout  time.Duration
	Accept   *websocket.AcceptOptions
}

// LoadKey reads an X25519 key, PKCS#8 encoded in PEM.
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

// Accept upgrades r and runs an NK handshake. verify authenticates the initiator's first
// message, of at most one frame, against the handshake's channel binding; its error closes the socket.
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

// Read returns the next whole message, refusing one longer than limit.
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

// Write sends message as frames no other message interleaves with.
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
