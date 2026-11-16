package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/flynn/noise"
	"golang.org/x/crypto/ssh"
)

func TestOwnerSSHAndNoiseSessions(t *testing.T) {
	s, _, _ := testState(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dh, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	apiListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		sshListener.Close()
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	done := make(chan error, 1)
	go func() {
		done <- s.serve(ctx, sshListener, apiListener, &owner{key: public, sessionKey: dh}, http.NotFoundHandler())
	}()
	t.Cleanup(func() {
		cancel()
		sshListener.Close()
		apiListener.Close()
		select {
		case <-done:
		case <-time.After(time.Second):
			t.Error("owner server did not stop")
		}
	})

	t.Run("SSH acknowledgement", func(t *testing.T) {
		signer, err := ssh.NewSignerFromKey(private)
		if err != nil {
			t.Fatal(err)
		}
		client, err := ssh.Dial("tcp", sshListener.Addr().String(), &ssh.ClientConfig{User: "owner", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)}, HostKeyCallback: ssh.FixedHostKey(s.hostKey().PublicKey()), Timeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		stop := context.AfterFunc(ctx, func() { client.Close() })
		defer stop()
		generation, _ := s.generation()
		options := sshOptions{Host: ownerHost, Token: base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), Generation: generation}
		stale := options
		stale.Generation++
		if channel, _, err := client.OpenChannel(sshChannel, ssh.Marshal(stale)); err == nil {
			channel.Close()
			t.Fatal("SSH accepted a channel requiring a future generation")
		}
		for _, accept := range []bool{true, false} {
			channel, requests, err := client.OpenChannel(sshChannel, ssh.Marshal(options))
			if err != nil {
				t.Fatal(err)
			}
			var acknowledged atomic.Uint64
			go func() {
				for r := range requests {
					var received sshGeneration
					valid := r.Type == sshGenerationRequest && ssh.Unmarshal(r.Payload, &received) == nil
					if valid {
						acknowledged.Store(received.Generation)
					}
					r.Reply(valid && accept, nil)
				}
			}()
			req, _ := http.NewRequestWithContext(ctx, "GET", "http://"+ownerHost+"/api/", nil)
			req.Header.Set(sessionHeader, options.Token)
			req.Close = true
			if err := req.Write(channel); err != nil {
				t.Fatal(err)
			}
			response, err := http.ReadResponse(bufio.NewReader(channel), req)
			if err != nil {
				t.Fatal(err)
			}
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			channel.Close()
			if (response.StatusCode == http.StatusOK) != accept || acknowledged.Load() != generation {
				t.Fatalf("generation acknowledgement: accepted=%v status=%d generation=%d", accept, response.StatusCode, acknowledged.Load())
			}
		}
	})

	t.Run("Noise signature and RPC", func(t *testing.T) {
		for _, validSignature := range []bool{false, true} {
			conn, _, err := websocket.Dial(ctx, "ws://"+apiListener.Addr().String()+"/owner/ws", nil)
			if err != nil {
				t.Fatal(err)
			}
			defer conn.CloseNow()
			hs, err := noise.NewHandshakeState(noise.Config{CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s), Pattern: noise.HandshakeNK, Initiator: true, PeerStatic: dh.Public, Prologue: []byte(ownerProtocol)})
			if err != nil {
				t.Fatal(err)
			}
			message, _, _, err := hs.WriteMessage(nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			if err := conn.Write(ctx, websocket.MessageBinary, message); err != nil {
				t.Fatal(err)
			}
			_, message, err = conn.Read(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, send, recv, err := hs.ReadMessage(nil, message)
			if err != nil {
				t.Fatal(err)
			}
			write := func(value any) {
				t.Helper()
				raw, err := json.Marshal(value)
				if err == nil {
					raw, err = send.Encrypt(nil, nil, append([]byte{1}, raw...))
				}
				if err == nil {
					err = conn.Write(ctx, websocket.MessageBinary, raw)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			signature := ed25519.Sign(private, append([]byte(sessionContext), hs.ChannelBinding()...))
			if !validSignature {
				signature[0] ^= 1
			}
			write(map[string]any{"open": rpcMode, "signature": signature})
			if !validSignature {
				if _, _, err := conn.Read(ctx); err == nil {
					t.Fatal("Noise accepted an invalid owner signature")
				}
				continue
			}
			generation, _ := s.generation()
			for _, minimum := range []uint64{generation, generation + 1} {
				write(ownerCall{ID: minimum, Method: "GET", Path: "/", Generation: minimum})
				var body []byte
				for {
					_, encrypted, err := conn.Read(ctx)
					if err != nil {
						t.Fatal(err)
					}
					frame, err := recv.Decrypt(nil, nil, encrypted)
					if err != nil || len(frame) == 0 {
						t.Fatalf("invalid Noise reply: %v", err)
					}
					body = append(body, frame[1:]...)
					if frame[0] == 1 {
						break
					}
				}
				var reply ownerReply
				if err := json.Unmarshal(body, &reply); err != nil {
					t.Fatal(err)
				}
				want := http.StatusOK
				if minimum != generation {
					want = http.StatusConflict
				}
				if reply.ID != minimum || reply.Status != want {
					t.Fatalf("Noise reply: id=%d status=%d; want id=%d status=%d", reply.ID, reply.Status, minimum, want)
				}
			}
		}
	})
}
