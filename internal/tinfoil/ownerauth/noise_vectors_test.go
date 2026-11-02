package ownerauth

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"flag"
	"math/rand/v2"
	"os"
	"testing"

	"github.com/flynn/noise"
)

const (
	nkVectorsPath   = "../../../ui/src/hosted/testdata/noise-nk-flynn.json"
	nkRandomVectors = 256
	nkMaxPrologue   = 64
	nkMaxPayload    = 95
	nkMaxTransport  = 11
	// nkCounterWalk sends over 256 messages each way, carrying each nonce counter into its second byte.
	nkCounterWalk = 600
)

var (
	updateVectors = flag.Bool("update", false, "rewrite "+nkVectorsPath)
	nkVectorSeed  [32]byte
	// nkBoundaries sit on either side of the 64-byte BLAKE2s and ChaCha20 blocks.
	nkBoundaries = []nkShape{{0, 0, 2}, {1, 1, 2}, {63, 63, 2}, {64, 64, 2}, {65, 65, 2}, {0, 0, nkCounterWalk}}
)

// nkShape sizes one vector: its prologue, each payload, and the messages after the handshake.
type nkShape struct{ prologue, payload, transport int }

type nkMessage struct {
	Payload    string `json:"payload"`
	Ciphertext string `json:"ciphertext"`
}

type nkVector struct {
	ProtocolName     string      `json:"protocol_name"`
	InitPrologue     string      `json:"init_prologue"`
	InitEphemeral    string      `json:"init_ephemeral"`
	InitRemoteStatic string      `json:"init_remote_static"`
	HandshakeHash    string      `json:"handshake_hash"`
	Messages         []nkMessage `json:"messages"`
}

// TestNoiseNKVectors regenerates the console's NK vectors from the flynn/noise the Monitor
// runs and requires the committed file to match; -update rewrites it.
func TestNoiseNKVectors(t *testing.T) {
	rng := rand.NewChaCha8(nkVectorSeed)
	draw := func(n int) []byte {
		b := make([]byte, n)
		rng.Read(b)
		return b
	}
	upTo := func(max int) int { return int(draw(1)[0]) % (max + 1) }
	var vectors []nkVector
	for _, shape := range nkBoundaries {
		vectors = append(vectors, nkVectorFor(t, shape, draw))
	}
	for range nkRandomVectors {
		shape := nkShape{upTo(nkMaxPrologue), upTo(nkMaxPayload), upTo(nkMaxTransport)}
		vectors = append(vectors, nkVectorFor(t, shape, draw))
	}
	got, err := json.MarshalIndent(map[string][]nkVector{"vectors": vectors}, "", "")
	if err != nil {
		t.Fatal(err)
	}
	got = append(got, '\n')
	if *updateVectors {
		if err := os.WriteFile(nkVectorsPath, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want, err := os.ReadFile(nkVectorsPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("%s is stale; rerun with -update", nkVectorsPath)
	}
}

func nkVectorFor(t *testing.T, shape nkShape, draw func(int) []byte) nkVector {
	t.Helper()
	server, err := suite.GenerateKeypair(bytes.NewReader(draw(noise.DH25519.DHLen())))
	if err != nil {
		t.Fatal(err)
	}
	ephemeral, prologue := draw(noise.DH25519.DHLen()), draw(shape.prologue)
	initiator, err := noise.NewHandshakeState(noise.Config{CipherSuite: suite, Pattern: noise.HandshakeNK, Initiator: true, Prologue: prologue, PeerStatic: server.Public, Random: bytes.NewReader(ephemeral)})
	if err != nil {
		t.Fatal(err)
	}
	responder, err := noise.NewHandshakeState(noise.Config{CipherSuite: suite, Pattern: noise.HandshakeNK, Prologue: prologue, StaticKeypair: server, Random: bytes.NewReader(draw(noise.DH25519.DHLen()))})
	if err != nil {
		t.Fatal(err)
	}
	v := nkVector{
		ProtocolName:     "Noise_" + noise.HandshakeNK.Name + "_" + string(suite.Name()),
		InitPrologue:     hex.EncodeToString(prologue),
		InitEphemeral:    hex.EncodeToString(ephemeral),
		InitRemoteStatic: hex.EncodeToString(server.Public),
	}
	relay := func(payload []byte, write, read func([]byte) ([]byte, error)) {
		ciphertext, err := write(payload)
		if err != nil {
			t.Fatal(err)
		}
		if got, err := read(ciphertext); err != nil || !bytes.Equal(got, payload) {
			t.Fatalf("flynn/noise did not round-trip a message: %v", err)
		}
		v.Messages = append(v.Messages, nkMessage{hex.EncodeToString(payload), hex.EncodeToString(ciphertext)})
	}
	var toServer, fromServer [2]*noise.CipherState
	relay(draw(shape.payload),
		func(p []byte) ([]byte, error) { m, _, _, err := initiator.WriteMessage(nil, p); return m, err },
		func(m []byte) ([]byte, error) { p, _, _, err := responder.ReadMessage(nil, m); return p, err })
	relay(draw(shape.payload),
		func(p []byte) (m []byte, err error) {
			m, toServer[1], fromServer[0], err = responder.WriteMessage(nil, p)
			return m, err
		},
		func(m []byte) (p []byte, err error) {
			p, toServer[0], fromServer[1], err = initiator.ReadMessage(nil, m)
			return p, err
		})
	if !bytes.Equal(initiator.ChannelBinding(), responder.ChannelBinding()) {
		t.Fatal("flynn/noise derived different handshake hashes")
	}
	v.HandshakeHash = hex.EncodeToString(initiator.ChannelBinding())
	for i := range shape.transport {
		pair := toServer
		if i%2 == 1 {
			pair = fromServer
		}
		relay(draw(shape.payload),
			func(p []byte) ([]byte, error) { return pair[0].Encrypt(nil, nil, p) },
			func(c []byte) ([]byte, error) { return pair[1].Decrypt(nil, nil, c) })
	}
	return v
}
