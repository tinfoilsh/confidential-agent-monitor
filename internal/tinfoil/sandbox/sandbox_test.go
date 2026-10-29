package sandbox

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"sync"
	"testing"

	"github.com/tinfoilsh/monitor/internal/frontdoor"
	"golang.org/x/crypto/ssh"
)

const (
	instanceA = "7c1d2e3f-4a5b-4c6d-8e7f-9a0b1c2d3e4f"
	instanceB = "11111111-2222-4333-8444-555555555555"
)

// seen is one request as the sandbox received it.
type seen struct {
	method, uri string
	header      http.Header
	body        []byte
}

// publish connects a sandbox boot that publishes its loopback 443 like monitor-reverse.
func publish(t *testing.T, forwards *frontdoor.Forwarder, instance string, handler http.HandlerFunc) *[]seen {
	_, private, _ := ed25519.GenerateKey(rand.Reader)
	hostKey, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	monitor, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer monitor.Close()
	config := &ssh.ServerConfig{NoClientAuth: true}
	config.AddHostKey(hostKey)
	go func() {
		server, err := monitor.Accept()
		if err != nil {
			return
		}
		conn, channels, requests, err := ssh.NewServerConn(server, config)
		if err == nil {
			forwards.ServePublisher(conn, channels, requests, frontdoor.Publisher{Name: "boot-" + instance, Alias: bootstrapRoute(BootstrapUser + instance)})
		}
	}()
	client, err := net.Dial("tcp", monitor.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	conn, channels, requests, err := ssh.NewClientConn(client, "monitor", &ssh.ClientConfig{User: BootstrapUser + instance, HostKeyCallback: ssh.InsecureIgnoreHostKey()})
	if err != nil {
		t.Fatal(err)
	}
	sandbox := ssh.NewClient(conn, channels, requests)
	t.Cleanup(func() { sandbox.Close() })
	listener, err := sandbox.Listen("tcp", "127.0.0.1:443")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var log []seen
	go http.Serve(listener, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		// Connection and Content-Length only frame the single request.
		header := r.Header.Clone()
		header.Del("Connection")
		header.Del("Content-Length")
		mu.Lock()
		log = append(log, seen{r.Method, r.RequestURI, header, body})
		mu.Unlock()
		handler(w, r)
	}))
	return &log
}

func random(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func ownerInput(instance string, body []byte) RelayInput {
	return RelayInput{InstanceID: instance, Target: "owner", Headers: &RelayHeaders{EncapsulatedKey: hex.EncodeToString(random(32)), ContentType: "application/octet-stream"},
		Body: base64.RawURLEncoding.EncodeToString(body)}
}

func TestRelayCarriesOnlyTheSelectedSandboxBytes(t *testing.T) {
	forwards := new(frontdoor.Forwarder)
	ciphertext, sealed := random(4096), random(1500)
	a := publish(t, forwards, instanceA, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=leak")
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(`{"format":"attestation"}`))
			return
		}
		w.Header().Set("Ehbp-Response-Nonce", "abcd")
		w.Header().Set("Content-Type", "application/problem+json")
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write(sealed)
	})
	b := publish(t, forwards, instanceB, func(w http.ResponseWriter, r *http.Request) {})

	nonce := hex.EncodeToString(random(32))
	reply, err := Relay(context.Background(), forwards, RelayInput{InstanceID: instanceA, Target: "attestation", Nonce: &nonce})
	if err != nil {
		t.Fatal(err)
	}
	if reply.Status != http.StatusOK || reply.Body != base64.RawURLEncoding.EncodeToString([]byte(`{"format":"attestation"}`)) || len(reply.Headers) != 1 || reply.Headers["Content-Type"] != "application/json" {
		t.Fatalf("attestation reply: %+v", reply)
	}
	in := ownerInput(instanceA, ciphertext)
	reply, err = Relay(context.Background(), forwards, in)
	if err != nil {
		t.Fatal(err)
	}
	// The workload's sealed response, including a key-configuration problem, passes through unchanged.
	if reply.Status != http.StatusUnprocessableEntity || reply.Body != base64.RawURLEncoding.EncodeToString(sealed) ||
		len(reply.Headers) != 2 || reply.Headers["Ehbp-Response-Nonce"] != "abcd" || reply.Headers["Content-Type"] != "application/problem+json" {
		t.Fatalf("owner reply: %+v", reply)
	}
	if len(*a) != 2 || len(*b) != 0 {
		t.Fatalf("requests reached A %d and B %d times", len(*a), len(*b))
	}
	attestation, owner := (*a)[0], (*a)[1]
	if attestation.method != http.MethodGet || attestation.uri != "/.well-known/tinfoil-attestation?nonce="+nonce || len(attestation.header) != 0 || len(attestation.body) != 0 {
		t.Fatalf("attestation request: %+v", attestation)
	}
	headers := slices.Sorted(func(yield func(string) bool) {
		for name := range owner.header {
			yield(name)
		}
	})
	if owner.method != http.MethodPost || owner.uri != "/owner/rpc" || !bytes.Equal(owner.body, ciphertext) ||
		!slices.Equal(headers, []string{"Content-Type", "Ehbp-Encapsulated-Key"}) ||
		owner.header.Get("Ehbp-Encapsulated-Key") != in.Headers.EncapsulatedKey || owner.header.Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("owner request: %s %s %v", owner.method, owner.uri, owner.header)
	}
}

func TestRelayBounds(t *testing.T) {
	forwards := new(frontdoor.Forwarder)
	var size int
	log := publish(t, forwards, instanceA, func(w http.ResponseWriter, r *http.Request) { w.Write(make([]byte, size)) })
	nonce := hex.EncodeToString(random(32))
	attest := RelayInput{InstanceID: instanceA, Target: "attestation", Nonce: &nonce}

	// Attestation keeps its own bound rather than the smaller owner response bound.
	for _, c := range []struct {
		in   RelayInput
		size int
		ok   bool
	}{
		{attest, maxRelayAttestationBytes, true},
		{attest, maxRelayAttestationBytes + 1, false},
		{ownerInput(instanceA, random(maxRelayBodyBytes)), maxRelayOwnerReplyBytes, true},
		{ownerInput(instanceA, random(1)), maxRelayOwnerReplyBytes + 1, false},
	} {
		size = c.size
		reply, err := Relay(context.Background(), forwards, c.in)
		if c.ok && (err != nil || len(reply.Body) != base64.RawURLEncoding.EncodedLen(c.size)) {
			t.Fatalf("%s reply of %d bytes: %v", c.in.Target, c.size, err)
		}
		var status interface{ HTTPStatus() int }
		if !c.ok && (!errors.As(err, &status) || status.HTTPStatus() != http.StatusBadGateway) {
			t.Fatalf("%s reply of %d bytes: %v", c.in.Target, c.size, err)
		}
	}
	reached := len(*log)

	upper := "7C1D2E3F-4A5B-4C6D-8E7F-9A0B1C2D3E4F"
	bad := hex.EncodeToString(random(31))
	padded := ownerInput(instanceA, random(10))
	padded.Body += "=="
	headed := attest
	headed.Headers = ownerInput(instanceA, nil).Headers
	withNonce := ownerInput(instanceA, random(10))
	withNonce.Nonce = &nonce
	newline := ownerInput(instanceA, random(10))
	newline.Headers.ContentType = "application/json\r\nX-Injected: 1"
	for name, in := range map[string]RelayInput{
		"oversized owner request": ownerInput(instanceA, random(maxRelayBodyBytes+1)),
		"empty owner request":     ownerInput(instanceA, nil),
		"uppercase instance":      {InstanceID: upper, Target: "attestation", Nonce: &nonce},
		"short nonce":             {InstanceID: instanceA, Target: "attestation", Nonce: &bad},
		"attestation headers":     headed,
		"attestation body":        {InstanceID: instanceA, Target: "attestation", Nonce: &nonce, Body: "AA"},
		"owner nonce":             withNonce,
		"owner without headers":   {InstanceID: instanceA, Target: "owner", Body: "AA"},
		"padded body":             padded,
		"header injection":        newline,
		"other target":            {InstanceID: instanceA, Target: "shell", Nonce: &nonce},
	} {
		if _, err := Relay(context.Background(), forwards, in); !errors.Is(err, errRelayInput) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if _, err := Relay(context.Background(), forwards, RelayInput{InstanceID: instanceB, Target: "attestation", Nonce: &nonce}); !errors.Is(err, ErrRouteUnavailable) {
		t.Fatalf("unpublished sandbox: %v", err)
	}
	if len(*log) != reached {
		t.Fatalf("rejected input reached the sandbox")
	}
}
