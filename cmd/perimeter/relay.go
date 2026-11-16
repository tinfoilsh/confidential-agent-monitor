package main

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"time"

	"github.com/coder/websocket"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/tinfoil"
)

const (
	sandboxRelayRoute = "POST /sandboxes/relay"
	maxRelayBytes     = 1 << 20

	maxRelayAttestationBytes = 32 << 20
	relayHopTimeout          = 30 * time.Second
	relayIdleTimeout         = time.Minute
	relayIdleConns           = 4
	sandboxAttestationURL    = "http://sandbox" + tinfoil.AttestationPath + "?nonce="
	sandboxOwnerPath         = "/owner/ws"
	bootstrapPort            = "443"
)

var (
	instancePattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hex32Pattern    = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	errRelayInput   = errors.New("a relay needs a bunker instance_id and an attestation nonce")
)

type sandboxes struct{ relays http.RoundTripper }

// newSandboxes keeps each bunker's bootstrap connections open between relayed
// requests, so a request does not wait for a new forwarded channel.
func newSandboxes(f *tinfoil.Forwarder) *sandboxes {
	return &sandboxes{&http.Transport{DisableCompression: true, MaxIdleConnsPerHost: relayIdleConns, IdleConnTimeout: relayIdleTimeout, DialContext: f.DialContext}}
}

// relayInput selects a bunker boot by its measured instance.
type relayInput struct {
	InstanceID string `json:"instance_id"`
	Nonce      string `json:"nonce"`
}

type relayReply struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
}

// relay fetches one attestation over a bunker's bootstrap route and returns the response
// bytes unchanged. That route is unverified and grants no agent access.
func (s *sandboxes) relay(ctx context.Context, in relayInput) (relayReply, error) {
	if !instancePattern.MatchString(in.InstanceID) || !hex32Pattern.MatchString(in.Nonce) {
		return relayReply{}, errRelayInput
	}
	request, err := http.NewRequest(http.MethodGet, sandboxAttestationURL+in.Nonce, nil)
	if err != nil {
		return relayReply{}, err
	}
	// An empty User-Agent is omitted, so the bunker receives no client headers.
	request.Header = http.Header{"User-Agent": {""}}
	// Connections are pooled per route; the bunker still sees its own Host.
	request.URL.Host = net.JoinHostPort(tinfoil.BootstrapRoute(in.InstanceID), bootstrapPort)
	ctx, cancel := context.WithTimeout(ctx, relayHopTimeout)
	defer cancel()
	response, err := s.relays.RoundTrip(request.WithContext(ctx))
	if err != nil {
		return relayReply{}, responseError{"bunker relay: " + err.Error(), http.StatusBadGateway}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxRelayAttestationBytes+1))
	if err == nil && len(body) > maxRelayAttestationBytes {
		err = errors.New("the response is too large")
	}
	if err != nil {
		return relayReply{}, responseError{"bunker relay: " + err.Error(), http.StatusBadGateway}
	}
	return relayReply{Status: response.StatusCode, Body: base64.RawURLEncoding.EncodeToString(body)}, nil
}

// dialOwner opens a bunker boot's owner socket over its bootstrap route.
func (s *sandboxes) dialOwner(ctx context.Context, instance string) (*websocket.Conn, error) {
	if !instancePattern.MatchString(instance) {
		return nil, errRelayInput
	}
	client := &http.Client{Transport: s.relays, Timeout: relayHopTimeout}
	conn, _, err := websocket.Dial(ctx, "ws://"+net.JoinHostPort(tinfoil.BootstrapRoute(instance), bootstrapPort)+sandboxOwnerPath, &websocket.DialOptions{HTTPClient: client})
	return conn, err
}

// responseError carries the HTTP status the owner API answers a failed relay with.
type responseError struct {
	message string
	status  int
}

func (e responseError) Error() string   { return e.message }
func (e responseError) HTTPStatus() int { return e.status }
