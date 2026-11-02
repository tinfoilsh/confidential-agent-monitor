// Package sandbox provides sandbox routes and the owner's relay to sandbox attestation and owner sockets.
package sandbox

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
	"github.com/tinfoilsh/monitor/internal/frontdoor"
)

const (
	// BootstrapUser prefixes the SSH user a sandbox boot publishes its bootstrap route as.
	BootstrapUser = "sandbox-v2:"
	// MaxRelayBytes bounds a relay request.
	MaxRelayBytes = 1 << 20

	maxRelayAttestationBytes = 32 << 20
	relayHopTimeout          = 30 * time.Second
	relayIdleTimeout         = time.Minute
	relayIdleConns           = 4
	sandboxAttestationURL    = "http://sandbox/.well-known/tinfoil-attestation?nonce="
	sandboxOwnerPath         = "/owner/ws"
)

var (
	instancePattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hex32Pattern    = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	errRelayInput   = errors.New("a relay needs a sandbox instance_id and an attestation nonce")
)

// RelayInput selects a sandbox boot by its measured instance.
type RelayInput struct {
	InstanceID string `json:"instance_id"`
	Nonce      string `json:"nonce"`
}

type RelayReply struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
}

// Relay fetches one attestation over a sandbox's bootstrap route and returns the response
// bytes unchanged. That route is unverified and grants no agent access.
func Relay(ctx context.Context, relays http.RoundTripper, in RelayInput) (RelayReply, error) {
	if !instancePattern.MatchString(in.InstanceID) || !hex32Pattern.MatchString(in.Nonce) {
		return RelayReply{}, errRelayInput
	}
	request, err := http.NewRequest(http.MethodGet, sandboxAttestationURL+in.Nonce, nil)
	if err != nil {
		return RelayReply{}, err
	}
	// An empty User-Agent is omitted, so the sandbox receives no client headers.
	request.Header = http.Header{"User-Agent": {""}}
	// Connections are pooled per route; the sandbox still sees its own Host.
	request.URL.Host = bootstrapRoute(BootstrapUser + in.InstanceID)
	ctx, cancel := context.WithTimeout(ctx, relayHopTimeout)
	defer cancel()
	response, err := relays.RoundTrip(request.WithContext(ctx))
	if err != nil {
		return RelayReply{}, responseError{"sandbox relay: " + err.Error(), http.StatusBadGateway}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxRelayAttestationBytes+1))
	if err == nil && len(body) > maxRelayAttestationBytes {
		err = errors.New("the response is too large")
	}
	if err != nil {
		return RelayReply{}, responseError{"sandbox relay: " + err.Error(), http.StatusBadGateway}
	}
	return RelayReply{Status: response.StatusCode, Body: base64.RawURLEncoding.EncodeToString(body)}, nil
}

// DialOwner opens a sandbox boot's owner socket over its bootstrap route.
func DialOwner(ctx context.Context, relays http.RoundTripper, instance string) (*websocket.Conn, error) {
	if !instancePattern.MatchString(instance) {
		return nil, errRelayInput
	}
	client := &http.Client{Transport: relays, Timeout: relayHopTimeout}
	conn, _, err := websocket.Dial(ctx, "ws://"+bootstrapRoute(BootstrapUser+instance)+sandboxOwnerPath, &websocket.DialOptions{HTTPClient: client})
	return conn, err
}

// Relays keeps each sandbox's bootstrap connections open between relayed requests, so a
// request does not wait for a new forwarded channel.
func Relays(forwards *frontdoor.Forwarder) http.RoundTripper {
	return &http.Transport{DisableCompression: true, MaxIdleConnsPerHost: relayIdleConns, IdleConnTimeout: relayIdleTimeout,
		DialContext: func(_ context.Context, _, address string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			return Dial(forwards, host, 443)
		}}
}
