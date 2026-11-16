package sandbox

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"strconv"
	"time"

	"github.com/coder/websocket"
)

const (
	RelayRoute    = "POST /sandboxes/relay"
	MaxRelayBytes = 1 << 20

	maxRelayAttestationBytes = 32 << 20
	relayHopTimeout          = 30 * time.Second
	relayIdleTimeout         = time.Minute
	relayIdleConns           = 4
	AttestationPath          = "/.well-known/tinfoil-attestation"
	sandboxAttestationURL    = "http://sandbox" + AttestationPath + "?nonce="
	sandboxOwnerPath         = "/owner/ws"
)

var (
	instancePattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hex32Pattern    = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	errRelayInput   = errors.New("a relay needs a bunker instance_id and an attestation nonce")
)

type badGateway struct{ error }

func (badGateway) HTTPStatus() int { return http.StatusBadGateway }

func (f *Forwarder) Transport() *http.Transport {
	return &http.Transport{DisableCompression: true, MaxIdleConnsPerHost: relayIdleConns, IdleConnTimeout: relayIdleTimeout, DialContext: f.DialContext}
}

type RelayInput struct {
	InstanceID string `json:"instance_id"`
	Nonce      string `json:"nonce"`
}

type relayReply struct {
	Status int    `json:"status"`
	Body   string `json:"body"`
}

func Relay(ctx context.Context, relays http.RoundTripper, in RelayInput) (relayReply, error) {
	if !instancePattern.MatchString(in.InstanceID) || !hex32Pattern.MatchString(in.Nonce) {
		return relayReply{}, errRelayInput
	}
	request, err := http.NewRequest(http.MethodGet, sandboxAttestationURL+in.Nonce, nil)
	if err != nil {
		return relayReply{}, err
	}
	request.Header = http.Header{"User-Agent": {""}}
	request.URL.Host = net.JoinHostPort(bootstrapRoute(in.InstanceID), strconv.Itoa(aliasPort))
	ctx, cancel := context.WithTimeout(ctx, relayHopTimeout)
	defer cancel()
	response, err := relays.RoundTrip(request.WithContext(ctx))
	if err != nil {
		return relayReply{}, badGateway{errors.New("bunker relay: " + err.Error())}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, maxRelayAttestationBytes+1))
	if err == nil && len(body) > maxRelayAttestationBytes {
		err = errors.New("the response is too large")
	}
	if err != nil {
		return relayReply{}, badGateway{errors.New("bunker relay: " + err.Error())}
	}
	return relayReply{Status: response.StatusCode, Body: base64.RawURLEncoding.EncodeToString(body)}, nil
}

func DialOwner(ctx context.Context, relays http.RoundTripper, instance string) (*websocket.Conn, error) {
	if !instancePattern.MatchString(instance) {
		return nil, errRelayInput
	}
	client := &http.Client{Transport: relays, Timeout: relayHopTimeout}
	conn, _, err := websocket.Dial(ctx, "ws://"+net.JoinHostPort(bootstrapRoute(instance), strconv.Itoa(aliasPort))+sandboxOwnerPath, &websocket.DialOptions{HTTPClient: client})
	return conn, err
}
