// Package sandbox provides sandbox routes and the owner's relay to sandbox attestation and owner APIs.
package sandbox

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/tinfoilsh/monitor/internal/frontdoor"
)

const (
	// BootstrapUser prefixes the SSH user a sandbox boot publishes its bootstrap route as.
	BootstrapUser = "sandbox-v2:"
	// MaxRelayBytes bounds a relay request, including its base64url body.
	MaxRelayBytes = 1 << 20

	maxRelayBodyBytes        = 512 << 10
	maxRelayOwnerReplyBytes  = 2 << 20
	maxRelayAttestationBytes = 32 << 20
	maxRelayContentType      = 256
	relayHopTimeout          = 30 * time.Second
	sandboxAttestationURL    = "http://sandbox/.well-known/tinfoil-attestation?nonce="
	sandboxOwnerURL          = "http://sandbox/owner/rpc"
)

var (
	instancePattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	hex32Pattern    = regexp.MustCompile(`^[0-9a-fA-F]{64}$`)
	errRelayInput   = errors.New("a relay needs a sandbox instance_id and either an attestation nonce or an EHBP owner request")
)

// RelayInput selects a sandbox boot by its measured instance and carries bytes Monitor cannot read.
type RelayInput struct {
	InstanceID string        `json:"instance_id"`
	Target     string        `json:"target"`
	Nonce      *string       `json:"nonce"`
	Headers    *RelayHeaders `json:"headers"`
	Body       string        `json:"body"`
}

// RelayHeaders are the only request headers an owner request carries to the sandbox.
type RelayHeaders struct {
	EncapsulatedKey string `json:"Ehbp-Encapsulated-Key"`
	ContentType     string `json:"Content-Type"`
}

type RelayReply struct {
	Status  int               `json:"status"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
}

// Relay sends one attestation or EHBP owner request over a sandbox's bootstrap route and
// returns the response bytes unchanged. That route is unverified and grants no agent access.
func Relay(ctx context.Context, forwards *frontdoor.Forwarder, in RelayInput) (RelayReply, error) {
	request, limit, err := in.request()
	if err != nil {
		return RelayReply{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, relayHopTimeout)
	defer cancel()
	conn, err := Dial(forwards, bootstrapRoute(BootstrapUser+in.InstanceID), 443)
	if err != nil {
		return RelayReply{}, err
	}
	defer conn.Close()
	// The hop deadline also covers the dial, which cannot be canceled itself.
	defer context.AfterFunc(ctx, func() { conn.Close() })()
	transport := &http.Transport{DisableKeepAlives: true, DisableCompression: true, DialContext: func(context.Context, string, string) (net.Conn, error) {
		return conn, nil
	}}
	response, err := transport.RoundTrip(request.WithContext(ctx))
	if err != nil {
		return RelayReply{}, responseError{"sandbox relay: " + err.Error(), http.StatusBadGateway}
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	if err == nil && int64(len(body)) > limit {
		err = errors.New("the response is too large")
	}
	if err != nil {
		return RelayReply{}, responseError{"sandbox relay: " + err.Error(), http.StatusBadGateway}
	}
	reply := RelayReply{Status: response.StatusCode, Headers: map[string]string{}, Body: base64.RawURLEncoding.EncodeToString(body)}
	for _, name := range []string{"Content-Type", "Ehbp-Response-Nonce"} {
		if value := response.Header.Get(name); value != "" {
			reply.Headers[name] = value
		}
	}
	return reply, nil
}

// request builds one of the two requests a relay may send, and the response bound for it.
func (in RelayInput) request() (*http.Request, int64, error) {
	if !instancePattern.MatchString(in.InstanceID) {
		return nil, 0, errRelayInput
	}
	var request *http.Request
	var limit int64
	var err error
	switch {
	case in.Target == "attestation" && in.Nonce != nil && hex32Pattern.MatchString(*in.Nonce) && in.Headers == nil && in.Body == "":
		request, err = http.NewRequest(http.MethodGet, sandboxAttestationURL+*in.Nonce, nil)
		limit = maxRelayAttestationBytes
	case in.Target == "owner" && in.Nonce == nil && in.Headers != nil && hex32Pattern.MatchString(in.Headers.EncapsulatedKey) &&
		in.Headers.ContentType != "" && len(in.Headers.ContentType) <= maxRelayContentType &&
		strings.IndexFunc(in.Headers.ContentType, func(r rune) bool { return r < 0x20 || r > 0x7e }) < 0:
		body, decodeErr := base64.RawURLEncoding.Strict().DecodeString(in.Body)
		if decodeErr != nil || base64.RawURLEncoding.EncodeToString(body) != in.Body || len(body) == 0 || len(body) > maxRelayBodyBytes {
			return nil, 0, errRelayInput
		}
		request, err = http.NewRequest(http.MethodPost, sandboxOwnerURL, bytes.NewReader(body))
		limit = maxRelayOwnerReplyBytes
	default:
		return nil, 0, errRelayInput
	}
	if err != nil {
		return nil, 0, err
	}
	// An empty User-Agent is omitted, so the sandbox receives only these headers.
	request.Header = http.Header{"User-Agent": {""}}
	if in.Headers != nil {
		request.Header.Set("Ehbp-Encapsulated-Key", in.Headers.EncapsulatedKey)
		request.Header.Set("Content-Type", in.Headers.ContentType)
	}
	return request, limit, nil
}
