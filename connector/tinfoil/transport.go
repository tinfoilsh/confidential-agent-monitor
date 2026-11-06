package tinfoil

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/connector/web"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
)

var errTinfoilKey = errors.New("Tinfoil TLS key differs from its attestation")

// The SDK's Verifier is offline. Monitor owns fetching and the TLS pool because
// both must use Env's guarded dialer (the host broker in an isolated worker).
// No SDK global HTTP client or direct network path is used.
type attestedTransport struct {
	enclave string
	repo    string
	base    *http.Transport
	verify  func([]byte, []byte, string) (*verify.Verification, error)
	gate    chan struct{}
	bound   *http.Transport
	expires time.Time
}

func validateEnclave(enclave, repo string) error {
	if !web.ValidOrigin("https://"+enclave) || strings.Trim(enclave, web.HostChars) != "" || strings.Contains(enclave, ":") {
		return errors.New("Tinfoil enclave must be a lowercase HTTPS hostname without a port")
	}
	_, _, _, err := verify.ParseReference(repo)
	return err
}

// newAttestedTransport verifies the enclave before callers can send credentials or MCP discovery.
// Inference and MCP share the same attestation, renewal, and TLS key binding.
func newAttestedTransport(ctx context.Context, key *credential.Value, enclave, repo string, base *http.Transport) (*attestedTransport, error) {
	if !key.Configured() {
		return nil, errors.New("Tinfoil API key is not configured")
	}
	v, err := verify.NewVerifier()
	if err != nil {
		return nil, err
	}
	t := &attestedTransport{enclave: enclave, repo: repo, base: base, verify: v.VerifyV3, gate: make(chan struct{}, 1)}
	if _, err := t.current(ctx, nil); err != nil {
		t.CloseIdleConnections()
		return nil, err
	}
	return t, nil
}

func (t *attestedTransport) current(ctx context.Context, rejected *http.Transport) (*http.Transport, error) {
	select {
	case t.gate <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-t.gate }()
	if t.bound != nil && t.bound != rejected && time.Now().Before(t.expires) {
		return t.bound, nil
	}
	if t.bound != nil {
		t.bound.CloseIdleConnections()
		t.bound = nil
	}

	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	nonce, err := document.RandomNonce()
	if err != nil {
		return nil, err
	}
	u := "https://" + t.enclave + "/.well-known/tinfoil-attestation?nonce=" + hex.EncodeToString(nonce)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	// RoundTrip never follows redirects and this request carries no credential.
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("fetch Tinfoil attestation: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Tinfoil attestation returned HTTP %d", resp.StatusCode)
	}
	const maxAttestationBytes = 32 << 20
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAttestationBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxAttestationBytes {
		return nil, errors.New("Tinfoil attestation is too large")
	}
	verified, err := t.verify(raw, nonce, t.repo)
	if err != nil {
		return nil, fmt.Errorf("verify Tinfoil attestation: %w", err)
	}
	pin, ok := verified.TLSPublicKeyFP()
	decoded, err := hex.DecodeString(pin)
	if !ok || err != nil || len(decoded) != sha256.Size {
		return nil, errors.New("invalid attested Tinfoil TLS key")
	}
	if !time.Now().Before(verified.FreshnessExpiresAt) {
		return nil, errors.New("Tinfoil attestation has expired")
	}
	bound := t.base.Clone()
	if bound.TLSClientConfig == nil {
		bound.TLSClientConfig = new(tls.Config)
	}
	previous := bound.TLSClientConfig.VerifyConnection
	bound.TLSClientConfig.VerifyConnection = func(state tls.ConnectionState) error {
		if previous != nil {
			if err := previous(state); err != nil {
				return err
			}
		}
		if !time.Now().Before(verified.FreshnessExpiresAt) {
			return errors.New("Tinfoil attestation has expired")
		}
		if len(state.PeerCertificates) == 0 {
			return errTinfoilKey
		}
		digest := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
		if hex.EncodeToString(digest[:]) != pin {
			return errTinfoilKey
		}
		return nil
	}
	t.bound, t.expires = bound, verified.FreshnessExpiresAt
	return bound, nil
}

func (t *attestedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.Host != t.enclave {
		if r.Body != nil {
			r.Body.Close()
		}
		return nil, errors.New("Tinfoil transport refuses another origin")
	}
	bound, err := t.current(r.Context(), nil)
	if err != nil {
		if r.Body != nil {
			r.Body.Close()
		}
		return nil, err
	}
	resp, err := bound.RoundTrip(r)
	if !errors.Is(err, errTinfoilKey) {
		return resp, err
	}
	// A pin rejection occurs in the handshake, before any HTTP bytes are sent.
	// Re-attest once. Never replay a timeout, server error or interrupted stream.
	bound, refreshErr := t.current(r.Context(), bound)
	if refreshErr != nil {
		return nil, refreshErr
	}
	retry := r.Clone(r.Context())
	if r.Body != nil && r.Body != http.NoBody {
		if r.GetBody == nil {
			return nil, err
		}
		if retry.Body, refreshErr = r.GetBody(); refreshErr != nil {
			return nil, refreshErr
		}
	}
	return bound.RoundTrip(retry)
}

func (t *attestedTransport) CloseIdleConnections() {
	t.gate <- struct{}{}
	defer func() { <-t.gate }()
	if t.bound != nil {
		t.bound.CloseIdleConnections()
	}
}
