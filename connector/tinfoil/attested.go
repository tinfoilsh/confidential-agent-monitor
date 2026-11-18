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
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/connector/worker"
	"github.com/tinfoilsh/tinfoil-go/verify"
	tinfoildoc "github.com/tinfoilsh/tinfoil-go/verify/document"
)

var errKey = errors.New("TLS key differs from its attestation")

type Transport struct {
	enclave, repo string
	verifier      *verify.Verifier
	base          *http.Transport
	gate          chan struct{}
	bound         *http.Transport
	expires       time.Time
}

func Attest(ctx context.Context, h worker.Host, secret, enclave, repo string, base *http.Transport) (*Transport, error) {
	if !h.Configured(secret) {
		return nil, errors.New("Tinfoil API key is not configured")
	}
	verifier, err := verify.NewVerifier()
	if err != nil {
		return nil, err
	}
	t := &Transport{enclave: enclave, repo: repo, verifier: verifier, base: base, gate: make(chan struct{}, 1)}
	if _, err := t.current(ctx, nil); err != nil {
		t.CloseIdleConnections()
		return nil, err
	}
	return t, nil
}

func (t *Transport) current(ctx context.Context, rejected *http.Transport) (*http.Transport, error) {
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

	ctx, cancel := context.WithTimeout(ctx, attestationTimeout)
	defer cancel()
	nonce, err := tinfoildoc.RandomNonce()
	if err != nil {
		return nil, err
	}
	u := "https://" + t.enclave + AttestationPath + "?nonce=" + hex.EncodeToString(nonce)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := t.base.RoundTrip(req)
	if err != nil {
		return nil, fmt.Errorf("fetch attestation: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("attestation returned HTTP %d", resp.StatusCode)
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxAttestationBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxAttestationBytes {
		return nil, errors.New("attestation is too large")
	}
	verified, err := t.verifier.VerifyV3(raw, nonce, t.repo)
	if err != nil {
		return nil, fmt.Errorf("verify Tinfoil attestation: %w", err)
	}
	pin, ok := verified.TLSPublicKeyFP()
	decoded, err := hex.DecodeString(pin)
	if !ok || err != nil || len(decoded) != sha256.Size {
		return nil, errors.New("invalid attested Tinfoil TLS key")
	}
	fresh := verified.FreshnessExpiresAt
	if !time.Now().Before(fresh) {
		return nil, errors.New("attestation has expired")
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
		if !time.Now().Before(fresh) {
			return errors.New("attestation has expired")
		}
		if len(state.PeerCertificates) == 0 {
			return errKey
		}
		digest := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
		if hex.EncodeToString(digest[:]) != pin {
			return errKey
		}
		return nil
	}
	t.bound, t.expires = bound, fresh
	return bound, nil
}

func (t *Transport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.URL.Scheme != "https" || r.URL.Host != t.enclave {
		if r.Body != nil {
			r.Body.Close()
		}
		return nil, errors.New("attested transport refuses another origin")
	}
	bound, err := t.current(r.Context(), nil)
	if err != nil {
		if r.Body != nil {
			r.Body.Close()
		}
		return nil, err
	}
	resp, err := bound.RoundTrip(r)
	if !errors.Is(err, errKey) {
		return resp, err
	}
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

func (t *Transport) CloseIdleConnections() {
	t.gate <- struct{}{}
	defer func() { <-t.gate }()
	if t.bound != nil {
		t.bound.CloseIdleConnections()
	}
}
