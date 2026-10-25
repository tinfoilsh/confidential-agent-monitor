//go:build !dev

package sandbox

import (
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"

	"github.com/tinfoilsh/tinfoil-go/verify"
	"github.com/tinfoilsh/tinfoil-go/verify/document"
	"golang.org/x/crypto/ssh"
)

// Verify verifies a document against the digest-pinned source, whose config fixes the boot's instance and owner.
func Verify(doc, nonce []byte, source string) (*Evidence, error) {
	verifier, err := verify.NewVerifier()
	if err != nil {
		return nil, err
	}
	verified, err := verifier.VerifyV3(doc, nonce, source)
	if err != nil {
		return nil, err
	}
	if verified.Config == nil {
		return nil, errors.New("sandbox attestation has no measured config")
	}
	data, ok := verified.CryptoMaterialData(sandboxHostKeyID, document.KeySPKIV1Format)
	if !ok {
		return nil, fmt.Errorf("sandbox endorses no %q key", sandboxHostKeyID)
	}
	der, err := hex.DecodeString(data)
	if err != nil {
		return nil, err
	}
	public, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, err
	}
	hostKey, err := ssh.NewPublicKey(public)
	if err != nil {
		return nil, err
	}
	return &Evidence{HostKey: hostKey, Expires: verified.FreshnessExpiresAt}, nil
}
