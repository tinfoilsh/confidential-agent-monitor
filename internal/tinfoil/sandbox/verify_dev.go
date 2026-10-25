//go:build dev

package sandbox

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"time"

	"golang.org/x/crypto/ssh"
)

// devSandboxLifetime stands in for the freshness window a real attestation carries.
const devSandboxLifetime = 5 * time.Minute

// Verify trusts the self-reported host key and environment of dev/cvm sandboxes, which have no TEE.
func Verify(doc, _ []byte, _ string) (*Evidence, error) {
	var claimed struct {
		HostKey string `json:"host_key"`
	}
	if err := json.Unmarshal(doc, &claimed); err != nil {
		return nil, err
	}
	block, _ := pem.Decode([]byte(claimed.HostKey))
	if block == nil {
		return nil, errors.New("dev sandbox sent no PEM host key")
	}
	public, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	hostKey, err := ssh.NewPublicKey(public)
	if err != nil {
		return nil, err
	}
	return &Evidence{HostKey: hostKey, Expires: time.Now().Add(devSandboxLifetime)}, nil
}
