package teleport

import (
	"bytes"
	"cmp"
	"encoding/json"
	"errors"
	"strings"

	"github.com/tinfoilsh/confidential-agent-monitor/core/certificates"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"golang.org/x/crypto/ssh"
)

const (
	rolesExtension       = "teleport-roles"
	permitPortForwarding = "permit-port-forwarding"
	// Teleport adds principals with this prefix for itself; they are never logins.
	internalPrefix = "-teleport-"
)

var (
	errLogin     = errors.New("the Teleport certificate does not permit this login with port forwarding")
	errAuthority = errors.New("the certificate is not from a trusted Teleport user CA")
)

// trusted holds the user CA public keys as tctl auth export --type=user writes them.
func User(trusted []byte, login string, cert *ssh.Certificate) (facts.Principal, error) {
	var err error
	for err == nil && len(bytes.TrimSpace(trusted)) != 0 {
		var ca ssh.PublicKey
		if ca, _, _, trusted, err = ssh.ParseAuthorizedKey(trusted); err != nil || !bytes.Equal(ca.Marshal(), cert.SignatureKey.Marshal()) {
			continue
		}
		var roles struct {
			Roles []string `json:"roles"`
		}
		claims, err := certificates.VerifySSHUser(ca, cert, login)
		if err == nil {
			err = json.Unmarshal([]byte(cert.Extensions[rolesExtension]), &roles)
		}
		if _, forwards := cert.Extensions[permitPortForwarding]; err == nil && (!forwards || strings.HasPrefix(login, internalPrefix)) {
			err = errLogin
		}
		return facts.Principal{Name: claims.KeyID, Groups: roles.Roles}, err
	}
	return facts.Principal{}, cmp.Or(err, errAuthority)
}
