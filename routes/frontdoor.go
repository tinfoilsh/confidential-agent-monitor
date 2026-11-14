package routes

import (
	"errors"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Authenticate returns the reverse-tunnel publisher that user announces with key, or nil
// for any other user, after the host's owner/locked checks. Key probes never enroll or
// restore an identity. A nil Forwarder refuses publishers.
func (f *Forwarder) Authenticate(user string, key ssh.PublicKey) (*Publisher, error) {
	instance, publisher := strings.CutPrefix(user, bootstrapUser)
	if !publisher {
		return nil, nil
	}
	if f == nil {
		return nil, errors.New("this Perimeter does not serve routes")
	}
	if instance == "" {
		return nil, errors.New("a publisher instance is required")
	}
	return &Publisher{Name: routeName(key), Alias: BootstrapRoute(instance)}, nil
}
