package sandbox

import (
	"errors"
	"strings"

	"golang.org/x/crypto/ssh"
)

// Authenticate distinguishes reverse-tunnel publishers from known clients after
// the host's owner/locked checks. Key probes never enroll or restore an identity.
func Authenticate(conn ssh.ConnMetadata, key ssh.PublicKey, identity func(string) (bool, bool)) (map[string]string, error) {
	if instance, publisher := strings.CutPrefix(conn.User(), BootstrapUser); publisher {
		if instance == "" {
			return nil, errors.New("bunker instance is required")
		}
		return map[string]string{RouteExtension: RouteName(key), BootstrapExtension: bootstrapRoute(conn.User())}, nil
	}
	known, routes := identity(ssh.FingerprintSHA256(key))
	if !known {
		return nil, errors.New("key has no agent access")
	}
	if fingerprint, required := strings.CutPrefix(conn.User(), "device+sandbox:"); required {
		if !routes {
			return nil, errors.New("device has no bunker route access")
		}
		if known, _ := identity(fingerprint); !known {
			return nil, errors.New("bunker is not enrolled")
		}
	}
	return map[string]string{}, nil
}
