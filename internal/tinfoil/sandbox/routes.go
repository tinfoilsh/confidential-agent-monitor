package sandbox

import (
	"crypto/sha256"
	"encoding/base32"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	// These server-assigned permissions identify a publisher and its bootstrap alias.
	RouteExtension     = "route"
	BootstrapExtension = "bootstrap-route"
	routeSuffix        = ".sandbox.invalid"
	// A bunker reaches another as NAME.sandbox, where NAME is an enrolled identity.
	bunkerSuffix = ".sandbox"
)

func RouteName(key ssh.PublicKey) string {
	digest := sha256.Sum256(key.Marshal())
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])) + routeSuffix
}

// bootstrapRoute names an unverified publisher by its claimed SSH user. Only its port
// 443 attestation and owner socket are reachable this way; callers verify the
// attestation and handshake with its attested key, and the route grants no agent access.
func bootstrapRoute(identity string) string {
	digest := sha256.Sum256([]byte(identity))
	return "bootstrap-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])) + routeSuffix
}

func ReservedRoute(host string) bool {
	host = "." + strings.TrimSuffix(strings.ToLower(host), ".")
	return strings.HasSuffix(host, bunkerSuffix) || strings.HasSuffix(host, routeSuffix)
}
