// Package routes serves the forwards identities publish over SSH and dials them as reserved route hosts.
package routes

import (
	"crypto/sha256"
	"encoding/base32"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	routeSuffix = ".sandbox.invalid"
	// An identity reaches another enrolled identity, NAME, as NAME.sandbox.
	identitySuffix = ".sandbox"
	// bootstrapUser prefixes the SSH user a publisher announces its bootstrap route as.
	bootstrapUser = "sandbox-v2:"
)

func routeName(key ssh.PublicKey) string {
	digest := sha256.Sum256(key.Marshal())
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])) + routeSuffix
}

// BootstrapRoute names an unverified publisher by the instance it claims. Only its port
// 443 is reachable this way; callers verify what it serves, and the route grants no agent access.
func BootstrapRoute(instance string) string {
	digest := sha256.Sum256([]byte(bootstrapUser + instance))
	return "bootstrap-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])) + routeSuffix
}

func ReservedRoute(host string) bool {
	host = "." + strings.TrimSuffix(strings.ToLower(host), ".")
	return strings.HasSuffix(host, identitySuffix) || strings.HasSuffix(host, routeSuffix)
}
