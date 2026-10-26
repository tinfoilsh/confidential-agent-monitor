package sandbox

import (
	"crypto/sha256"
	"encoding/base32"
	"net"
	"net/http"
	"strconv"
	"strings"

	"github.com/tinfoilsh/monitor/internal/frontdoor"
	"golang.org/x/crypto/ssh"
)

const (
	// These server-assigned permissions identify a publisher and its bootstrap alias.
	RouteExtension     = "route"
	BootstrapExtension = "bootstrap-route"
	routeSuffix        = ".sandbox.invalid"
)

var ErrRouteUnavailable = responseError{"route unavailable", http.StatusServiceUnavailable}

func RouteName(key ssh.PublicKey) string {
	digest := sha256.Sum256(key.Marshal())
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])) + routeSuffix
}

// bootstrapRoute names an unverified publisher by its claimed SSH user. Only
// attestation is reachable this way; callers must verify it before sending secrets.
func bootstrapRoute(identity string) string {
	digest := sha256.Sum256([]byte(identity))
	return "bootstrap-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])) + routeSuffix
}

func ReservedRoute(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return host == "sandbox.invalid" || strings.HasSuffix(host, routeSuffix)
}

// Dial resolves sandbox destinations to their virtual loopback forwards.
// Bootstrap aliases expose only attestation; key-derived names may use any port.
func Dial(forwards *frontdoor.Forwarder, host string, port uint32) (net.Conn, error) {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if strings.HasPrefix(host, "bootstrap-") && port != 443 {
		return nil, ErrRouteUnavailable
	}
	conn, err := forwards.Dial(host, net.JoinHostPort("127.0.0.1", strconv.FormatUint(uint64(port), 10)))
	if err != nil {
		return nil, ErrRouteUnavailable
	}
	return conn, nil
}
