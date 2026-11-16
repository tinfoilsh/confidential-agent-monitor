package sandbox

import (
	"context"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/sshtransport"
	"github.com/tinfoilsh/tinfoil-go/verify"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
)

const (
	maxUntrustedPublishers = 128
	maxForwardAddresses    = 128
	forwardOpenTimeout     = 10 * time.Second
	socksPort              = "1080"
	aliasPort              = 443
	wildcardHost           = "127.0.0.2"
	forwardHost            = "127.0.0.1"
	unclaimed              = -1

	routeSuffix       = ".sandbox.invalid"
	identitySuffix    = ".sandbox"
	bootstrapUser     = "sandbox-v2:"
	fingerprintPrefix = "SHA256:"
	Attribute         = "sandbox"
)

var (
	errRouteUnavailable  = errors.New("not connected to the Perimeter")
	ErrDirectUnavailable = fmt.Errorf("route %w", sshtransport.ErrUnavailable)
)

func routeName(fingerprint string) string {
	digest, _ := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(fingerprint, fingerprintPrefix))
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest)) + routeSuffix
}

func bootstrapRoute(instance string) string {
	digest := sha256.Sum256([]byte(bootstrapUser + instance))
	return "bootstrap-" + strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(digest[:])) + routeSuffix
}

func ReservedRoute(host string) bool {
	host = "." + strings.TrimSuffix(strings.ToLower(host), ".")
	return strings.HasSuffix(host, identitySuffix) || strings.HasSuffix(host, routeSuffix)
}

func routeAllowed(hosts []string, host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return slices.ContainsFunc(hosts, func(pattern string) bool {
		ok, _ := path.Match(strings.ToLower(pattern), host)
		return ok && ReservedRoute(pattern)
	})
}

type publisher struct {
	Name, Alias string
	Trusted     bool
}

type forwardPeer struct {
	publisher
	conn     *ssh.ServerConn
	forwards *sshtransport.Forwards
}

type Forwarder struct {
	mu    sync.Mutex
	peers map[string]*forwardPeer
}

func (f *Forwarder) servePublisher(conn *ssh.ServerConn, channels <-chan ssh.NewChannel, requests <-chan *ssh.Request, identity publisher) {
	defer conn.Close()
	if identity.Name == "" {
		return
	}
	f.mu.Lock()
	unknown := 0
	for name, peer := range f.peers {
		if name != identity.Name && !peer.Trusted {
			unknown++
		}
	}
	if !identity.Trusted && unknown >= maxUntrustedPublishers {
		f.mu.Unlock()
		return
	}
	previous := f.peers[identity.Name]
	peer := &forwardPeer{publisher: identity, conn: conn, forwards: sshtransport.NewForwards(conn, maxForwardAddresses, forwardOpenTimeout)}
	if f.peers == nil {
		f.peers = map[string]*forwardPeer{}
	}
	f.peers[identity.Name] = peer
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		if f.peers[identity.Name] == peer {
			delete(f.peers, identity.Name)
		}
	}()
	if previous != nil {
		previous.conn.Close()
	}
	go func() {
		for channel := range channels {
			channel.Reject(ssh.Prohibited, "publisher connections cannot open client channels")
		}
	}()
	peer.forwards.Serve(requests)
}

func (f *Forwarder) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	host, service, err := net.SplitHostPort(address)
	port, invalid := strconv.ParseUint(service, 10, 16)
	if err != nil || invalid != nil || port == 0 {
		return nil, errRouteUnavailable
	}
	name := strings.TrimSuffix(strings.ToLower(host), ".")
	f.mu.Lock()
	peer := f.peers[name]
	if peer == nil && name != "" && port == aliasPort {
		for _, candidate := range f.peers {
			if candidate.Alias == name && candidate.forwards.Has(forwardHost, uint32(port)) {
				if peer != nil {
					f.mu.Unlock()
					return nil, errRouteUnavailable
				}
				peer = candidate
			}
		}
	}
	f.mu.Unlock()
	if peer == nil {
		return nil, errRouteUnavailable
	}
	conn, err := peer.forwards.Dial(forwardHost, uint32(port))
	if err != nil {
		return nil, errRouteUnavailable
	}
	return conn, nil
}

type dialFunc = func(ctx context.Context, network, address string) (net.Conn, error)

func (f *Forwarder) RouteDial(hosts []string, keysOf func(name string) []string, next dialFunc) dialFunc {
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		host, port, err := net.SplitHostPort(address)
		if err != nil || !ReservedRoute(host) {
			return next(ctx, network, address)
		}
		name, named := strings.CutSuffix(strings.TrimSuffix(strings.ToLower(host), "."), identitySuffix)
		keys := keysOf(name)
		if !routeAllowed(hosts, host) || !named || len(keys) != 1 {
			return nil, errRouteUnavailable
		}
		server := net.JoinHostPort(routeName(keys[0]), socksPort)
		socks, err := proxy.SOCKS5(network, server, nil, nil)
		if err != nil {
			return nil, err
		}
		conn, err := f.DialContext(ctx, network, server)
		if err != nil {
			return nil, err
		}
		if _, err := socks.(interface {
			DialWithConn(context.Context, net.Conn, string, string) (net.Addr, error)
		}).DialWithConn(ctx, conn, network, net.JoinHostPort(wildcardHost, port)); err != nil {
			conn.Close()
			return nil, err
		}
		return conn, nil
	}
}

func RouteClaim(hosts []string, claim func(string, uint32) int) func(string, uint32) int {
	if claim == nil {
		return nil
	}
	return func(host string, port uint32) int {
		if ReservedRoute(host) && !routeAllowed(hosts, host) {
			return unclaimed
		}
		return claim(host, port)
	}
}

func (f *Forwarder) Publisher(user string, key ssh.PublicKey, trusted func(fingerprint string) (bool, error)) (sshtransport.Session, error) {
	instance, announced := strings.CutPrefix(user, bootstrapUser)
	if !announced {
		return nil, nil
	}
	if instance == "" {
		return nil, errors.New("a publisher instance is required")
	}
	fingerprint := ssh.FingerprintSHA256(key)
	p := publisher{Name: routeName(fingerprint), Alias: bootstrapRoute(instance)}
	var err error
	if p.Trusted, err = trusted(fingerprint); err != nil {
		return nil, err
	}
	return func(conn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
		f.servePublisher(conn, chans, reqs, p)
	}, nil
}

type Boot struct {
	Source     string `json:"source"`
	InstanceID string `json:"instance_id"`
}

func ValidateBoot(raw json.RawMessage) error {
	var b Boot
	if len(raw) == 0 {
		return nil
	}
	if err := facts.DecodeNumbers(raw, &b); err != nil {
		return err
	}
	if b == (Boot{}) {
		return nil
	}
	if _, _, digest, err := verify.ParseReference(b.Source); err != nil || digest == "" {
		return errors.New("source must be a digest-pinned release reference")
	}
	if b.InstanceID == "" {
		return errors.New("instance_id is required")
	}
	return nil
}
