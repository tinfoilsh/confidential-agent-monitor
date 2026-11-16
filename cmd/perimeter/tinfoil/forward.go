package tinfoil

import (
	"context"
	"errors"
	"net"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"

	"github.com/tinfoilsh/confidential-agent-monitor/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/core/identity"
	"github.com/tinfoilsh/confidential-agent-monitor/core/sshx"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
)

const (
	maxUntrustedPublishers = 128
	maxForwardAddresses    = 128
	// An identity publishes an OpenSSH SOCKS RemoteForward on this loopback port.
	socksPort = "1080"
	aliasPort = 443
	// Listeners on 127.0.0.1 do not accept this loopback alias; wildcard listeners do.
	wildcardHost = "127.0.0.2"
	forwardHost  = "127.0.0.1"
	// A negative claim refuses a target.
	unclaimed = -1
)

var errRouteUnavailable = errors.New("not connected to the Perimeter")

// Publisher names an authenticated peer and an optional discovery alias.
// Trusted publishers are exempt from the limit on untrusted connections.
type Publisher struct {
	Name, Alias string
	Trusted     bool
}

type forwardPeer struct {
	Publisher
	conn     *ssh.ServerConn
	forwards *sshx.Forwards
}

// Forwarder serves virtual TCP forwards without binding sockets on the server.
// Each authenticated name owns one connection; aliases must resolve uniquely.
type Forwarder struct {
	// Identities holds the keys whose publishers are trusted and whose names route hosts resolve.
	Identities *identity.Registry

	mu    sync.Mutex
	peers map[string]*forwardPeer
}

// ServePublisher replaces a peer's previous connection immediately and owns its
// registrations until disconnect. Callers supply names from authentication.
// Only explicit ports (1-65535) are accepted; no local sockets are bound.
func (f *Forwarder) ServePublisher(conn *ssh.ServerConn, channels <-chan ssh.NewChannel, requests <-chan *ssh.Request, identity Publisher) {
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
	peer := &forwardPeer{Publisher: identity, conn: conn, forwards: sshx.NewForwards(conn, maxForwardAddresses)}
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

// Dial opens a publisher's virtual loopback forward at address, a peer name or
// unambiguous alias with a port. Addresses are scoped to the publisher, so peers can publish the
// same ports. Aliases expose only port 443; key-derived names may use any port.
func (f *Forwarder) Dial(_, address string) (net.Conn, error) {
	host, service, err := net.SplitHostPort(address)
	port, invalid := strconv.ParseUint(service, 10, 16)
	if f == nil || err != nil || invalid != nil || port == 0 {
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

func (f *Forwarder) DialContext(_ context.Context, network, address string) (net.Conn, error) {
	return f.Dial(network, address)
}

// RouteAllowed reports whether a route pattern among hosts matches host, so * never reaches a route.
func RouteAllowed(hosts []string, host string) bool {
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	return slices.ContainsFunc(hosts, func(pattern string) bool {
		ok, _ := path.Match(strings.ToLower(pattern), host)
		return ok && ReservedRoute(pattern)
	})
}

// RouteDialer dials reserved route hosts through Routes, none if it is nil, and every other address through Next.
type RouteDialer struct {
	Routes *Forwarder
	Next   proxy.ContextDialer
	// Keys lists the fingerprints of the keys registered as the identity a route host names, as NAME.sandbox.
	Keys  func(name string) []string
	Hosts []string
}

func (d RouteDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || !ReservedRoute(host) {
		return d.Next.DialContext(ctx, network, address)
	}
	name, named := strings.CutSuffix(strings.TrimSuffix(strings.ToLower(host), "."), identitySuffix)
	keys := d.Keys(name)
	if !RouteAllowed(d.Hosts, host) || !named || len(keys) != 1 {
		return nil, errRouteUnavailable
	}
	// The SOCKS server is the publisher's own ssh client, reached over an SSH channel, not a socket.
	server := net.JoinHostPort(routeName(keys[0]), socksPort)
	socks, err := proxy.SOCKS5(network, server, nil, nil)
	if err != nil {
		return nil, err
	}
	conn, err := d.Routes.DialContext(ctx, network, server)
	if err != nil {
		return nil, err
	}
	// The handshake runs on the channel itself, so callers keep its half-close and closure.
	if _, err := socks.(interface {
		DialWithConn(context.Context, net.Conn, string, string) (net.Addr, error)
	}).DialWithConn(ctx, conn, network, net.JoinHostPort(wildcardHost, port)); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// Kinds returns kinds whose connections dial reserved route hosts through f, and are never
// chosen for one that their hosts do not name.
func (f *Forwarder) Kinds(kinds map[string]connector.Kind) map[string]connector.Kind {
	routed := map[string]connector.Kind{}
	for name, kind := range kinds {
		parse, open := kind.Parse, kind.Open
		kind.Parse = func(setup connector.Setup) (connector.Prepared, error) {
			p, err := parse(setup)
			if claim := p.Claim; claim != nil {
				p.Claim = func(host string, port uint32) int {
					if ReservedRoute(host) && !RouteAllowed(p.Hosts, host) {
						return unclaimed
					}
					return claim(host, port)
				}
			}
			return p, err
		}
		kind.Open = func(ctx context.Context, p connector.Prepared, secrets map[string]connector.Secret, env *connector.Env) (connector.Handler, error) {
			routed := *env
			routed.Dialer = RouteDialer{Routes: f, Next: env.Dialer, Keys: f.Identities.Keys, Hosts: p.Hosts}
			return open(ctx, p, secrets, &routed)
		}
		routed[name] = kind
	}
	return routed
}
