package routes

import (
	"context"
	"errors"
	"net"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/netx"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/proxy"
)

const (
	maxUntrustedPublishers = 128
	maxForwardAddresses    = 128
	forwardOpenTimeout     = 10 * time.Second
	// An identity publishes an OpenSSH SOCKS RemoteForward on this loopback port.
	socksPort = "1080"
	aliasPort = 443
	// Listeners on 127.0.0.1 do not accept this loopback alias; wildcard listeners do.
	wildcardHost = "127.0.0.2"
)

var errRouteUnavailable = errors.New("not connected to the Perimeter")

// Publisher names an authenticated peer and an optional discovery alias.
// Trusted publishers are exempt from the limit on untrusted connections.
type Publisher struct {
	Name, Alias string
	Trusted     bool
}

type forwardAddress struct {
	Host string
	Port uint32
}

type forwardPeer struct {
	Publisher
	conn      *ssh.ServerConn
	addresses map[forwardAddress]bool
}

// Forwarder serves virtual TCP forwards without binding sockets on the server.
// Each authenticated name owns one connection; aliases must resolve uniquely.
type Forwarder struct {
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
	peer := &forwardPeer{Publisher: identity, conn: conn, addresses: map[forwardAddress]bool{}}
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
	for req := range requests {
		ok := req.Type == "keepalive@openssh.com"
		var address forwardAddress
		if (req.Type == "tcpip-forward" || req.Type == "cancel-tcpip-forward") && ssh.Unmarshal(req.Payload, &address) == nil && address.Port > 0 && address.Port <= 65535 {
			f.mu.Lock()
			if f.peers[identity.Name] == peer {
				if req.Type == "cancel-tcpip-forward" {
					ok = peer.addresses[address]
					delete(peer.addresses, address)
				} else if !peer.addresses[address] && len(peer.addresses) < maxForwardAddresses {
					peer.addresses[address], ok = true, true
				}
			}
			f.mu.Unlock()
		}
		req.Reply(ok, nil)
	}
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
	endpoint := forwardAddress{"127.0.0.1", uint32(port)}
	f.mu.Lock()
	peer := f.peers[name]
	if peer == nil && name != "" && port == aliasPort {
		for _, candidate := range f.peers {
			if candidate.Alias == name && candidate.addresses[endpoint] {
				if peer != nil {
					f.mu.Unlock()
					return nil, errRouteUnavailable
				}
				peer = candidate
			}
		}
	}
	available := peer != nil && peer.addresses[endpoint]
	f.mu.Unlock()
	if !available {
		return nil, errRouteUnavailable
	}
	// OpenChannel cannot be canceled, so a peer that stalls it is closed.
	stalled := time.AfterFunc(forwardOpenTimeout, func() { peer.conn.Close() })
	defer stalled.Stop()
	channel, requests, err := peer.conn.OpenChannel("forwarded-tcpip", ssh.Marshal(struct {
		Host       string
		Port       uint32
		Origin     string
		OriginPort uint32
	}{endpoint.Host, endpoint.Port, endpoint.Host, endpoint.Port}))
	if err != nil {
		return nil, errRouteUnavailable
	}
	return netx.NewChannelConn(channel, requests), nil
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
	// Key returns the key of the enrolled identity a route host names, as NAME.sandbox.
	Key   func(name string) (ssh.PublicKey, bool)
	Hosts []string
}

func (d RouteDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil || !ReservedRoute(host) {
		return d.Next.DialContext(ctx, network, address)
	}
	name, named := strings.CutSuffix(strings.TrimSuffix(strings.ToLower(host), "."), identitySuffix)
	key, enrolled := d.Key(name)
	if !RouteAllowed(d.Hosts, host) || !named || !enrolled {
		return nil, errRouteUnavailable
	}
	// The SOCKS server is the publisher's own ssh client, reached over an SSH channel, not a socket.
	server := net.JoinHostPort(routeName(key), socksPort)
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
