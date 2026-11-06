package sandbox

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/internal/frontdoor"
	"golang.org/x/crypto/ssh"
)

const (
	maxUntrustedPublishers = 128
	maxForwardAddresses    = 128
	forwardOpenTimeout     = 10 * time.Second
)

var errRouteUnavailable = errors.New("route unavailable")

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
	mu     sync.Mutex
	peers  map[string]*forwardPeer
	relays http.RoundTripper
}

// NewForwarder keeps each sandbox's bootstrap connections open between relayed
// requests, so a request does not wait for a new forwarded channel.
func NewForwarder() *Forwarder {
	f := new(Forwarder)
	f.relays = &http.Transport{DisableCompression: true, MaxIdleConnsPerHost: relayIdleConns, IdleConnTimeout: relayIdleTimeout,
		DialContext: func(_ context.Context, _, address string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			return f.Dial(host, 443)
		}}
	return f
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

// Dial opens a sandbox destination's virtual loopback forward for a peer name or
// unambiguous alias. Addresses are scoped to the publisher, so peers can publish the
// same ports. Bootstrap aliases expose only port 443; key-derived names may use any port.
func (f *Forwarder) Dial(name string, port uint32) (net.Conn, error) {
	name = strings.TrimSuffix(strings.ToLower(name), ".")
	if port == 0 || port > 65535 || strings.HasPrefix(name, "bootstrap-") && port != 443 {
		return nil, errRouteUnavailable
	}
	endpoint := forwardAddress{"127.0.0.1", port}
	f.mu.Lock()
	peer := f.peers[name]
	if peer == nil && name != "" {
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
	channel, requests, err := peer.conn.OpenChannel("forwarded-tcpip", ssh.Marshal(frontdoor.Target{Host: endpoint.Host, Port: port, Origin: endpoint.Host, OriginPort: port}))
	if err != nil {
		return nil, errRouteUnavailable
	}
	return connector.NewChannelConn(channel, requests), nil
}
