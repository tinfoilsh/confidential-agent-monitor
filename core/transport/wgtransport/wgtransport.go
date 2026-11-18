package wgtransport

import (
	"encoding/base64"
	"errors"
	"fmt"
	"iter"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/tun/netstack"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

const (
	maxOpening     = 4096
	identityPrefix = "wireguard"
)

var errOverlap = errors.New("WireGuard peers' allowed addresses overlap")

// Identity names the peer that reaches the tunnel from one inner address.
func Identity(peer [32]byte, address netip.Addr) string {
	return strings.Join([]string{identityPrefix, base64.StdEncoding.EncodeToString(peer[:]), address.String()}, " ")
}

func ParseIdentity(key string) (peer [32]byte, address netip.Addr, ok bool) {
	fields := strings.Fields(key)
	if len(fields) != 3 || fields[0] != identityPrefix {
		return peer, address, false
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(fields[1])
	address, addressErr := netip.ParseAddr(fields[2])
	if err != nil || addressErr != nil || len(raw) != len(peer) || address.Zone() != "" {
		return peer, netip.Addr{}, false
	}
	return [32]byte(raw), address.Unmap(), true
}

func Peers(keys iter.Seq[string]) map[[32]byte][]netip.Prefix {
	peers := map[[32]byte][]netip.Prefix{}
	for key := range keys {
		if peer, address, ok := ParseIdentity(key); ok {
			peers[peer] = append(peers[peer], netip.PrefixFrom(address, address.BitLen()))
		}
	}
	return peers
}

// WireGuard drops a packet whose inner source is not among its peer's allowed addresses, so the source of a stream's SYN names the peer that opened it.
type Server struct {
	device  *device.Device
	ln      net.Listener
	port    uint16
	setting sync.Mutex
	mu      sync.Mutex
	peers   map[[32]byte][]netip.Prefix
	opening map[netip.AddrPort][32]byte
}

// WireGuard writes a peer's packets from that peer's goroutine, which removing the peer waits for, so the peers a write finds still hold its sender.
type stack struct {
	tun.Device
	s *Server
}

func (k stack) Write(bufs [][]byte, offset int) (int, error) {
	for _, buf := range bufs {
		if source, ok := syn(buf[offset:], k.s.port); ok {
			k.s.mu.Lock()
			for key, prefixes := range k.s.peers {
				if slices.ContainsFunc(prefixes, func(p netip.Prefix) bool { return p.Contains(source.Addr()) }) {
					// An unanswered SYN leaves its entry behind, so a full map is forgotten; Serve refuses what it held.
					if len(k.s.opening) == maxOpening {
						clear(k.s.opening)
					}
					k.s.opening[source] = key
				}
			}
			k.s.mu.Unlock()
		}
	}
	return k.Device.Write(bufs, offset)
}

func syn(packet []byte, port uint16) (netip.AddrPort, bool) {
	var ip header.Network
	switch version := header.IPVersion(packet); {
	case version == header.IPv4Version && header.IPv4(packet).IsValid(len(packet)):
		ip = header.IPv4(packet)
	case version == header.IPv6Version && header.IPv6(packet).IsValid(len(packet)):
		ip = header.IPv6(packet)
	default:
		return netip.AddrPort{}, false
	}
	tcp := header.TCP(ip.Payload())
	if ip.TransportProtocol() != header.TCPProtocolNumber || len(tcp) < header.TCPMinimumSize || tcp.DestinationPort() != port || tcp.Flags()&(header.TCPFlagSyn|header.TCPFlagAck) != header.TCPFlagSyn {
		return netip.AddrPort{}, false
	}
	address := ip.SourceAddress()
	source, _ := netip.AddrFromSlice(address.AsSlice())
	return netip.AddrPortFrom(source, tcp.SourcePort()), true
}

func Listen(private []byte, port uint16, address netip.AddrPort) (*Server, error) {
	tun, tnet, err := netstack.CreateNetTUN([]netip.Addr{address.Addr()}, nil, device.DefaultMTU)
	if err != nil {
		return nil, err
	}
	s := &Server{port: address.Port(), peers: map[[32]byte][]netip.Prefix{}, opening: map[netip.AddrPort][32]byte{}}
	s.device = device.NewDevice(stack{tun, s}, conn.NewDefaultBind(), device.NewLogger(device.LogLevelSilent, ""))
	err = s.device.IpcSet(fmt.Sprintf("private_key=%x\nlisten_port=%d\n", private, port))
	if err == nil {
		err = s.device.Up()
	}
	if err == nil {
		s.ln, err = tnet.ListenTCPAddrPort(address)
	}
	if err != nil {
		s.device.Close()
		return nil, err
	}
	return s, nil
}

// A peer whose addresses changed is removed and added again. Ending the streams Serve already accepted from a removed peer is the caller's.
func (s *Server) SetPeers(peers map[[32]byte][]netip.Prefix) error {
	var allowed []netip.Prefix
	for _, prefixes := range peers {
		for _, p := range prefixes {
			if slices.ContainsFunc(allowed, p.Overlaps) {
				return errOverlap
			}
			allowed = append(allowed, p)
		}
	}
	s.setting.Lock()
	defer s.setting.Unlock()
	var removed, added strings.Builder
	var gone [][32]byte
	s.mu.Lock()
	for key, old := range s.peers {
		if next, kept := peers[key]; !kept || len(next) != len(old) || slices.ContainsFunc(next, func(p netip.Prefix) bool { return !slices.Contains(old, p) }) {
			fmt.Fprintf(&removed, "public_key=%x\nremove=true\n", key)
			gone = append(gone, key)
		}
	}
	s.mu.Unlock()
	if err := s.device.IpcSet(removed.String()); err != nil {
		return err
	}
	s.mu.Lock()
	for _, key := range gone {
		delete(s.peers, key)
	}
	maps.DeleteFunc(s.opening, func(_ netip.AddrPort, peer [32]byte) bool { return slices.Contains(gone, peer) })
	for key, prefixes := range peers {
		if _, kept := s.peers[key]; !kept {
			fmt.Fprintf(&added, "public_key=%x\n", key)
			for _, p := range prefixes {
				fmt.Fprintf(&added, "allowed_ip=%s\n", p)
			}
			s.peers[key] = slices.Clone(prefixes)
		}
	}
	s.mu.Unlock()
	return s.device.IpcSet(added.String())
}

func (s *Server) Serve(serve func(peer [32]byte, source netip.AddrPort, conn net.Conn)) {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		source := c.RemoteAddr().(*net.TCPAddr).AddrPort()
		s.mu.Lock()
		peer, found := s.opening[source]
		delete(s.opening, source)
		s.mu.Unlock()
		if !found {
			c.Close()
			continue
		}
		go serve(peer, source, c)
	}
}

func (s *Server) Close() {
	s.ln.Close()
	s.device.Close()
}
