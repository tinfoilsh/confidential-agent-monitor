// Package frontdoor serves a Monitor's agents, route publishers and owner over SSH.
package frontdoor

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/monitor"
	"github.com/tinfoilsh/confidential-agent-monitor/netx"
	"github.com/tinfoilsh/confidential-agent-monitor/owner"
	"github.com/tinfoilsh/confidential-agent-monitor/routes"
	"golang.org/x/crypto/ssh"
)

const (
	fingerprintExtension = "fingerprint"
	ownerExtension       = "owner"
	deviceUserPrefix     = "device+sandbox:"
	routeUnavailable     = "route unavailable"
)

type certifiedKey struct{}

type publisherKey struct{}

var errLocked = errors.New("the Perimeter is locked")

type Server struct {
	Monitor    *monitor.Monitor
	Owner      *owner.SSH        // nil serves no owner sessions
	IdentityCA ssh.PublicKey     // nil names no identities by certificate
	Routes     *routes.Forwarder // nil refuses publishers
}

type target struct {
	Host       string
	Port       uint32
	Origin     string
	OriginPort uint32
}

func (s *Server) Serve(ln net.Listener) {
	serve(ln, s.config, s.session)
}

func (s *Server) config() *ssh.ServerConfig {
	host := s.Monitor.HostKey()
	if host == nil {
		return nil
	}
	c := &ssh.ServerConfig{MaxAuthTries: 3, PublicKeyCallback: s.authenticate, VerifiedPublicKeyCallback: s.certify}
	c.AddHostKey(host)
	return c
}

func (s *Server) authenticate(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	if s.Owner != nil && s.Owner.Authenticates(key) {
		return &ssh.Permissions{Extensions: map[string]string{ownerExtension: "true"}}, nil
	}
	if _, unlocked := s.Monitor.Generation(); !unlocked {
		return nil, errLocked
	}
	if cert, ok := key.(*ssh.Certificate); ok && s.IdentityCA != nil {
		if cert.CertType != ssh.UserCert || !bytes.Equal(cert.SignatureKey.Marshal(), s.IdentityCA.Marshal()) || cert.KeyId == "" || cert.ValidBefore == ssh.CertTimeInfinity {
			return nil, errors.New("an identity certificate must be an expiring user certificate with a key ID from the identity CA")
		}
		// Principals carry groups, not logins, so any listed one stands in for the login.
		if err := new(ssh.CertChecker).CheckCert(cmp.Or(cert.ValidPrincipals...), cert); err != nil {
			return nil, err
		}
		// A certificate is public, so it is stored only once VerifiedPublicKeyCallback has seen its key sign.
		return &ssh.Permissions{Extensions: map[string]string{fingerprintExtension: ssh.FingerprintSHA256(cert.Key)},
			ExtraData: map[any]any{certifiedKey{}: cert}}, nil
	}
	publisher, err := s.Routes.Authenticate(conn.User(), key)
	if err != nil {
		return nil, err
	}
	fingerprint := ssh.FingerprintSHA256(key)
	permissions := &ssh.Permissions{Extensions: map[string]string{fingerprintExtension: fingerprint}}
	if publisher != nil {
		permissions.ExtraData = map[any]any{publisherKey{}: publisher}
		return permissions, nil
	}
	known, operator := s.Monitor.Capable(fingerprint, monitor.CapabilityRoutes)
	if !known {
		return nil, errors.New("key has no agent access")
	}
	if identity, required := strings.CutPrefix(conn.User(), deviceUserPrefix); required {
		if !operator {
			return nil, errors.New("identity has no route access")
		}
		if enrolled, _ := s.Monitor.Capable(identity, monitor.CapabilityRoutes); !enrolled {
			return nil, errors.New("route identity is not enrolled")
		}
	}
	return permissions, nil
}

func (s *Server) certify(_ ssh.ConnMetadata, _ ssh.PublicKey, p *ssh.Permissions, _ string) (*ssh.Permissions, error) {
	if cert, ok := p.ExtraData[certifiedKey{}].(*ssh.Certificate); ok {
		return p, s.Monitor.Certify(context.Background(), p.Extensions[fingerprintExtension], cert.KeyId, cert.ValidPrincipals, cert.ValidBefore)
	}
	return p, nil
}

func (s *Server) session(conn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	if conn.Permissions.Extensions[ownerExtension] == "true" {
		go ssh.DiscardRequests(reqs)
		for nc := range chans {
			go s.Owner.ServeChannel(nc)
		}
		return
	}

	fingerprint := conn.Permissions.Extensions[fingerprintExtension]
	if publisher, ok := conn.Permissions.ExtraData[publisherKey{}].(*routes.Publisher); ok {
		publisher.Trusted, _ = s.Monitor.Capable(fingerprint, monitor.CapabilityRoutes)
		s.Routes.ServePublisher(conn, chans, reqs, *publisher)
		return
	}

	go func() {
		for req := range reqs {
			req.Reply(req.Type == "keepalive@openssh.com", nil)
		}
	}()
	for nc := range chans {
		t, err := parse(nc)
		if err != nil {
			nc.Reject(ssh.Prohibited, err.Error())
			continue
		}
		go s.open(fingerprint, nc, t)
	}
}

func (s *Server) open(fingerprint string, nc ssh.NewChannel, t target) {
	if routes.ReservedRoute(t.Host) {
		if held, release, ok := s.Monitor.Hold(context.Background(), fingerprint, monitor.CapabilityRoutes); ok {
			defer release()
			upstream, err := s.Routes.Dial("tcp", net.JoinHostPort(t.Host, fmt.Sprint(t.Port)))
			if err != nil {
				nc.Reject(ssh.ConnectionFailed, routeUnavailable)
				return
			}
			defer upstream.Close()
			if ch, reqs, err := nc.Accept(); err == nil {
				netx.Relay(held, netx.NewChannelConn(ch, reqs), upstream)
			}
			return
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	accepted := false
	err := s.Monitor.Open(ctx, fingerprint, t.Host, t.Port, func() (net.Conn, error) {
		accepted = true
		ch, reqs, err := nc.Accept()
		if err != nil {
			return nil, err
		}
		conn := netx.NewChannelConn(ch, reqs)
		go func() { <-conn.Closed(); cancel() }()
		return conn, nil
	})
	if err == nil || accepted {
		return
	}
	nc.Reject(ssh.Prohibited, err.Error())
}

func parse(nc ssh.NewChannel) (target, error) {
	var t target
	if nc.ChannelType() != "direct-tcpip" {
		return t, errors.New("only direct-tcpip channels are forwarded")
	}
	if err := ssh.Unmarshal(nc.ExtraData(), &t); err != nil {
		return t, errors.New("malformed direct-tcpip request")
	}
	return t, nil
}

func serve(ln net.Listener, config func() *ssh.ServerConfig, session func(*ssh.ServerConn, <-chan ssh.NewChannel, <-chan *ssh.Request)) {
	handshakes := make(chan struct{}, 64)
	for {
		nc, err := ln.Accept()
		if err != nil {
			if !errors.Is(err, net.ErrClosed) {
				log.Printf("SSH listener: %v", err)
			}
			return
		}
		front := config()
		if front == nil {
			nc.Close()
			continue
		}
		select {
		case handshakes <- struct{}{}:
		default:
			nc.Close()
			continue
		}
		go func() {
			nc.SetDeadline(time.Now().Add(10 * time.Second))
			conn, chans, reqs, err := ssh.NewServerConn(nc, front)
			<-handshakes
			if err != nil {
				nc.Close()
				return
			}
			nc.SetDeadline(time.Time{})
			defer conn.Close()
			session(conn, chans, reqs)
		}()
	}
}
