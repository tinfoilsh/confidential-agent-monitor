// Package frontdoor serves SSH: registered identities open direct-tcpip streams, and extensions take whole connections.
package frontdoor

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"net"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/identity"
	"github.com/tinfoilsh/confidential-agent-monitor/core/netx"
	"github.com/tinfoilsh/confidential-agent-monitor/core/sshx"
	"golang.org/x/crypto/ssh"
)

const (
	fingerprintExtension = "fingerprint"
	maxAuthTries         = 3
)

type certifiedKey struct{}

type sessionKey struct{}

type Server struct {
	HostKey    func() ssh.Signer
	Identities *identity.Registry
	CA         ssh.PublicKey // nil names no identities by certificate
	// Streams serves each direct-tcpip channel under a context carrying its identity.
	Streams netx.Opener
	// Extensions are tried in order before identities.
	Extensions []sshx.Extension
}

func (s *Server) Serve(ln net.Listener) {
	config := func() *ssh.ServerConfig {
		host := s.HostKey()
		if host == nil {
			return nil
		}

		c := &ssh.ServerConfig{
			MaxAuthTries:              maxAuthTries,
			PublicKeyCallback:         s.authenticate,
			VerifiedPublicKeyCallback: s.certify,
		}
		c.AddHostKey(host)
		return c
	}

	sshx.Serve(ln, config, s.session)
}

func (s *Server) authenticate(conn ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	for _, extension := range s.Extensions {
		session, err := extension(conn, key)
		if err != nil {
			return nil, err
		}

		if session != nil {
			return &ssh.Permissions{ExtraData: map[any]any{sessionKey{}: session}}, nil
		}
	}

	if cert, ok := key.(*ssh.Certificate); ok && s.CA != nil {
		if cert.CertType != ssh.UserCert ||
			!bytes.Equal(cert.SignatureKey.Marshal(), s.CA.Marshal()) ||
			cert.KeyId == "" ||
			cert.ValidBefore == ssh.CertTimeInfinity {
			return nil, errors.New("an identity certificate must be an expiring user certificate with a key ID from the identity CA")
		}

		// Principals carry groups, not logins, so any listed one stands in for the login.
		if err := new(ssh.CertChecker).CheckCert(cmp.Or(cert.ValidPrincipals...), cert); err != nil {
			return nil, err
		}

		// A certificate is public, so it is registered only once VerifiedPublicKeyCallback has seen its key sign.
		return &ssh.Permissions{
			Extensions: map[string]string{fingerprintExtension: ssh.FingerprintSHA256(cert.Key)},
			ExtraData:  map[any]any{certifiedKey{}: cert},
		}, nil
	}

	fingerprint := ssh.FingerprintSHA256(key)
	if _, known := s.Identities.Lookup(fingerprint); !known {
		return nil, errors.New("key has no agent access")
	}

	return &ssh.Permissions{Extensions: map[string]string{fingerprintExtension: fingerprint}}, nil
}

func (s *Server) certify(_ ssh.ConnMetadata, _ ssh.PublicKey, p *ssh.Permissions, _ string) (*ssh.Permissions, error) {
	cert, ok := p.ExtraData[certifiedKey{}].(*ssh.Certificate)
	if !ok {
		return p, nil
	}

	identity := facts.Principal{Name: cert.KeyId, Groups: cert.ValidPrincipals}
	end, err := s.Identities.Register(p.Extensions[fingerprintExtension], identity, false)
	if err != nil {
		return p, err
	}
	time.AfterFunc(time.Until(time.Unix(int64(cert.ValidBefore), 0)), end)
	return p, nil
}

func (s *Server) session(conn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
	if session, ok := conn.Permissions.ExtraData[sessionKey{}].(sshx.Session); ok {
		session(conn, chans, reqs)
		return
	}

	fingerprint := conn.Permissions.Extensions[fingerprintExtension]
	go sshx.AnswerKeepalives(reqs)

	for nc := range chans {
		t, err := parse(nc)
		if err != nil {
			nc.Reject(ssh.Prohibited, err.Error())
			continue
		}
		go s.open(fingerprint, nc, t)
	}
}

func (s *Server) open(fingerprint string, nc ssh.NewChannel, t sshx.TCPIP) {
	ctx, cancel, ok := s.Identities.Hold(context.Background(), fingerprint)
	if !ok {
		nc.Reject(ssh.Prohibited, "key has no agent access")
		return
	}
	defer cancel()

	accepted := false
	err := s.Streams.Open(ctx, t.Host, t.Port, func() (net.Conn, error) {
		accepted = true
		ch, reqs, err := nc.Accept()
		if err != nil {
			return nil, err
		}

		conn := sshx.NewConn(ch, reqs)
		go func() {
			<-conn.Closed()
			cancel()
		}()
		return conn, nil
	})
	if err == nil || accepted {
		return
	}

	reason := ssh.Prohibited
	if errors.Is(err, netx.ErrUnavailable) {
		reason = ssh.ConnectionFailed
	}
	nc.Reject(reason, err.Error())
}

func parse(nc ssh.NewChannel) (sshx.TCPIP, error) {
	var t sshx.TCPIP
	if nc.ChannelType() != "direct-tcpip" {
		return t, errors.New("only direct-tcpip channels are forwarded")
	}

	if err := ssh.Unmarshal(nc.ExtraData(), &t); err != nil {
		return t, errors.New("malformed direct-tcpip request")
	}
	return t, nil
}
