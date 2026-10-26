// Package frontdoor bounds SSH transport and selects explicit or claimed targets.
package frontdoor

import (
	"errors"
	"log"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

type Target struct {
	Host       string
	Port       uint32
	Origin     string
	OriginPort uint32
}
type Candidate struct {
	Name  string
	Claim func(string, uint32) int
}

// Select resolves only supplied candidates, so inaccessible accounts cannot tie.
func Select(host string, port uint32, candidates []Candidate) (name string, explicit bool) {
	// Explicit names bypass inference.
	if name, ok := strings.CutSuffix(host, ".monitor"); ok {
		for _, c := range candidates {
			if c.Name == name {
				return name, true
			}
		}
		return "", true
	}
	best, tied := -1, false
	for _, c := range candidates {
		if c.Claim == nil {
			continue
		}
		score := c.Claim(host, port)
		if score < 0 {
			continue
		}
		if score > best {
			name, best, tied = c.Name, score, false
		} else if score == best {
			tied = true
		}
	}
	// Refuse ambiguous routing claims.
	if tied {
		return "", false
	}
	return name, false
}

func Parse(nc ssh.NewChannel) (Target, error) {
	var t Target
	if nc.ChannelType() != "direct-tcpip" {
		return t, errors.New("only direct-tcpip channels are forwarded")
	}
	if err := ssh.Unmarshal(nc.ExtraData(), &t); err != nil {
		return t, errors.New("malformed direct-tcpip request")
	}
	return t, nil
}

func Serve(ln net.Listener, config func() *ssh.ServerConfig, session func(*ssh.ServerConn, <-chan ssh.NewChannel, <-chan *ssh.Request)) {
	// Bound concurrent authentication work.
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
