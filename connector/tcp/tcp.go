package tcp

import (
	"errors"
	"fmt"
	"net"
	"path"
	"strconv"
	"strings"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/facts"
)

var Definition = connector.Definition{NewConfig: func() connector.Server { return new(TCP) }, Requests: []connector.Request{new(TCPRequest)}}

const maxPort = 65535

type TCP struct {
	Hosts []string `json:"hosts"`
}

func (c *TCP) UnmarshalJSON(raw []byte) error {
	type plain TCP
	if err := facts.DecodeNumbers(raw, (*plain)(c)); err != nil {
		return err
	}
	if len(c.Hosts) == 0 {
		return errors.New("TCP needs at least one host pattern")
	}
	for _, host := range c.Hosts {
		if _, err := path.Match(host, "example.com"); err != nil || host == "" || strings.ContainsAny(host, "/\\ \t\r\n") {
			return fmt.Errorf("invalid TCP host pattern %q", host)
		}
	}
	return nil
}

func (c *TCP) Claim(host string, port uint32) int {
	if port == 0 || port > maxPort || host == "" {
		return -1
	}
	score := -1
	for _, pattern := range c.Hosts {
		if ok, _ := path.Match(strings.ToLower(pattern), strings.ToLower(host)); ok {
			if pattern == "*" {
				score = max(score, 0)
			} else {
				score = max(score, len(pattern))
			}
		}
	}
	return score
}

type TCPRequest facts.TCP

func (r *TCPRequest) Describe(connector.Context) (facts.Facts, error) {
	return facts.Facts{Title: "Connect to " + net.JoinHostPort(r.Host, strconv.Itoa(int(r.Port))),
		Operation:  &facts.Operation{Action: "connect", Effects: []string{"read", "send"}},
		Parameters: map[string]any{"host": r.Host, "port": r.Port}, Details: facts.Details{TCP: (*facts.TCP)(r)},
		Context: facts.Context{Sends: "anyone", Observes: facts.Label{Audience: "me", Trust: "untrusted"}}}, nil
}

func (c *TCP) Serve(s *connector.Stream, e *connector.Env) {
	host, port := s.Host, s.Port
	if c.Claim(host, port) < 0 || s.Gate(s.Context, &TCPRequest{Host: host, Port: port}) != nil {
		return
	}
	upstream, err := e.Dialer.DialContext(s.Context, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		return
	}
	connector.Relay(s.Context, s.Conn, upstream)
}
