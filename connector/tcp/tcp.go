package tcp

import (
	"errors"
	"fmt"
	"net"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/tinfoilsh/confidential-agent-monitor/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/netx"
)

var Kind = connector.Kind{Parse: Parse, Open: connector.Stateless((*TCP).serve)}

const maxPort = 65535

type TCP struct {
	connector.Semantics `json:"-"`
	Hosts               []string `json:"hosts"`
	Ports               []uint32 `json:"ports,omitempty"`
}

func Parse(source connector.Setup) (connector.Prepared, error) {
	c := new(TCP)
	if err := connector.ParseSetup(source, c, &c.Semantics); err != nil {
		return connector.Prepared{}, err
	}
	if len(c.Hosts) == 0 {
		return connector.Prepared{}, errors.New("TCP needs at least one host pattern")
	}
	for _, host := range c.Hosts {
		if _, err := path.Match(host, "example.com"); err != nil || host == "" || strings.ContainsAny(host, "/\\ \t\r\n") {
			return connector.Prepared{}, fmt.Errorf("invalid TCP host pattern %q", host)
		}
	}
	for _, port := range c.Ports {
		if port == 0 || port > maxPort {
			return connector.Prepared{}, fmt.Errorf("invalid TCP port %d; use 1 to %d", port, maxPort)
		}
	}
	return connector.Prepared{Value: c, Claim: c.Claim, Hosts: c.Hosts}, nil
}

func (c *TCP) Claim(host string, port uint32) int {
	if port == 0 || port > maxPort || host == "" {
		return -1
	}
	if len(c.Ports) > 0 && !slices.Contains(c.Ports, port) {
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

func (r *TCPFacts) Describe() facts.Facts {
	return facts.Facts{Title: "Connect to " + net.JoinHostPort(r.Host, strconv.Itoa(int(r.Port))),
		Operation:  &facts.Operation{Action: "connect"},
		Parameters: map[string]any{"host": r.Host, "port": r.Port}, Details: Details{TCP: r},
		Context: facts.Context{Sends: "anyone", Observes: facts.Label{Audience: "me", Trust: "untrusted"}}}
}

func (c *TCP) serve(s *connector.Stream, e *connector.Env) {
	host, port := s.Host, s.Port
	if c.Claim(host, port) < 0 || s.Gate(s.Context, c.Capture((&TCPFacts{Host: host, Port: port}).Describe())) != nil {
		return
	}
	upstream, err := e.Dialer.DialContext(s.Context, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		return
	}
	netx.Relay(s.Context, s.Conn, upstream)
}
