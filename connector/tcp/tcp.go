package tcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"path"
	"slices"
	"strconv"
	"strings"

	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

const maxPort = 65535

type TCP struct {
	Hosts []string `json:"hosts"`
	Ports []uint32 `json:"ports,omitempty"`
}

func Parse(config json.RawMessage) (*TCP, error) {
	c := new(TCP)
	if err := facts.DecodeNumbers(config, c); err != nil {
		return nil, err
	}
	if len(c.Hosts) == 0 {
		return nil, errors.New("TCP needs at least one host pattern")
	}
	for _, host := range c.Hosts {
		if _, err := path.Match(host, "example.com"); err != nil || host == "" || strings.ContainsAny(host, "/\\ \t\r\n") {
			return nil, fmt.Errorf("invalid TCP host pattern %q", host)
		}
	}
	for _, port := range c.Ports {
		if port == 0 || port > maxPort {
			return nil, fmt.Errorf("invalid TCP port %d; use 1 to %d", port, maxPort)
		}
	}
	return c, nil
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

func (r *TCPFacts) Describe() facts.Observation {
	return facts.Observation{Title: "Connect to " + net.JoinHostPort(r.Host, strconv.Itoa(int(r.Port))),
		Operation:  &facts.Operation{Action: "connect"},
		Parameters: map[string]any{"host": r.Host, "port": r.Port}, Details: Details{TCP: r}}
}

func (c *TCP) Handler(dial func(ctx context.Context, network, address string) (net.Conn, error), relay func(ctx context.Context, a, b net.Conn)) func(context.Context, net.Conn, string, string, uint32, func(context.Context, facts.Event) error) {
	return func(ctx context.Context, conn net.Conn, _, host string, port uint32, gate func(context.Context, facts.Event) error) {
		if c.Claim(host, port) < 0 || gate(ctx, facts.Capture((&TCPFacts{Host: host, Port: port}).Describe(), nil)) != nil {
			return
		}
		upstream, err := dial(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
		if err != nil {
			return
		}
		relay(ctx, conn, upstream)
	}
}
