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
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/core/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/netx"
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

func (c *TCP) Claim(target connector.Target) int {
	if target.Port == 0 || target.Port > maxPort || target.Host == "" {
		return -1
	}
	if len(c.Ports) > 0 && !slices.Contains(c.Ports, target.Port) {
		return -1
	}
	score := -1
	for _, pattern := range c.Hosts {
		if ok, _ := path.Match(strings.ToLower(pattern), strings.ToLower(target.Host)); ok {
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

func (c *TCP) Handler(dial func(ctx context.Context, network, address string) (net.Conn, error), drain time.Duration) connector.Serve {
	return func(ctx context.Context, conn net.Conn, _ string, target connector.Target, gate connector.Gate) {
		if c.Claim(target) < 0 || gate(ctx, facts.Capture((&TCPFacts{Host: target.Host, Port: target.Port}).Describe(), nil)) != nil {
			return
		}
		upstream, err := dial(ctx, "tcp", net.JoinHostPort(target.Host, strconv.Itoa(int(target.Port))))
		if err != nil {
			return
		}
		netx.Relay(ctx, conn, upstream, drain)
	}
}
