package udp

import (
	"context"
	"io"
	"net"
	"strconv"
	"sync"

	"github.com/tinfoilsh/confidential-agent-monitor/core/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/netx"
)

// The largest payload one IPv4 UDP datagram carries.
const maxDatagram = 65507

type UDPFacts struct {
	Host    string `json:"host"`
	Port    uint32 `json:"port"`
	Payload []byte `json:"payload"`
}

type Details struct {
	UDP *UDPFacts `json:"udp,omitempty"`
}

func (r *UDPFacts) Describe() facts.Observation {
	return facts.Observation{Title: "Send a datagram to " + net.JoinHostPort(r.Host, strconv.Itoa(int(r.Port))),
		Operation:  &facts.Operation{Action: "send"},
		Parameters: map[string]any{"host": r.Host, "port": r.Port}, Details: Details{UDP: r}}
}

func Handler(claim func(connector.Target) int, dial func(ctx context.Context, network, address string) (net.Conn, error)) connector.Serve {
	return func(ctx context.Context, conn net.Conn, _ string, target connector.Target, gate connector.Gate) {
		if claim(target) < 0 {
			return
		}
		agent := netx.Datagrams(conn)
		var upstream net.Conn
		var replies sync.WaitGroup
		defer func() {
			if upstream != nil {
				upstream.Close()
			}
			conn.Close()
			replies.Wait()
		}()
		datagram := make([]byte, maxDatagram)
		for {
			n, err := agent.Read(datagram)
			if err != nil || gate(ctx, facts.Capture((&UDPFacts{Host: target.Host, Port: target.Port, Payload: datagram[:n]}).Describe(), nil)) != nil {
				return
			}
			if upstream == nil {
				if upstream, err = dial(ctx, "udp", net.JoinHostPort(target.Host, strconv.Itoa(int(target.Port)))); err != nil {
					return
				}
				replies.Go(func() { io.Copy(agent, upstream); conn.Close() })
			}
			if _, err := upstream.Write(datagram[:n]); err != nil {
				return
			}
		}
	}
}
