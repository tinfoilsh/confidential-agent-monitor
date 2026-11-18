package connector

import (
	"context"
	"encoding/json"
	"net"
	"net/http"

	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

type Target struct {
	// Network is "tcp", or "udp" for a stream that carries each datagram after its length.
	Network string
	// Host is empty for a stream addressed by its connection's name.
	Host string
	Port uint32
}

type Gate = func(context.Context, facts.Event) error

type Serve = func(ctx context.Context, conn net.Conn, name string, target Target, gate Gate)

type Instance struct {
	Serve   Serve
	Close   func() error
	Ready   func() error
	Details json.RawMessage
	Control http.Handler
}
