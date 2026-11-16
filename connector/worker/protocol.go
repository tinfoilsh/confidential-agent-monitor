// Package worker runs one connector in another process and carries its private protocol: the host keeps
// the gate, the network, the credentials and the TLS and SSH identities, and the worker asks for each use.
package worker

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/netx"
)

// Limits bound a worker's use of the host. The private protocol's message and header sizes are fixed.
type Limits struct {
	// Streams one process serves at once, and upstream connections it holds open at once.
	Streams, Upstreams int
	// Handshake bounds dialing a stream into the worker or an upstream through the host.
	Handshake time.Duration
	// Credential and Sign bound the worker's wait for a credential value or a host signature.
	Credential, Sign time.Duration
	// Connections and Idle bound the RPC connections either side keeps to the other; PoolIdle closes an unused one.
	Connections, Idle int
	PoolIdle          time.Duration
	// Read bounds receiving an RPC request head or callback payload; ServeIdle closes an RPC connection left idle.
	Read, ServeIdle time.Duration
	// Drain bounds how long a relayed stream's closed peer keeps draining.
	Drain time.Duration
}

// dialFunc opens a private connection between the host and one worker process.
type dialFunc func(context.Context) (net.Conn, error)

func (dial dialFunc) transport(l Limits) *http.Transport {
	return &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dial(ctx)
	}, MaxConnsPerHost: l.Connections, MaxIdleConnsPerHost: l.Idle, IdleConnTimeout: l.PoolIdle}
}

// The private protocol's encoding bounds: one JSON message and one request head.
const (
	maxMessage = 4 << 20
	maxHeader  = 16 << 10
)

const readyPath = "/_monitor/ready"

// bootstrap carries the host's prepared protocol data and the handles of its grants, never their values.
type bootstrap struct {
	Data    json.RawMessage         `json:"data"`
	Secrets map[string]secretHandle `json:"secrets,omitempty"`
	HostKey []byte                  `json:"host_key,omitempty"`
}

type secretHandle struct {
	Configured  bool   `json:"configured"`
	Placeholder string `json:"placeholder"`
}

const (
	streamHeader    = "X-Monitor-Session"
	upgradeProtocol = "monitor-connector"
)

type streamInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Host string `json:"host"`
	Port uint32 `json:"port"`
}

func readBody(r io.Reader) ([]byte, error) {
	raw, err := io.ReadAll(io.LimitReader(r, maxMessage+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxMessage {
		return nil, errors.New("host message exceeds size limit")
	}
	return raw, nil
}

func readJSON(r io.Reader, value any) error {
	raw, err := readBody(r)
	if err != nil {
		return err
	}
	return facts.DecodeNumbers(raw, value)
}

// Bound receipt of a callback's payload, then clear the deadline before Gate or
// a credential provider waits. A completed request may require owner approval.
func readRequest(w http.ResponseWriter, r *http.Request, timeout time.Duration) ([]byte, error) {
	control := http.NewResponseController(w)
	if err := control.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	raw, err := readBody(r.Body)
	if err == nil {
		err = control.SetReadDeadline(time.Time{})
	}
	return raw, err
}

func call(ctx context.Context, transport http.RoundTripper, path string, input, output any) error {
	raw, err := json.Marshal(input)
	if err != nil {
		return err
	}
	if len(raw) > maxMessage {
		return errors.New("host message exceeds size limit")
	}
	r, err := http.NewRequestWithContext(ctx, "POST", "http://connector"+path, bytes.NewReader(raw))
	if err != nil {
		return err
	}
	resp, err := transport.RoundTrip(r)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
		return errors.New(string(raw))
	}
	if output == nil {
		_, err = io.Copy(io.Discard, io.LimitReader(resp.Body, maxMessage))
		return err
	}
	return readJSON(resp.Body, output)
}

func reply(w http.ResponseWriter, value any, err error) {
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(value)
}

type certificate struct {
	Chain [][]byte
	Key   []byte
}
type signing struct {
	Data      []byte
	Algorithm string
}

// connect bounds dialing and the HTTP handshake, then returns an untimed stream.
func connect(ctx context.Context, dial dialFunc, r *http.Request, status int, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	conn, err := dial(ctx)
	if err != nil {
		return nil, err
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if err := r.Write(conn); err != nil {
		conn.Close()
		return nil, err
	}
	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, r)
	if err != nil || resp.StatusCode != status || status == http.StatusSwitchingProtocols && resp.Header.Get("Upgrade") != upgradeProtocol {
		conn.Close()
		return nil, errors.New("connector connection refused")
	}
	if ctx.Err() != nil {
		conn.Close()
		return nil, ctx.Err()
	}
	return netx.Buffered(conn, reader), nil
}

func accept(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	if r.Header.Get("Upgrade") != upgradeProtocol {
		return nil, errors.New("connector upgrade required")
	}
	return netx.Hijack(w, "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: "+upgradeProtocol+"\r\n\r\n")
}

// Worker RPC has stricter header and idle bounds than arbitrary protocol HTTP.
func serveRPC(ctx context.Context, ln net.Listener, handler http.Handler, l Limits) error {
	return netx.ServeListener(ctx, ln, &http.Server{Handler: handler, ReadHeaderTimeout: l.Read, IdleTimeout: l.ServeIdle, MaxHeaderBytes: maxHeader})
}
