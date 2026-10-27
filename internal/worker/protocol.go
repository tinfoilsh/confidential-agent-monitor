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

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/facts"
)

// DialFunc opens a private connection. Remote implementations must authenticate
// and encrypt it in both directions.
type DialFunc func(context.Context) (net.Conn, error)

func (dial DialFunc) Transport() *http.Transport {
	return &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dial(ctx)
	}, MaxConnsPerHost: maxRPCConnections, MaxIdleConnsPerHost: maxIdleRPCConnections, IdleConnTimeout: idleRPCTimeout}
}

const (
	maxMessage            = 4 << 20
	maxRPCConnections     = 32
	maxIdleRPCConnections = 8
	idleRPCTimeout        = 30 * time.Second
	rpcReadTimeout        = 10 * time.Second
)

const protocolVersion = 9
const readyPath = "/_monitor/ready"

type bootstrap struct {
	connector.Setup
	Version  int                     `json:"version"`
	Protocol string                  `json:"kind"`
	Settings json.RawMessage         `json:"settings,omitempty"`
	Secrets  map[string]secretHandle `json:"secrets,omitempty"`
	HostKey  []byte                  `json:"host_key,omitempty"`
}

type secretHandle struct {
	Configured  bool   `json:"configured"`
	Placeholder string `json:"placeholder"`
}

const streamHeader = "X-Monitor-Session"

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
func readRequest(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	control := http.NewResponseController(w)
	if err := control.SetReadDeadline(time.Now().Add(rpcReadTimeout)); err != nil {
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

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) {
	// Drain the handshake prefix, then leave net/http's connection reader behind.
	// A later protocol read deadline must not cancel the hijacked request context.
	if buffered := c.reader.Buffered(); buffered > 0 {
		return c.reader.Read(b[:min(len(b), buffered)])
	}
	return c.Conn.Read(b)
}

func (c *bufferedConn) CloseWrite() error {
	if writer, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return writer.CloseWrite()
	}
	return errors.New("connection does not support half-close")
}

// connect bounds dialing and the HTTP handshake, then returns an untimed stream.
func connect(ctx context.Context, dial DialFunc, r *http.Request, status int) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, connector.DialTimeout)
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
	if err != nil || resp.StatusCode != status || status == http.StatusSwitchingProtocols && resp.Header.Get("Upgrade") != "monitor-connector" {
		conn.Close()
		return nil, errors.New("connector connection refused")
	}
	if ctx.Err() != nil {
		conn.Close()
		return nil, ctx.Err()
	}
	return &bufferedConn{Conn: conn, reader: reader}, nil
}

func Accept(w http.ResponseWriter, r *http.Request) (net.Conn, error) {
	if r.Header.Get("Upgrade") != "monitor-connector" {
		return nil, errors.New("connector upgrade required")
	}
	c, rw, err := w.(http.Hijacker).Hijack()
	if err != nil {
		return nil, err
	}
	if _, err := rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: monitor-connector\r\n\r\n"); err != nil {
		c.Close()
		return nil, err
	}
	if err := rw.Flush(); err != nil {
		c.Close()
		return nil, err
	}
	return &bufferedConn{Conn: c, reader: rw.Reader}, nil
}

// Worker RPC has stricter header and idle bounds than arbitrary protocol HTTP.
func serveRPC(ctx context.Context, ln net.Listener, handler http.Handler) error {
	return connector.ServeListener(ctx, ln, &http.Server{Handler: handler,
		ReadHeaderTimeout: rpcReadTimeout, IdleTimeout: time.Minute, MaxHeaderBytes: 16 << 10})
}
