package rpc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
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
)

const protocolVersion = 3
const readyPath = "/_monitor/ready"

type bootstrap struct {
	Version  int             `json:"version"`
	Kind     string          `json:"kind"`
	Config   json.RawMessage `json:"config"`
	Settings json.RawMessage `json:"settings,omitempty"`
	Secrets  map[string]bool `json:"secrets,omitempty"`
	HostKey  []byte          `json:"host_key,omitempty"`
}

const sessionHeader = "X-Monitor-Session"

type sessionInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Host string `json:"host"`
	Port uint32 `json:"port"`
}

func readJSON(r io.Reader, value any) error {
	raw, err := io.ReadAll(io.LimitReader(r, maxMessage+1))
	if err != nil {
		return err
	}
	if len(raw) > maxMessage {
		return errors.New("host message exceeds size limit")
	}
	return facts.DecodeNumbers(raw, value)
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

type event struct {
	Type int             `json:"type"`
	Data json.RawMessage `json:"data"`
}

func encode(d connector.Definition, r connector.Request) (event, error) {
	for i, sample := range d.Requests {
		if reflect.TypeOf(sample) == reflect.TypeOf(r) && !reflect.ValueOf(r).IsNil() {
			raw, err := json.Marshal(r)
			return event{i, raw}, err
		}
	}
	return event{}, fmt.Errorf("unregistered request %T", r)
}

func decode(d connector.Definition, e event) (connector.Request, error) {
	if e.Type < 0 || e.Type >= len(d.Requests) || len(e.Data) == 0 || string(e.Data) == "null" {
		return nil, errors.New("invalid connector request")
	}
	r := reflect.New(reflect.TypeOf(d.Requests[e.Type]).Elem()).Interface().(connector.Request)
	return r, facts.DecodeNumbers(e.Data, r)
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedConn) Read(b []byte) (int, error) { return c.reader.Read(b) }

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
