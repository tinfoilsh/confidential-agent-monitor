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

type Limits struct {
	Streams, Upstreams int
	Handshake          time.Duration
	Credential, Sign   time.Duration
	Connections, Idle  int
	PoolIdle           time.Duration
	Read, ServeIdle    time.Duration
	Drain              time.Duration
}

type dialFunc func(context.Context) (net.Conn, error)

func (dial dialFunc) transport(l Limits) *http.Transport {
	return &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dial(ctx)
	}, MaxConnsPerHost: l.Connections, MaxIdleConnsPerHost: l.Idle, IdleConnTimeout: l.PoolIdle}
}

const (
	maxMessage = 4 << 20
	maxHeader  = 16 << 10
)

const readyPath = "/_monitor/ready"

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

func serveRPC(ctx context.Context, ln net.Listener, handler http.Handler, l Limits) error {
	return netx.ServeListener(ctx, ln, &http.Server{Handler: handler, ReadHeaderTimeout: l.Read, IdleTimeout: l.ServeIdle, MaxHeaderBytes: maxHeader})
}
