package postgres

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync/atomic"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

const (
	sslAccepted = 'S'
	gssRefused  = 'N'
)

type Postgres struct {
	RawURL string `json:"url"`
	User   string `json:"user"`
	url    *url.URL
}

// Parse validates a destination whose password is the "password" credential.
func Parse(config json.RawMessage) (*Postgres, error) {
	r := new(Postgres)
	if err := facts.DecodeNumbers(config, r); err != nil {
		return nil, err
	}
	u, err := url.Parse(r.RawURL)
	switch {
	case err != nil:
		return nil, err
	case u.Scheme == "" || u.Host == "":
		return nil, errors.New("destination requires a URL with a scheme and host")
	}
	if _, set := u.User.Password(); set || u.Query().Has("password") {
		return nil, errors.New("put the password in the service's password credential, not the URL")
	}
	if r.User != "" {
		u.User = url.User(r.User)
	}
	r.url = u
	return r, nil
}

func (r *Postgres) Hosts() []string { return []string{r.url.Hostname()} }

// Handler authenticates upstream with the stored password and relays each admitted statement.
// serverTLS answers a client's SSLRequest for the stream's host; timeout bounds the upstream connection.
func (r *Postgres) Handler(dial func(ctx context.Context, network, address string) (net.Conn, error), password func(context.Context) (string, error), serverTLS func(ctx context.Context, host string) *tls.Config, timeout time.Duration) func(context.Context, net.Conn, string, string, uint32, func(context.Context, facts.Event) error) {
	return func(ctx context.Context, s net.Conn, _, host string, _ uint32, gate func(context.Context, facts.Event) error) {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		backend, startup, err := startup(s, serverTLS(ctx, host))
		if err != nil {
			log.Printf("postgres startup: %v", err)
			return
		}
		up, err := r.connect(ctx, dial, password, timeout, startup)
		if err != nil {
			log.Printf("postgres: %v", err)
			backend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "08006", Message: err.Error()})
			backend.Flush()
			return
		}
		stop := context.AfterFunc(ctx, func() { up.Conn.Close() })
		defer func() { stop(); up.Conn.Close() }()
		backend.Send(&pgproto3.AuthenticationOk{})
		for name, value := range up.ParameterStatuses {
			backend.Send(&pgproto3.ParameterStatus{Name: name, Value: value})
		}
		backend.Send(&pgproto3.BackendKeyData{ProcessID: up.PID, SecretKey: up.SecretKey})
		backend.Send(&pgproto3.ReadyForQuery{TxStatus: up.TxStatus})
		if err := backend.Flush(); err != nil {
			return
		}
		relayQueries(ctx, func() { cancel(); s.Close() }, gate, backend, up)
	}
}

func startup(s net.Conn, config *tls.Config) (*pgproto3.Backend, *pgproto3.StartupMessage, error) {
	conn := s
	for {
		backend := pgproto3.NewBackend(conn, conn)
		msg, err := backend.ReceiveStartupMessage()
		if err != nil {
			return nil, nil, err
		}
		switch msg := msg.(type) {
		case *pgproto3.StartupMessage:
			return backend, msg, nil
		case *pgproto3.SSLRequest:
			if _, err := conn.Write([]byte{sslAccepted}); err != nil {
				return nil, nil, err
			}
			conn = tls.Server(conn, config)
		case *pgproto3.GSSEncRequest:
			if _, err := conn.Write([]byte{gssRefused}); err != nil {
				return nil, nil, err
			}
		default:
			return nil, nil, fmt.Errorf("unsupported startup message %T", msg)
		}
	}
}

func (r *Postgres) connect(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), password func(context.Context) (string, error), timeout time.Duration, startup *pgproto3.StartupMessage) (*pgconn.HijackedConn, error) {
	config, err := pgconn.ParseConfig(r.url.String())
	if err != nil {
		return nil, err
	}
	config.Password, err = password(ctx)
	if err != nil {
		return nil, err
	}
	config.DialFunc = dial
	// The dialer resolves hostnames so workers do not need direct DNS access.
	config.LookupFunc = func(_ context.Context, host string) ([]string, error) { return []string{host}, nil }
	for name, value := range startup.Parameters {
		if name != "user" && name != "database" {
			config.RuntimeParams[name] = value
		}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	pg, err := pgconn.ConnectConfig(ctx, config)
	if err != nil {
		return nil, err
	}
	return pg.Hijack()
}

// A refused statement is answered with an error in the client's place, so the session stays usable.
func relayQueries(ctx context.Context, end func(), gate func(context.Context, facts.Event) error, backend *pgproto3.Backend, up *pgconn.HijackedConn) {
	var status atomic.Uint32
	status.Store(uint32(up.TxStatus))
	pumped := make(chan struct{})
	defer func() { end(); <-pumped }()
	go func() {
		defer close(pumped)
		defer end()
		for {
			msg, err := up.Frontend.Receive()
			if err != nil {
				return
			}
			if ready, ok := msg.(*pgproto3.ReadyForQuery); ok {
				status.Store(uint32(ready.TxStatus))
			}
			backend.Send(msg)
			if err := backend.Flush(); err != nil {
				return
			}
		}
	}()
	for {
		msg, err := backend.Receive()
		if err != nil {
			return
		}
		sql := ""
		switch msg := msg.(type) {
		case *pgproto3.Query:
			sql = msg.String
		case *pgproto3.Parse:
			sql = msg.Query
		}
		if sql != "" {
			if err := gate(ctx, facts.Capture((&PostgresFacts{SQL: sql}).Describe(), nil)); err != nil {
				backend.Send(&pgproto3.ErrorResponse{Severity: "ERROR", Code: "42501", Message: err.Error()})
				if _, simple := msg.(*pgproto3.Query); simple {
					backend.Send(&pgproto3.ReadyForQuery{TxStatus: byte(status.Load())})
				}
				if err := backend.Flush(); err != nil {
					return
				}
				continue
			}
		}
		up.Frontend.Send(msg)
		if err := up.Frontend.Flush(); err != nil {
			return
		}
	}
}

func (v *PostgresFacts) Describe() facts.Observation {
	details := Details{Postgres: v}
	action := "write"
	if plainRead(v.SQL) {
		action = "read"
	}
	return facts.Observation{Operation: &facts.Operation{Action: action}, Title: "Run " + v.SQL, Parameters: map[string]any{"sql": v.SQL}, Details: details}
}

var sqlFirst = regexp.MustCompile(`^\w+`)
var sqlUnsafe = regexp.MustCompile(`(?i)\b(into|for\s+(no\s+key\s+)?(update|share)|for\s+key\s+share|analyze)\b`)

func plainRead(sql string) bool {
	sql = strings.TrimSuffix(strings.TrimSpace(sql), ";")
	return !strings.Contains(sql, ";") && slices.Contains(strings.Fields("SELECT SHOW TABLE VALUES EXPLAIN BEGIN COMMIT ROLLBACK END"), strings.ToUpper(sqlFirst.FindString(sql))) && !sqlUnsafe.MatchString(sql)
}
