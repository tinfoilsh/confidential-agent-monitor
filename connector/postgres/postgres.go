package postgres

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync/atomic"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"

	"github.com/tinfoilsh/monitor/connector"
)

const (
	sslAccepted = 'S'
	gssRefused  = 'N'
)

type Postgres struct{ connector.Endpoint }

func (r *Postgres) Serve(s *connector.Stream, e *connector.Env) {
	client, backend, startup, err := startup(s, e.TLS)
	if err != nil {
		log.Printf("postgres startup: %v", err)
		return
	}
	defer client.Close()
	up, err := r.connect(s, e, startup)
	if err != nil {
		log.Printf("postgres: %v", err)
		backend.Send(&pgproto3.ErrorResponse{Severity: "FATAL", Code: "08006", Message: err.Error()})
		backend.Flush()
		return
	}
	defer s.Interrupt(up.Conn)()
	backend.Send(&pgproto3.AuthenticationOk{})
	for name, value := range up.ParameterStatuses {
		backend.Send(&pgproto3.ParameterStatus{Name: name, Value: value})
	}
	backend.Send(&pgproto3.BackendKeyData{ProcessID: up.PID, SecretKey: up.SecretKey})
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: up.TxStatus})
	if err := backend.Flush(); err != nil {
		return
	}
	relayQueries(s, backend, up)
}

func startup(s *connector.Stream, config *tls.Config) (net.Conn, *pgproto3.Backend, *pgproto3.StartupMessage, error) {
	conn := net.Conn(s)
	for {
		backend := pgproto3.NewBackend(conn, conn)
		msg, err := backend.ReceiveStartupMessage()
		if err != nil {
			return nil, nil, nil, err
		}
		switch msg := msg.(type) {
		case *pgproto3.StartupMessage:
			return conn, backend, msg, nil
		case *pgproto3.SSLRequest:
			if _, err := conn.Write([]byte{sslAccepted}); err != nil {
				return nil, nil, nil, err
			}
			conn = tls.Server(conn, config)
		case *pgproto3.GSSEncRequest:
			if _, err := conn.Write([]byte{gssRefused}); err != nil {
				return nil, nil, nil, err
			}
		default:
			return nil, nil, nil, fmt.Errorf("unsupported startup message %T", msg)
		}
	}
}

func (r *Postgres) connect(s *connector.Stream, e *connector.Env, startup *pgproto3.StartupMessage) (*pgconn.HijackedConn, error) {
	config, err := pgconn.ParseConfig(r.URL.String())
	if err != nil {
		return nil, err
	}
	config.Password, err = r.Password.Value(s.Context)
	if err != nil {
		return nil, err
	}
	config.DialFunc = e.Dialer.DialContext
	for name, value := range startup.Parameters {
		if name != "user" && name != "database" {
			config.RuntimeParams[name] = value
		}
	}
	ctx, cancel := context.WithTimeout(s.Context, connector.DialTimeout)
	defer cancel()
	pg, err := pgconn.ConnectConfig(ctx, config)
	if err != nil {
		return nil, err
	}
	return pg.Hijack()
}

// A refused statement is answered with an error in the client's place, so the session stays usable.
func relayQueries(s *connector.Stream, backend *pgproto3.Backend, up *pgconn.HijackedConn) {
	var status atomic.Uint32
	status.Store(uint32(up.TxStatus))
	done := make(chan struct{})
	defer func() { s.Close(); up.Conn.Close(); <-done }()
	go func() {
		defer close(done)
		defer s.Close()
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
			if err := s.Gate(connector.Event{Postgres: &connector.PostgresLayer{SQL: sql}}); err != nil {
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
