package connector

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"sync/atomic"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

type postgresLayer struct {
	SQL string `json:"sql"`
}

const (
	sslAccepted           = 'S'
	gssRefused            = 'N'
	connectionFailure     = "08006"
	insufficientPrivilege = "42501"
	severityFatal         = "FATAL"
	severityError         = "ERROR"
	startupUser           = "user"
	startupDatabase       = "database"
)

type Postgres string

func (dsn *Postgres) Serve(s *Stream) {
	defer s.Close()
	client, backend, startup, err := startup(s)
	if err != nil {
		log.Printf("postgres startup: %v", err)
		return
	}
	defer client.Close()
	up, err := connectPostgres(s.Dialer, string(*dsn), startup)
	if err != nil {
		log.Printf("postgres: %v", err)
		backend.Send(&pgproto3.ErrorResponse{Severity: severityFatal, Code: connectionFailure, Message: err.Error()})
		backend.Flush()
		return
	}
	defer up.Conn.Close()
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

func startup(s *Stream) (net.Conn, *pgproto3.Backend, *pgproto3.StartupMessage, error) {
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
			conn = tls.Server(conn, s.TLS)
		case *pgproto3.GSSEncRequest:
			if _, err := conn.Write([]byte{gssRefused}); err != nil {
				return nil, nil, nil, err
			}
		default:
			return nil, nil, nil, fmt.Errorf("unsupported startup message %T", msg)
		}
	}
}

func connectPostgres(d *net.Dialer, url string, startup *pgproto3.StartupMessage) (*pgconn.HijackedConn, error) {
	config, err := pgconn.ParseConfig(url)
	if err != nil {
		return nil, err
	}
	config.DialFunc = d.DialContext
	for name, value := range startup.Parameters {
		if name != startupUser && name != startupDatabase {
			config.RuntimeParams[name] = value
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	pg, err := pgconn.ConnectConfig(ctx, config)
	if err != nil {
		return nil, err
	}
	return pg.Hijack()
}

// A refused statement is answered with an error in the client's place, so the session stays usable.
func relayQueries(s *Stream, backend *pgproto3.Backend, up *pgconn.HijackedConn) {
	var status atomic.Uint32
	status.Store(uint32(up.TxStatus))
	go func() {
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
			if err := s.Gate(Event{Postgres: &postgresLayer{SQL: sql}}); err != nil {
				backend.Send(&pgproto3.ErrorResponse{Severity: severityError, Code: insufficientPrivilege, Message: err.Error()})
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
