package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

const (
	sslAccepted       = 'S'
	gssRefused        = 'N'
	connectionFailure = "08006"
	severityFatal     = "FATAL"
	startupUser       = "user"
	startupDatabase   = "database"
)

// relayPostgres answers the client's startup itself, then splices it onto a session opened with the stored URL.
func (m *monitor) relayPostgres(conn net.Conn, url string) {
	defer conn.Close()
	client, backend, startup, err := m.startup(conn)
	if err != nil {
		log.Printf("postgres startup: %v", err)
		return
	}
	defer client.Close()
	up, err := connectPostgres(url, startup)
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
	splice(client, up.Conn)
}

func (m *monitor) startup(conn net.Conn) (net.Conn, *pgproto3.Backend, *pgproto3.StartupMessage, error) {
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
			conn = tls.Server(conn, m.tls)
		case *pgproto3.GSSEncRequest:
			if _, err := conn.Write([]byte{gssRefused}); err != nil {
				return nil, nil, nil, err
			}
		default:
			return nil, nil, nil, fmt.Errorf("unsupported startup message %T", msg)
		}
	}
}

// The client's session parameters are kept; its user and database are replaced by the stored URL's.
func connectPostgres(url string, startup *pgproto3.StartupMessage) (*pgconn.HijackedConn, error) {
	config, err := pgconn.ParseConfig(url)
	if err != nil {
		return nil, err
	}
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

func splice(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
}
