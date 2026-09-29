package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync/atomic"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
	"github.com/tidwall/redcon"
)

const (
	sslAccepted           = 'S'
	gssRefused            = 'N'
	connectionFailure     = "08006"
	insufficientPrivilege = "42501"
	severityFatal         = "FATAL"
	severityError         = "ERROR"
	startupUser           = "user"
	startupDatabase       = "database"
	redisTLSScheme        = "rediss"
	redisPort             = "6379"
	redisDefaultUser      = "default"
	redisOK               = "+"
)

// postgresRelay is a connection string for pgconn, which parses it when a session opens.
type postgresRelay string

// serve answers the client's startup itself, then relays messages on a session opened with the stored URL.
func (dsn *postgresRelay) serve(cc *channelConn) {
	defer cc.Close()
	client, backend, startup, err := startup(cc)
	if err != nil {
		log.Printf("postgres startup: %v", err)
		return
	}
	defer client.Close()
	up, err := connectPostgres(string(*dsn), startup)
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
	relayQueries(cc, backend, up)
}

func startup(cc *channelConn) (net.Conn, *pgproto3.Backend, *pgproto3.StartupMessage, error) {
	conn := net.Conn(cc)
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
			conn = tls.Server(conn, cc.m.tls)
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

// A refused statement is answered with an error in the client's place, so the session stays usable.
func relayQueries(cc *channelConn, backend *pgproto3.Backend, up *pgconn.HijackedConn) {
	var status atomic.Uint32
	status.Store(uint32(up.TxStatus))
	go func() {
		defer cc.Close()
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
			if err := cc.gate(event{Postgres: &postgresLayer{SQL: sql}}); err != nil {
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

type redisRelay struct{ endpoint }

// serve authenticates upstream first, then forwards each command the policy allows, with any
// AUTH or HELLO AUTH rewritten to the stored credential so the client's own is never sent.
func (r *redisRelay) serve(cc *channelConn) {
	defer cc.Close()
	u := &r.URL
	up, err := dialURL(u, redisTLSScheme, redisPort, redisPort)
	if err != nil {
		log.Printf("redis: %v", err)
		return
	}
	defer up.Close()
	user, pass := u.User.Username(), ""
	if p, ok := u.User.Password(); ok {
		pass = p
	}
	replies := bufio.NewReader(up)
	if pass != "" {
		if _, err := up.Write(encode(authArgs(user, pass))); err != nil {
			return
		}
		line, err := replies.ReadString('\n')
		if err != nil || !strings.HasPrefix(line, redisOK) {
			log.Printf("redis upstream refused the stored credential: %q %v", line, err)
			return
		}
	}
	go func() {
		io.Copy(cc, replies)
		cc.Close()
	}()
	commands := redcon.NewReader(cc)
	for {
		cmd, err := commands.ReadCommand()
		if err != nil {
			return
		}
		args := make([]string, len(cmd.Args))
		for i, arg := range cmd.Args {
			args[i] = string(arg)
		}
		if err := cc.gate(event{Redis: &argvLayer{Argv: args}}); err != nil {
			if _, err := cc.Write(redcon.AppendError(nil, "ERR "+err.Error())); err != nil {
				return
			}
			continue
		}
		out := cmd.Raw
		if pass != "" {
			if args, ok := reauthorize(cmd.Args, user, pass); ok {
				out = encode(args)
			}
		}
		if _, err := up.Write(out); err != nil {
			return
		}
	}
}

func reauthorize(args [][]byte, user, pass string) ([][]byte, bool) {
	if len(args) == 0 {
		return nil, false
	}
	switch strings.ToUpper(string(args[0])) {
	case "AUTH":
		return authArgs(user, pass), true
	case "HELLO":
		if user == "" {
			user = redisDefaultUser
		}
		for i := range args {
			if strings.EqualFold(string(args[i]), "AUTH") && i+2 < len(args) {
				args[i+1], args[i+2] = []byte(user), []byte(pass)
				return args, true
			}
		}
	}
	return nil, false
}

func authArgs(user, pass string) [][]byte {
	if user == "" {
		return [][]byte{[]byte("AUTH"), []byte(pass)}
	}
	return [][]byte{[]byte("AUTH"), []byte(user), []byte(pass)}
}

func encode(args [][]byte) []byte {
	out := redcon.AppendArray(nil, len(args))
	for _, arg := range args {
		out = redcon.AppendBulk(out, arg)
	}
	return out
}
