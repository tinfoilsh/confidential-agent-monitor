package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/url"
	"strings"

	"github.com/tidwall/redcon"
)

const (
	redisTLSScheme   = "rediss"
	redisPort        = "6379"
	redisDefaultUser = "default"
	redisOK          = "+"
)

// relayRedis authenticates upstream first, then forwards commands with any AUTH or HELLO AUTH
// rewritten to the stored credential, so the client's own password is never sent.
func relayRedis(conn net.Conn, raw string) {
	defer conn.Close()
	u, err := url.Parse(raw)
	if err != nil {
		log.Printf("redis url: %v", err)
		return
	}
	up, err := dialRedis(u)
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
		io.Copy(conn, replies)
		conn.Close()
	}()
	commands := redcon.NewReader(conn)
	for {
		cmd, err := commands.ReadCommand()
		if err != nil {
			return
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

func dialRedis(u *url.URL) (net.Conn, error) {
	address := u.Host
	if u.Port() == "" {
		address = net.JoinHostPort(u.Hostname(), redisPort)
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	switch u.Scheme {
	case redisTLSScheme:
		return (&tls.Dialer{Config: &tls.Config{ServerName: u.Hostname()}}).DialContext(ctx, "tcp", address)
	case "redis":
		return (&net.Dialer{}).DialContext(ctx, "tcp", address)
	}
	return nil, errors.New("redis url scheme must be redis or rediss")
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
