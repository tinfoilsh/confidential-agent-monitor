package redis

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/url"
	"slices"
	"strings"

	"github.com/tidwall/redcon"
	"github.com/tinfoilsh/confidential-agent-monitor/core/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

const (
	redisPort = "6379"
)

var containerCommands = []string{
	"ACL", "CLIENT", "CLUSTER", "COMMAND", "CONFIG", "FUNCTION", "LATENCY", "MEMORY",
	"MODULE", "OBJECT", "PUBSUB", "SCRIPT", "SLOWLOG", "XGROUP", "XINFO",
}

type Redis struct {
	RawURL string `json:"url"`
	User   string `json:"user"`
	url    *url.URL
}

func Parse(config json.RawMessage) (*Redis, error) {
	r := new(Redis)
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
	if u.Scheme != "rediss" {
		return nil, errors.New("Redis requires a rediss:// URL to protect credentials with TLS")
	}
	if r.User != "" {
		u.User = url.User(r.User)
	}
	r.url = u
	return r, nil
}

func (r *Redis) Hosts() []string { return []string{r.url.Hostname()} }

func (r *Redis) Handler(dial func(ctx context.Context, network, address string) (net.Conn, error), password func(context.Context) (string, error)) connector.Serve {
	return func(ctx context.Context, s net.Conn, _ string, _ connector.Target, gate connector.Gate) {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		u := r.url
		address := u.Host
		if u.Port() == "" {
			address = net.JoinHostPort(u.Hostname(), redisPort)
		}
		raw, err := dial(ctx, "tcp", address)
		if err != nil {
			log.Printf("redis: %v", err)
			return
		}
		up := tls.Client(raw, &tls.Config{ServerName: u.Hostname()})
		stop := context.AfterFunc(ctx, func() { up.Close() })
		defer func() { stop(); up.Close() }()
		if err := up.HandshakeContext(ctx); err != nil {
			log.Printf("redis: %v", err)
			return
		}
		user := u.User.Username()
		pass, err := password(ctx)
		if err != nil {
			log.Printf("credential: %v", err)
			return
		}
		replies := bufio.NewReader(up)
		if pass != "" {
			if _, err := up.Write(encode(authArgs(user, pass))); err != nil {
				return
			}
			line, err := replies.ReadString('\n')
			if err != nil || !strings.HasPrefix(line, "+") {
				log.Printf("redis upstream refused the stored credential: %q %v", line, err)
				return
			}
		}
		pumped := make(chan struct{})
		go func() { defer close(pumped); io.Copy(s, replies); cancel(); s.Close() }()
		defer func() { cancel(); s.Close(); <-pumped }()
		commands := redcon.NewReader(s)
		for {
			cmd, err := commands.ReadCommand()
			if err != nil {
				return
			}
			args := make([]string, len(cmd.Args))
			for i, arg := range cmd.Args {
				args[i] = string(arg)
			}
			if err := gate(ctx, facts.Capture((&RedisFacts{Command: commandName(args), Argv: args}).Describe(), nil)); err != nil {
				if _, err := s.Write(redcon.AppendError(nil, "ERR "+err.Error())); err != nil {
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
}

func commandName(argv []string) string {
	switch {
	case len(argv) > 1 && slices.Contains(containerCommands, strings.ToUpper(argv[0])):
		return strings.ToUpper(argv[0] + "|" + argv[1])
	}
	return strings.ToUpper(argv[0])
}

func reauthorize(args [][]byte, user, pass string) ([][]byte, bool) {
	switch strings.ToUpper(string(args[0])) {
	case "AUTH":
		return authArgs(user, pass), true
	case "HELLO":
		if user == "" {
			user = "default"
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

func (v *RedisFacts) Describe() facts.Observation {
	details := Details{Redis: v}
	action := "write"
	if slices.Contains(redisReads, v.Command) {
		action = "read"
	}
	return facts.Observation{Operation: &facts.Operation{Action: action}, Title: strings.Join(v.Argv[:min(2, len(v.Argv))], " "), Parameters: map[string]any{"command": v.Command, "argv": v.Argv}, Details: details}
}

var redisReads = strings.Fields(`
	AUTH HELLO PING ECHO SELECT QUIT
	MULTI EXEC DISCARD WATCH UNWATCH
	SUBSCRIBE PSUBSCRIBE UNSUBSCRIBE PUNSUBSCRIBE
	INFO DBSIZE TIME
	COMMAND COMMAND|COUNT COMMAND|DOCS COMMAND|INFO COMMAND|LIST COMMAND|GETKEYS COMMAND|GETKEYSANDFLAGS
	CLIENT|SETNAME CLIENT|SETINFO CLIENT|GETNAME CLIENT|ID CLIENT|INFO
	TYPE TTL PTTL EXISTS KEYS SCAN RANDOMKEY DUMP
	OBJECT|ENCODING OBJECT|FREQ OBJECT|IDLETIME OBJECT|REFCOUNT
	GET MGET GETRANGE STRLEN GETBIT BITCOUNT PFCOUNT
	HGET HMGET HGETALL HKEYS HVALS HLEN HEXISTS HSCAN
	LRANGE LLEN LINDEX LPOS
	SMEMBERS SISMEMBER SMISMEMBER SCARD SSCAN
	ZRANGE ZRANGEBYSCORE ZREVRANGE ZREVRANGEBYSCORE ZSCORE ZMSCORE ZCARD ZCOUNT ZRANK ZREVRANK ZSCAN
	XRANGE XREVRANGE XREAD XLEN XINFO|CONSUMERS XINFO|GROUPS XINFO|STREAM
	GEOPOS GEODIST GEOSEARCH
`)
