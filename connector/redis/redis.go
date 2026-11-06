package redis

import (
	"bufio"
	"errors"
	"io"
	"log"
	"slices"
	"strings"

	"github.com/tidwall/redcon"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/facts"
)

var Kind = connector.Kind{Parse: parseRedis, New: func() connector.Server { return new(Redis) }}

func parseRedis(source connector.Setup) (connector.Prepared, error) {
	c := new(redisSetup)
	if err := connector.ParseSetup(source, c, &c.Semantics, &c.Semantics); err != nil {
		return connector.Prepared{}, err
	}
	if err := c.validate(); err != nil {
		return connector.Prepared{}, err
	}
	return connector.Prepared{Source: source, Value: c, SecretNames: []string{"password"}}, nil
}

// Redis keeps one immutable setup for each admitted stream.
type Redis struct{ connector.Slot[redisSetup] }

const (
	redisPort = "6379"
)

var containerCommands = []string{
	"ACL", "CLIENT", "CLUSTER", "COMMAND", "CONFIG", "FUNCTION", "LATENCY", "MEMORY",
	"MODULE", "OBJECT", "PUBSUB", "SCRIPT", "SLOWLOG", "XGROUP", "XINFO",
}

type redisSetup struct{ connector.Endpoint }

func (r *redisSetup) validate() error {
	if err := r.Endpoint.Parse(); err != nil {
		return err
	}
	if r.URL.Scheme != "rediss" {
		return errors.New("Redis requires a rediss:// URL to protect credentials with TLS")
	}
	return nil
}

func (owner *Redis) Serve(s *connector.Stream, e *connector.Env) {
	captured := owner.Load()
	if captured == nil {
		return
	}
	r := captured.Value
	r.Secrets = captured.Secrets

	u := &r.URL
	up, err := connector.DialURL(s.Context, e.Dialer, u, "rediss", redisPort, redisPort)
	if err != nil {
		log.Printf("redis: %v", err)
		return
	}
	defer s.Interrupt(up)()
	user := u.User.Username()
	pass, err := r.Secret(s.Context, "password")
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
	defer connector.PumpReplies(s, func() { io.Copy(s, replies) })()
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
		if err := s.Gate(s.Context, r.Capture((&Request{Command: commandName(args), Argv: args}).Describe())); err != nil {
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

type Request RedisFacts

func (v *Request) Describe() (facts.Facts, error) {
	details := Details{Redis: (*RedisFacts)(v)}
	action := "write"
	if slices.Contains(redisReads, v.Command) {
		action = "read"
	}
	return facts.Facts{Operation: &facts.Operation{Action: action}, Title: strings.Join(v.Argv[:min(2, len(v.Argv))], " "), Parameters: map[string]any{"command": v.Command, "argv": v.Argv}, Details: details}, nil
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
