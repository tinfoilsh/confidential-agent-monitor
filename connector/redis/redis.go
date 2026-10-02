package redis

import (
	"bufio"
	"io"
	"log"
	"slices"
	"strings"

	"github.com/tidwall/redcon"

	"github.com/tinfoilsh/monitor/connector"
)

const (
	redisTLSScheme   = "rediss"
	redisPort        = "6379"
	redisDefaultUser = "default"
	redisOK          = "+"
)

var containerCommands = []string{
	"ACL", "CLIENT", "CLUSTER", "COMMAND", "CONFIG", "FUNCTION", "LATENCY", "MEMORY",
	"MODULE", "OBJECT", "PUBSUB", "SCRIPT", "SLOWLOG", "XGROUP", "XINFO",
}

type Redis struct{ connector.Endpoint }

func (r *Redis) Serve(s *connector.Stream) {
	defer s.Close()
	u := &r.URL
	up, err := connector.DialURL(s.Dialer, u, redisTLSScheme, redisPort, redisPort)
	if err != nil {
		log.Printf("redis: %v", err)
		return
	}
	defer up.Close()
	user := u.User.Username()
	pass, _ := u.User.Password()
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
		io.Copy(s, replies)
		s.Close()
	}()
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
		if err := s.Gate(connector.Event{Redis: &connector.RedisLayer{Command: commandName(args), Argv: args}}); err != nil {
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
	case len(argv) == 0:
		return ""
	case len(argv) > 1 && slices.Contains(containerCommands, strings.ToUpper(argv[0])):
		return strings.ToUpper(argv[0] + "|" + argv[1])
	}
	return strings.ToUpper(argv[0])
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
