package connector

import (
	"bufio"
	"io"
	"log"
	"strings"

	"github.com/tidwall/redcon"
)

const (
	redisTLSScheme   = "rediss"
	redisPort        = "6379"
	redisDefaultUser = "default"
	redisOK          = "+"
)

type Redis struct{ endpoint }

// Serve authenticates upstream first, then forwards each command the policy allows, with any
// AUTH or HELLO AUTH rewritten to the stored credential so the client's own is never sent.
func (r *Redis) Serve(s *Stream) {
	defer s.Close()
	u := &r.URL
	up, err := dialURL(u, redisTLSScheme, redisPort, redisPort)
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
		if err := s.Gate(Event{Redis: &argvLayer{Argv: args}}); err != nil {
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
