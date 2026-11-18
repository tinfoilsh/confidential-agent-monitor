package session

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/core/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"golang.org/x/crypto/ssh"
)

func ParseCLI(config json.RawMessage) (*CLI, error) {
	c := new(CLI)
	return c, facts.DecodeNumbers(config, c)
}

const exitRefused = 126

type CLI struct {
	Path        string   `json:"path"`
	Stdin       string   `json:"stdin"`
	Credentials []string `json:"credentials"`
}

type Limits struct {
	Stdin     int64
	WaitDelay time.Duration
}

func (t *CLI) Handler(host ssh.Signer, secret func(ctx context.Context, name string) (string, error), limits Limits, name string) connector.Serve {
	return func(ctx context.Context, conn net.Conn, _ string, _ connector.Target, gate connector.Gate) {
		s := newStream(ctx, conn, gate)
		serveSessions(s, host, func(*sync.WaitGroup) func(ssh.NewChannel) {
			return func(nc ssh.NewChannel) { t.session(s, nc, secret, limits, name) }
		})
	}
}

func (t *CLI) session(s *stream, nc ssh.NewChannel, secret func(context.Context, string) (string, error), limits Limits, name string) {
	ch, reqs, err := nc.Accept()
	if err != nil {
		return
	}
	defer ch.Close()
	for r := range reqs {
		e := eventForSSH(r)
		if r.Type != requestExec || e.Command == nil {
			r.Reply(false, nil)
			continue
		}
		r.Reply(true, nil)
		var stdin []byte
		if t.Stdin == "git" {
			stdin, _ = io.ReadAll(io.LimitReader(ch, limits.Stdin))
			e.Payload = gitObject(stdin)
		}
		status := exitRefused
		if err := s.gate(s.ctx, facts.Capture(e.Describe(""), nil)); err != nil {
			fmt.Fprintf(ch.Stderr(), "%s: %v\n", name, err)
		} else {
			status = t.execute(s.ctx, secret, limits.WaitDelay, e.Command.Argv, io.MultiReader(bytes.NewReader(stdin), ch), ch)
		}
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(status)}))
		return
	}
}

func (t *CLI) execute(ctx context.Context, secret func(context.Context, string) (string, error), waitDelay time.Duration, args []string, stdin io.Reader, ch ssh.Channel) int {
	cmd := exec.CommandContext(ctx, t.Path, args[1:]...)
	cmd.WaitDelay = waitDelay
	cmd.Env = []string{}
	for _, name := range t.Credentials {
		value, err := secret(ctx, name)
		if err != nil {
			log.Printf("cli credential: %v", err)
			return exitRefused
		}
		cmd.Env = append(cmd.Env, name+"="+value)
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = stdin, ch, ch.Stderr()
	err := cmd.Run()
	var exit *exec.ExitError
	switch {
	case err == nil:
		return 0
	case errors.As(err, &exit):
		return exit.ExitCode()
	}
	log.Printf("%s: %v", t.Path, err)
	return exitRefused
}

func gitObject(b []byte) *GitFacts {
	header, message, _ := bytes.Cut(b, []byte("\n\n"))
	object := &GitFacts{Message: string(message), Parents: []string{}}
	for line := range strings.SplitSeq(string(header), "\n") {
		key, value, _ := strings.Cut(line, " ")
		switch key {
		case "tree":
			object.Type, object.Tree = "commit", value
		case "object":
			object.Type, object.Object = "tag", value
		case "type":
			object.ObjectType = value
		case "parent":
			object.Parents = append(object.Parents, value)
		case "tag":
			object.Tag = value
		case "author":
			object.Author = value
		case "committer":
			object.Committer = value
		case "tagger":
			object.Tagger = value
		}
	}
	if object.Type == "" {
		return nil
	}
	return object
}
