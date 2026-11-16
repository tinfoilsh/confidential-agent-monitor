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

	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"golang.org/x/crypto/ssh"
)

func ParseCLI(config json.RawMessage) (*CLI, error) {
	c := new(CLI)
	return c, facts.DecodeNumbers(config, c)
}

const exitRefused = 126

// CLI runs a host program for each admitted command, with its credentials as environment variables.
type CLI struct {
	Path        string   `json:"path"`
	Stdin       string   `json:"stdin"`
	Credentials []string `json:"credentials"`
}

// Limits bound one command: the git object it reads and how long its output may outlive it.
type Limits struct {
	Stdin     int64
	WaitDelay time.Duration
}

// Handler serves agent sessions under config, the SSH server configuration they reach. name prefixes
// the refusals agents read on stderr.
func (t *CLI) Handler(config *ssh.ServerConfig, secret func(ctx context.Context, name string) (string, error), limits Limits, name string) func(context.Context, net.Conn, string, string, uint32, func(context.Context, facts.Event) error) {
	return func(ctx context.Context, conn net.Conn, _, _ string, _ uint32, gate func(context.Context, facts.Event) error) {
		s := newStream(ctx, conn, gate)
		serveSessions(s, config, func(*sync.WaitGroup) func(ssh.NewChannel) {
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
