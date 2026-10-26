package session

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strings"
	"sync"
	"time"

	"github.com/tinfoilsh/monitor/connector"
	"golang.org/x/crypto/ssh"
)

var CLIDefinition = connector.Definition{HostKey: true, Parse: parseCLI, New: func() connector.Server { return new(CLI) }}

func parseCLI(source connector.Setup) (connector.Prepared, error) {
	c := new(cliSetup)
	if err := connector.ParseSetup(source, c, &c.Semantics, &c.Semantics); err != nil {
		return connector.Prepared{}, err
	}
	names, err := c.Declarations()
	return connector.Prepared{Source: source, Value: c, Secrets: names}, err
}

// CLI keeps one immutable setup for each admitted stream.
type CLI struct{ connector.Slot[cliSetup] }

const (
	maxStdinBytes = 1 << 20
	exitRefused   = 126
)

type cliSetup struct {
	connector.SecretConfig
	Path  string `json:"path"`
	Stdin string `json:"stdin"`
}

func (owner *CLI) Serve(s *connector.Stream, e *connector.Env) {
	captured := owner.Load()
	if captured == nil {
		return
	}
	t := captured.Value
	t.Secrets = captured.Secrets

	chans, err := innerSSH(s, e.HostKey)
	if err != nil {
		return
	}
	var workers sync.WaitGroup
	defer func() { s.Close(); workers.Wait() }()
	for nc := range chans {
		if nc.ChannelType() != channelSession {
			nc.Reject(ssh.Prohibited, "only session channels are served")
			continue
		}
		ch, reqs, err := nc.Accept()
		if err != nil {
			return
		}
		workers.Go(func() { t.session(s, ch, reqs) })
	}
}

func (t *cliSetup) session(s *connector.Stream, ch ssh.Channel, reqs <-chan *ssh.Request) {
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
			stdin, _ = io.ReadAll(io.LimitReader(ch, maxStdinBytes))
			e.Payload = gitObject(stdin)
		}
		status := exitRefused
		if err := s.Gate(s.Context, t.Event((e).Describe(""))); err != nil {
			fmt.Fprintf(ch.Stderr(), "monitor: %v\n", err)
		} else {
			status = t.execute(s.Context, e.Command.Argv, io.MultiReader(bytes.NewReader(stdin), ch), ch)
		}
		ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(status)}))
		return
	}
}

func (t *cliSetup) execute(ctx context.Context, args []string, stdin io.Reader, ch ssh.Channel) int {
	cmd := exec.CommandContext(ctx, t.Path, args[1:]...)
	cmd.WaitDelay = time.Second
	cmd.Env = []string{}
	for name, v := range t.Secrets {
		value, err := v.Value(ctx)
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
