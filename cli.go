package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strings"

	"golang.org/x/crypto/ssh"
)

const (
	maxStdinBytes     = 1 << 20
	exitRefused       = 126
	stdinGit          = "git"
	requestExitStatus = "exit-status"
	objectCommit      = "commit"
	objectTag         = "tag"
)

type cliRelay struct {
	Path  string            `yaml:"path"`
	Env   map[string]string `yaml:"env"`
	Stdin string            `yaml:"stdin"`
}

// serve runs the configured binary with argv from the parsed exec string and env from the config alone.
func (t *cliRelay) serve(cc *channelConn) {
	defer cc.Close()
	inner, chans, reqs, err := ssh.NewServerConn(cc, cc.m.inner)
	if err != nil {
		return
	}
	defer inner.Close()
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != channelSession {
			nc.Reject(ssh.Prohibited, "only session channels are served")
			continue
		}
		ch, reqs, err := nc.Accept()
		if err != nil {
			return
		}
		go t.session(cc, ch, reqs)
	}
}

func (t *cliRelay) session(cc *channelConn, ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	for r := range reqs {
		e := sshEvent(r)
		if r.Type != requestExec || e.Command == nil {
			r.Reply(false, nil)
			continue
		}
		r.Reply(true, nil)
		var stdin []byte
		if t.Stdin == stdinGit {
			stdin, _ = io.ReadAll(io.LimitReader(ch, maxStdinBytes))
			e.Payload = gitObject(stdin)
		}
		status := exitRefused
		if err := cc.gate(e); err != nil {
			fmt.Fprintf(ch.Stderr(), "monitor: %v\n", err)
		} else {
			status = t.execute(e.Command.Argv, io.MultiReader(bytes.NewReader(stdin), ch), ch)
		}
		ch.SendRequest(requestExitStatus, false, ssh.Marshal(struct{ Status uint32 }{uint32(status)}))
		return
	}
}

func (t *cliRelay) execute(args []string, stdin io.Reader, ch ssh.Channel) int {
	cmd := exec.Command(t.Path, args[1:]...)
	cmd.Env = []string{}
	for name, value := range t.Env {
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

// gitObject is the payload layer for a commit or tag as git hands it to a signing program.
func gitObject(b []byte) *gitLayer {
	header, message, _ := bytes.Cut(b, []byte("\n\n"))
	object := &gitLayer{Message: string(message), Parents: []string{}}
	for line := range strings.SplitSeq(string(header), "\n") {
		key, value, _ := strings.Cut(line, " ")
		switch key {
		case "tree":
			object.Type, object.Tree = objectCommit, value
		case "object":
			object.Type, object.Object = objectTag, value
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
