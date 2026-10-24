package sandbox

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"maps"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	// MaxShellSessions bounds the shells open at once.
	MaxShellSessions = 8
	// MaxShellChunk bounds the output one poll returns.
	MaxShellChunk = 64 << 10
	// MaxShellBuffer bounds the output a shell holds until polls acknowledge it.
	MaxShellBuffer = 1 << 20

	shellTerminal     = "xterm-256color"
	maxShellInput     = 64 << 10
	maxTerminalSize   = 1000
	shellPollTimeout  = 25 * time.Second
	shellIdleTimeout  = 2 * time.Minute
	shellWriteTimeout = 10 * time.Second
)

var ErrShellGone = errors.New("the shell session ended or does not exist")

type ShellInput struct {
	Action string `json:"action"`
	ID     string `json:"id"`
	Cursor uint64 `json:"cursor"`
	Data   []byte `json:"data"`
	Cols   uint32 `json:"cols"`
	Rows   uint32 `json:"rows"`
}

type ShellReply struct {
	ID       string `json:"id"`
	Data     []byte `json:"data"`
	Cursor   uint64 `json:"cursor"`
	Closed   bool   `json:"closed"`
	ExitCode *int   `json:"exit_code,omitempty"`
}

// shellSession is one owner terminal on a sandbox. Output stays buffered until a poll
// acknowledges it, and a full buffer pauses the shell rather than dropping output.
type shellSession struct {
	name, owner string
	client      *ssh.Client
	session     *ssh.Session
	stdin       io.Writer
	idle        *time.Timer

	mu      sync.Mutex
	changed chan struct{} // Closed and replaced on every change.
	output  []byte
	start   uint64 // The cursor of output[0].
	ended   bool
	exit    *int
}

// Shell serves the owner's terminals. A session belongs to the owner session and the
// sandbox name that opened it, and is removed when closed or idle.
func (svc *Service) Shell(ctx context.Context, owner, name string, in ShellInput) (ShellReply, error) {
	switch in.Action {
	case "open":
		return svc.openShell(ctx, owner, name, in)
	case "poll", "input", "resize", "close":
	default:
		return ShellReply{}, fmt.Errorf("unknown shell action %q", in.Action)
	}
	svc.mu.Lock()
	s := svc.shells[in.ID]
	svc.mu.Unlock()
	if s == nil || s.name != name || s.owner != owner {
		return ShellReply{}, ErrShellGone
	}
	s.idle.Reset(shellIdleTimeout)
	reply := ShellReply{ID: in.ID, Data: []byte{}}
	switch in.Action {
	case "poll":
		// An ended session stays until closed or idle, so a lost final reply can be polled again.
		polled, err := s.poll(ctx, in.Cursor)
		s.idle.Reset(shellIdleTimeout)
		polled.ID = in.ID
		return polled, err
	case "close":
		svc.dropShell(in.ID, s)
		reply.Closed = true
		return reply, nil
	}
	if in.Action == "resize" && !validTerminal(in.Cols, in.Rows) {
		return ShellReply{}, fmt.Errorf("terminal size must be 1-%d columns and rows", maxTerminalSize)
	}
	if len(in.Data) > maxShellInput {
		return ShellReply{}, fmt.Errorf("shell input is limited to %d bytes per call", maxShellInput)
	}
	// A sandbox that stops reading cannot hold the request; its shell is closed instead.
	stalled := time.AfterFunc(shellWriteTimeout, s.close)
	defer stalled.Stop()
	if in.Action == "resize" {
		return reply, s.session.WindowChange(int(in.Rows), int(in.Cols))
	}
	_, err := s.stdin.Write(in.Data)
	return reply, err
}

func validTerminal(cols, rows uint32) bool {
	return cols > 0 && rows > 0 && cols <= maxTerminalSize && rows <= maxTerminalSize
}

// openShell starts a login shell as the Monitor on a boot that attests the enrolled sandbox.
func (svc *Service) openShell(ctx context.Context, owner, name string, in ShellInput) (ShellReply, error) {
	if !validTerminal(in.Cols, in.Rows) {
		return ShellReply{}, fmt.Errorf("terminal size must be 1-%d columns and rows", maxTerminalSize)
	}
	boot := svc.monitor.Boot(name)
	if boot == (Boot{}) {
		return ShellReply{}, errors.New("enroll this sandbox from the console to open its shell")
	}
	id := rand.Text()
	svc.mu.Lock()
	if len(svc.shells) >= MaxShellSessions {
		svc.mu.Unlock()
		return ShellReply{}, fmt.Errorf("at most %d shells can be open; close one first", MaxShellSessions)
	}
	if svc.shells == nil {
		svc.shells = map[string]*shellSession{}
	}
	svc.shells[id] = nil // Reserved until connected.
	svc.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, sandboxConnectTimeout)
	defer cancel()
	s, stdout, err := svc.startShell(ctx, owner, name, boot, in)
	svc.mu.Lock()
	if err != nil {
		delete(svc.shells, id)
	} else {
		s.idle = time.AfterFunc(shellIdleTimeout, func() { svc.dropShell(id, s) })
		svc.shells[id] = s
	}
	svc.mu.Unlock()
	if err != nil {
		return ShellReply{}, err
	}
	go s.relay(stdout)
	return ShellReply{ID: id, Data: []byte{}}, nil
}

func (svc *Service) startShell(ctx context.Context, owner, name string, boot Boot, in ShellInput) (*shellSession, io.Reader, error) {
	client, err := svc.connect(ctx, boot, svc.monitor.HostKey())
	if err != nil {
		return nil, nil, err
	}
	// Closing the connection also ends a session setup the sandbox never answers.
	stop := context.AfterFunc(ctx, func() { client.Close() })
	s := &shellSession{name: name, owner: owner, client: client, changed: make(chan struct{})}
	s.session, err = client.NewSession()
	var stdout io.Reader
	if err == nil {
		s.stdin, err = s.session.StdinPipe()
	}
	if err == nil {
		stdout, err = s.session.StdoutPipe()
	}
	if err == nil {
		if err = s.session.RequestPty(shellTerminal, int(in.Rows), int(in.Cols), ssh.TerminalModes{}); err != nil {
			err = fmt.Errorf("sandbox refused a terminal; enroll it to unlock its workspace: %w", err)
		}
	}
	if err == nil {
		err = s.session.Shell()
	}
	if !stop() {
		err = errors.Join(err, context.Cause(ctx))
	}
	if err != nil {
		client.Close()
		return nil, nil, err
	}
	return s, stdout, nil
}

func (svc *Service) dropShell(id string, s *shellSession) {
	svc.mu.Lock()
	if svc.shells[id] == s {
		delete(svc.shells, id)
	}
	svc.mu.Unlock()
	s.close()
}

// CloseShells closes every open shell; one still connecting stays unreachable until idle.
func (svc *Service) CloseShells() {
	svc.mu.Lock()
	shells := maps.Clone(svc.shells)
	svc.mu.Unlock()
	for id, s := range shells {
		if s != nil {
			svc.dropShell(id, s)
		}
	}
}

// signal wakes waiters; the caller holds mu.
func (s *shellSession) signal() {
	close(s.changed)
	s.changed = make(chan struct{})
}

func (s *shellSession) close() {
	s.mu.Lock()
	s.ended = true
	s.signal()
	s.mu.Unlock()
	s.idle.Stop()
	s.client.Close()
}

func (s *shellSession) relay(stdout io.Reader) {
	buffer := make([]byte, MaxShellChunk)
	for {
		n, err := stdout.Read(buffer)
		if n > 0 && !s.append(buffer[:n]) || err != nil {
			break
		}
	}
	err := s.session.Wait()
	s.client.Close()
	s.mu.Lock()
	defer s.mu.Unlock()
	var exit *ssh.ExitError
	if !s.ended && err == nil {
		s.exit = new(int)
	} else if !s.ended && errors.As(err, &exit) {
		code := exit.ExitStatus()
		s.exit = &code
	}
	s.ended = true
	s.signal()
}

func (s *shellSession) append(p []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for len(s.output)+len(p) > MaxShellBuffer && !s.ended {
		changed := s.changed
		s.mu.Unlock()
		<-changed
		s.mu.Lock()
	}
	if s.ended {
		return false
	}
	s.output = append(s.output, p...)
	s.signal()
	return true
}

// poll acknowledges output before cursor, then waits for more output, the end, or a timeout.
func (s *shellSession) poll(ctx context.Context, cursor uint64) (ShellReply, error) {
	timeout := time.NewTimer(shellPollTimeout)
	defer timeout.Stop()
	s.mu.Lock()
	defer s.mu.Unlock()
	if cursor < s.start || cursor-s.start > uint64(len(s.output)) {
		return ShellReply{}, errors.New("shell cursor is outside the unacknowledged output")
	}
	if cursor > s.start {
		s.output = s.output[cursor-s.start:]
		s.start = cursor
		s.signal()
	}
	for wait := true; wait && len(s.output) == 0 && !s.ended; {
		changed := s.changed
		s.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			wait = false
		case <-timeout.C:
			wait = false
		}
		s.mu.Lock()
	}
	data := append([]byte{}, s.output[:min(len(s.output), MaxShellChunk)]...)
	reply := ShellReply{Data: data, Cursor: cursor + uint64(len(data))}
	if s.ended && len(data) == len(s.output) {
		reply.Closed, reply.ExitCode = true, s.exit
	}
	return reply, nil
}
