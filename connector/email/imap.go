package email

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

const (
	loginTag = "m0"
	imapPort = "993"
)

var imapLiteral = regexp.MustCompile(`\{(\d+)(\+?)\}$`)

// Endpoint is a destination whose password is the "password" credential.
type Endpoint struct {
	RawURL string `json:"url"`
	User   string `json:"user"`
	url    *url.URL
}

func parse(config json.RawMessage) (*Endpoint, error) {
	e := new(Endpoint)
	if err := facts.DecodeNumbers(config, e); err != nil {
		return nil, err
	}
	u, err := url.Parse(e.RawURL)
	switch {
	case err != nil:
		return nil, err
	case u.Scheme == "" || u.Host == "":
		return nil, errors.New("destination requires a URL with a scheme and host")
	}
	if _, set := u.User.Password(); set || u.Query().Has("password") {
		return nil, errors.New("put the password in the service's password credential, not the URL")
	}
	if e.User != "" {
		u.User = url.User(e.User)
	}
	e.url = u
	return e, nil
}

func (e *Endpoint) Hosts() []string { return []string{e.url.Hostname()} }

// dial reaches the destination, over TLS when it uses the secure scheme.
func (e *Endpoint) dial(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error), secure, port, securePort string) (net.Conn, error) {
	u := e.url
	address := u.Host
	if u.Port() == "" {
		if u.Scheme == secure {
			port = securePort
		}
		address = net.JoinHostPort(u.Hostname(), port)
	}
	c, err := dial(ctx, "tcp", address)
	if err != nil || u.Scheme != secure {
		return c, err
	}
	t := tls.Client(c, &tls.Config{ServerName: u.Hostname()})
	if err := t.HandshakeContext(ctx); err != nil {
		c.Close()
		return nil, err
	}
	return t, nil
}

type IMAP struct{ *Endpoint }

func ParseIMAP(config json.RawMessage) (*IMAP, error) {
	e, err := parse(config)
	if err != nil {
		return nil, err
	}
	if e.url.Scheme != "imaps" {
		return nil, errors.New("IMAP requires an imaps:// URL to protect credentials with TLS")
	}
	return &IMAP{e}, nil
}

// Preauthenticated logs in with the stored password and relays commands, each after the gate admits it.
// The caller authenticated each stream, so the agent is greeted "* PREAUTH greeting" and its LOGIN or
// AUTHENTICATE is acknowledged unchecked.
func (r *IMAP) Preauthenticated(dial func(ctx context.Context, network, address string) (net.Conn, error), password func(context.Context) (string, error), greeting string) func(context.Context, net.Conn, string, string, uint32, func(context.Context, facts.Event) error) {
	return func(ctx context.Context, s net.Conn, _, _ string, _ uint32, gate func(context.Context, facts.Event) error) {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		up, err := r.dial(ctx, dial, "imaps", imapPort, imapPort)
		if err != nil {
			log.Printf("imap: %v", err)
			return
		}
		stop := context.AfterFunc(ctx, func() { up.Close() })
		defer func() { stop(); up.Close() }()
		replies := bufio.NewReader(up)
		if _, err := replies.ReadString('\n'); err != nil {
			return
		}
		pass, err := password(ctx)
		if err != nil {
			log.Printf("credential: %v", err)
			return
		}
		quote := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
		fmt.Fprintf(up, "%s LOGIN \"%s\" \"%s\"\r\n", loginTag, quote.Replace(r.url.User.Username()), quote.Replace(pass))
		for {
			line, err := replies.ReadString('\n')
			if err != nil {
				return
			}
			if strings.HasPrefix(line, loginTag+" ") {
				if !strings.HasPrefix(line, loginTag+" OK") {
					log.Printf("imap upstream refused the stored credential: %s", strings.TrimSpace(line))
					return
				}
				break
			}
		}
		fmt.Fprintf(s, "* PREAUTH %s\r\n", greeting)
		pumped := make(chan struct{})
		go func() { defer close(pumped); io.Copy(s, replies); cancel(); s.Close() }()
		defer func() { cancel(); s.Close(); <-pumped }()
		commands := bufio.NewReader(s)
		mailbox := ""
		for {
			line, err := commands.ReadString('\n')
			if err != nil {
				return
			}
			tag, rest, _ := strings.Cut(strings.TrimRight(line, "\r\n"), " ")
			if rest == "" {
				if _, err := io.WriteString(up, line); err != nil {
					return
				}
				continue
			}
			command, args, _ := strings.Cut(rest, " ")
			if strings.EqualFold(command, "UID") {
				command, args, _ = strings.Cut(args, " ")
			}
			command = strings.ToUpper(command)
			switch command {
			case "LOGIN", "AUTHENTICATE":
				fmt.Fprintf(s, "%s OK already authenticated\r\n", tag)
				continue
			case "SELECT", "EXAMINE":
				mailbox = strings.Trim(args, `"`)
			}
			dst := io.Writer(up)
			if err := gate(ctx, facts.Capture((&IMAPFacts{Command: command, Args: args, Mailbox: mailbox}).Describe(), nil)); err != nil {
				fmt.Fprintf(s, "%s NO %v\r\n", tag, err)
				dst = io.Discard
			}
			if err := forwardIMAP(dst, commands, line); err != nil {
				return
			}
		}
	}
}

// A refused command's synchronizing literal never comes, since the client is still waiting for a continuation.
func forwardIMAP(dst io.Writer, src *bufio.Reader, line string) error {
	for {
		if _, err := io.WriteString(dst, line); err != nil {
			return err
		}
		match := imapLiteral.FindStringSubmatch(strings.TrimRight(line, "\r\n"))
		if match == nil || (dst == io.Discard && match[2] == "") {
			return nil
		}
		size, _ := strconv.ParseInt(match[1], 10, 64)
		if _, err := io.CopyN(dst, src, size); err != nil {
			return err
		}
		var err error
		if line, err = src.ReadString('\n'); err != nil {
			return err
		}
	}
}

func (v *IMAPFacts) Describe() facts.Observation {
	details := Details{IMAP: v}
	action := ""
	if slices.Contains(strings.Fields("CAPABILITY CHECK ENABLE EXAMINE FETCH ID IDLE LIST LOGOUT LSUB NAMESPACE NOOP SEARCH SELECT STATUS UNSELECT"), v.Command) {
		action = "read"
	}
	if slices.Contains(strings.Fields("APPEND CLOSE COPY CREATE DELETE EXPUNGE MOVE RENAME STORE SUBSCRIBE UNSUBSCRIBE"), v.Command) {
		action = "organize"
	}
	op := &facts.Operation{Action: action}
	return facts.Observation{Operation: op, Title: v.Command + " " + v.Mailbox, Parameters: map[string]any{"mailbox": v.Mailbox, "args": v.Args}, Details: details}
}
