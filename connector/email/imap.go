package email

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/facts"
)

const (
	loginTag = "m0"
)

var imapLiteral = regexp.MustCompile(`\{(\d+)(\+?)\}$`)

type IMAP struct{ connector.Endpoint }

func (r *IMAP) Serve(s *connector.Stream, e *connector.Env) {
	u := &r.URL
	up, err := connector.DialURL(s.Context, e.Dialer, u, "imaps", "143", "993")
	if err != nil {
		log.Printf("imap: %v", err)
		return
	}
	defer s.Interrupt(up)()
	replies := bufio.NewReader(up)
	if _, err := replies.ReadString('\n'); err != nil {
		return
	}
	pass, err := r.Password.Value(s.Context)
	if err != nil {
		log.Printf("credential: %v", err)
		return
	}
	quote := strings.NewReplacer(`\`, `\\`, `"`, `\"`)
	fmt.Fprintf(up, "%s LOGIN \"%s\" \"%s\"\r\n", loginTag, quote.Replace(u.User.Username()), quote.Replace(pass))
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
	fmt.Fprintf(s, "* PREAUTH monitor\r\n")
	defer connector.CopyReplies(s, up, replies)()
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
		if err := s.Gate(&IMAPRequest{Command: command, Args: args, Mailbox: mailbox}); err != nil {
			fmt.Fprintf(s, "%s NO %v\r\n", tag, err)
			dst = io.Discard
		}
		if err := forwardIMAP(dst, commands, line); err != nil {
			return
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

type IMAPRequest struct {
	Command string `json:"command"`
	Args    string `json:"args"`
	Mailbox string `json:"mailbox,omitempty"`
}

func (v *IMAPRequest) Describe(c connector.Context) (facts.Facts, connector.Approval, error) {
	details := map[string]any{"imap": v}
	action := ""
	if slices.Contains(strings.Fields("CAPABILITY CHECK ENABLE EXAMINE FETCH ID IDLE LIST LOGOUT LSUB NAMESPACE NOOP SEARCH SELECT STATUS UNSELECT"), v.Command) {
		action = "read"
	}
	if slices.Contains(strings.Fields("APPEND CLOSE COPY CREATE DELETE EXPUNGE MOVE RENAME STORE SUBSCRIBE UNSUBSCRIBE"), v.Command) {
		action = "organize"
	}
	op := &facts.Operation{Action: action}
	if action == "" {
		op = nil
	}
	return facts.Facts{Operation: op, Title: v.Command + " " + v.Mailbox, Parameters: map[string]any{"mailbox": v.Mailbox, "args": v.Args}, Details: details}, connector.Approval{}, nil
}
