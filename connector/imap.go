package connector

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"regexp"
	"strconv"
	"strings"
)

type imapLayer struct {
	Command string `json:"command"`
	Args    string `json:"args"`
	Mailbox string `json:"mailbox,omitempty"`
}

const (
	imapTLSScheme = "imaps"
	imapPort      = "143"
	imapsPort     = "993"
	loginTag      = "m0"
)

var imapLiteral = regexp.MustCompile(`\{(\d+)(\+?)\}$`)

type IMAP struct{ endpoint }

func (r *IMAP) Serve(s *Stream) {
	defer s.Close()
	u := &r.URL
	up, err := dialURL(s.Dialer, u, imapTLSScheme, imapPort, imapsPort)
	if err != nil {
		log.Printf("imap: %v", err)
		return
	}
	defer up.Close()
	replies := bufio.NewReader(up)
	if _, err := replies.ReadString('\n'); err != nil {
		return
	}
	pass, _ := u.User.Password()
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
	go func() {
		io.Copy(s, replies)
		s.Close()
	}()
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
		command = strings.ToUpper(command)
		switch command {
		case "LOGIN", "AUTHENTICATE":
			fmt.Fprintf(s, "%s OK already authenticated\r\n", tag)
			continue
		case "SELECT", "EXAMINE":
			mailbox = strings.Trim(args, `"`)
		}
		dst := io.Writer(up)
		if err := s.Gate(Event{IMAP: &imapLayer{Command: command, Args: args, Mailbox: mailbox}}); err != nil {
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
