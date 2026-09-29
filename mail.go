package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net/mail"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
)

const (
	imapTLSScheme   = "imaps"
	imapPort        = "143"
	imapsPort       = "993"
	loginTag        = "m0"
	smtpTLSScheme   = "smtps"
	smtpPort        = "587"
	smtpsPort       = "465"
	smtpDomain      = "monitor"
	maxMessageBytes = 25 << 20
	smtpRefused     = 550
)

var imapLiteral = regexp.MustCompile(`\{(\d+)(\+?)\}$`)

type imapRelay struct{ endpoint }

// serve logs in upstream with the stored URL and greets the client as already authenticated.
func (r *imapRelay) serve(cc *channelConn) {
	defer cc.Close()
	u := &r.URL
	up, err := dialURL(u, imapTLSScheme, imapPort, imapsPort)
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
	fmt.Fprintf(cc, "* PREAUTH monitor\r\n")
	go func() {
		io.Copy(cc, replies)
		cc.Close()
	}()
	commands := bufio.NewReader(cc)
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
			fmt.Fprintf(cc, "%s OK already authenticated\r\n", tag)
			continue
		case "SELECT", "EXAMINE":
			mailbox = strings.Trim(args, `"`)
		}
		dst := io.Writer(up)
		if err := cc.gate(event{IMAP: &imapLayer{Command: command, Args: args, Mailbox: mailbox}}); err != nil {
			fmt.Fprintf(cc, "%s NO %v\r\n", tag, err)
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

type smtpRelay struct{ endpoint }

func (r *smtpRelay) serve(cc *channelConn) { cc.m.smtp.push(cc) }

// serveSMTP accepts any credential from the client and submits each message upstream with the stored one.
func (m *monitor) serveSMTP() {
	server := smtp.NewServer(smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
		cc := channelOf(c.Conn())
		return &smtpSession{cc: cc, relay: m.Connections[cc.name].relay.(*smtpRelay)}, nil
	}))
	server.Domain = smtpDomain
	server.MaxMessageBytes = maxMessageBytes
	server.AllowInsecureAuth = true
	server.TLSConfig = m.tls
	log.Fatal(server.Serve(m.smtp))
}

type smtpSession struct {
	cc    *channelConn
	relay *smtpRelay
	from  string
	to    []string
}

func (s *smtpSession) AuthMechanisms() []string { return []string{sasl.Plain} }
func (s *smtpSession) Auth(string) (sasl.Server, error) {
	return sasl.NewPlainServer(func(_, _, _ string) error { return nil }), nil
}
func (s *smtpSession) Mail(from string, _ *smtp.MailOptions) error { s.from = from; return nil }
func (s *smtpSession) Rcpt(to string, _ *smtp.RcptOptions) error   { s.to = append(s.to, to); return nil }
func (s *smtpSession) Reset()                                      { s.from, s.to = "", nil }
func (s *smtpSession) Logout() error                               { return nil }

func (s *smtpSession) Data(r io.Reader) error {
	message, err := io.ReadAll(r)
	if err != nil {
		return err
	}
	if err := s.cc.gate(event{SMTP: &smtpLayer{From: s.from, To: s.to}, Mail: mailHeaders(message)}); err != nil {
		return &smtp.SMTPError{Code: smtpRefused, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: err.Error()}
	}
	return submit(&s.relay.URL, s.from, s.to, message)
}

func submit(u *url.URL, from string, to []string, message []byte) error {
	target := address(u, smtpTLSScheme, smtpPort, smtpsPort)
	var c *smtp.Client
	var err error
	if u.Scheme == smtpTLSScheme {
		c, err = smtp.DialTLS(target, nil)
	} else {
		c, err = smtp.DialStartTLS(target, nil)
	}
	if err != nil {
		return err
	}
	defer c.Close()
	pass, _ := u.User.Password()
	if err := c.Auth(sasl.NewPlainClient("", u.User.Username(), pass)); err != nil {
		return err
	}
	if err := c.SendMail(from, to, bytes.NewReader(message)); err != nil {
		return err
	}
	return c.Quit()
}

const multipartPrefix = "multipart/"

// mailHeaders is the mail layer: the addressing headers and the names of top-level attachments.
func mailHeaders(message []byte) *mailLayer {
	msg, err := mail.ReadMessage(bytes.NewReader(message))
	if err != nil {
		return nil
	}
	return &mailLayer{
		From:        addresses(msg.Header, "From"),
		To:          addresses(msg.Header, "To"),
		Cc:          addresses(msg.Header, "Cc"),
		Subject:     msg.Header.Get("Subject"),
		Attachments: attachments(msg),
	}
}

func addresses(h mail.Header, key string) []string {
	out := []string{}
	list, err := h.AddressList(key)
	if err != nil {
		if raw := h.Get(key); raw != "" {
			out = append(out, raw)
		}
		return out
	}
	for _, a := range list {
		out = append(out, a.Address)
	}
	return out
}

func attachments(msg *mail.Message) []string {
	names := []string{}
	mediaType, params, err := mime.ParseMediaType(msg.Header.Get("Content-Type"))
	if err != nil || !strings.HasPrefix(mediaType, multipartPrefix) {
		return names
	}
	parts := multipart.NewReader(msg.Body, params["boundary"])
	for {
		part, err := parts.NextPart()
		if err != nil {
			return names
		}
		if name := part.FileName(); name != "" {
			names = append(names, name)
		}
	}
}
