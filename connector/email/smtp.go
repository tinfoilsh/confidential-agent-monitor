package email

import (
	"bytes"
	"crypto/tls"
	"io"
	"log"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"net/url"
	"strings"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"

	"github.com/tinfoilsh/monitor/connector"
)

const (
	smtpTLSScheme   = "smtps"
	smtpPort        = "587"
	smtpsPort       = "465"
	smtpDomain      = "monitor"
	maxMessageBytes = 25 << 20
	smtpRefused     = 550
)

type SMTP struct {
	connector.Endpoint
	conns connector.Listener
}

func (r *SMTP) Serve(s *connector.Stream) { r.conns <- s }

// Start accepts any credential from the client and submits each message upstream with the stored one.
func (r *SMTP) Start(e *connector.Env) {
	r.conns = make(connector.Listener)
	server := smtp.NewServer(smtp.BackendFunc(func(c *smtp.Conn) (smtp.Session, error) {
		s := connector.StreamOf(c.Conn())
		return &smtpSession{stream: s, relay: r}, nil
	}))
	server.Domain = smtpDomain
	server.MaxMessageBytes = maxMessageBytes
	server.AllowInsecureAuth = true
	server.TLSConfig = e.TLS
	go func() { log.Fatal(server.Serve(r.conns)) }()
}

type smtpSession struct {
	stream *connector.Stream
	relay  *SMTP
	from   string
	to     []string
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
	if err := s.stream.Gate(connector.Event{SMTP: &connector.SMTPLayer{From: s.from, To: s.to}, Mail: mailHeaders(message)}); err != nil {
		return &smtp.SMTPError{Code: smtpRefused, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: err.Error()}
	}
	return submit(s.stream.Dialer, &s.relay.URL, s.from, s.to, message)
}

func submit(d *net.Dialer, u *url.URL, from string, to []string, message []byte) error {
	conn, err := connector.DialURL(d, u, smtpTLSScheme, smtpPort, smtpsPort)
	if err != nil {
		return err
	}
	c := smtp.NewClient(conn)
	if u.Scheme != smtpTLSScheme {
		if c, err = smtp.NewClientStartTLS(conn, &tls.Config{ServerName: u.Hostname()}); err != nil {
			return err
		}
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

// Only top-level attachments are named.
func mailHeaders(message []byte) *connector.MailLayer {
	msg, err := mail.ReadMessage(bytes.NewReader(message))
	if err != nil {
		return nil
	}
	return &connector.MailLayer{
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
