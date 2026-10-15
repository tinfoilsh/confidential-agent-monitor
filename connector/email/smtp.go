package email

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"mime"
	"mime/multipart"
	"net/mail"
	"slices"
	"strings"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/facts"
)

var SMTPDefinition = connector.Definition{NewConfig: func() connector.Server { return new(SMTP) }, Requests: []connector.Request{new(SMTPRequest)}}

const (
	smtpTLSScheme = "smtps"

	maxMessageBytes = 25 << 20
	smtpRefused     = 550
)

type SMTP struct{ connector.Endpoint }

func (r *SMTP) Serve(s *connector.Stream, e *connector.Env) {
	server := smtp.NewServer(smtp.BackendFunc(func(*smtp.Conn) (smtp.Session, error) {
		return &smtpSession{stream: s, relay: r, env: e}, nil
	}))
	server.Domain = "monitor"
	server.MaxMessageBytes = maxMessageBytes
	server.AllowInsecureAuth = true
	server.TLSConfig = e.TLS
	defer server.Shutdown(context.Background())
	server.Serve(connector.Listen(s, s))
}

type smtpSession struct {
	env    *connector.Env
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
	if err := s.stream.Check(&SMTPRequest{SMTP: &facts.SMTP{From: s.from, To: s.to}, Mail: mailHeaders(message)}); err != nil {
		return &smtp.SMTPError{Code: smtpRefused, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: err.Error()}
	}
	return s.relay.submit(s.stream, s.env, s.from, s.to, message)
}

func (r *SMTP) submit(s *connector.Stream, e *connector.Env, from string, to []string, message []byte) error {
	u := &r.URL
	pass, err := r.Secret(s.Context, "password")
	if err != nil {
		return err
	}
	conn, err := connector.DialURL(s.Context, e.Dialer, u, smtpTLSScheme, "587", "465")
	if err != nil {
		return err
	}
	defer s.Interrupt(conn)()
	c := smtp.NewClient(conn)
	if u.Scheme != smtpTLSScheme {
		if c, err = smtp.NewClientStartTLS(conn, &tls.Config{ServerName: u.Hostname()}); err != nil {
			return err
		}
	}
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
func mailHeaders(message []byte) *facts.Mail {
	msg, err := mail.ReadMessage(bytes.NewReader(message))
	if err != nil {
		return nil
	}
	return &facts.Mail{
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

type SMTPRequest struct {
	SMTP *facts.SMTP `json:"smtp"`
	Mail *facts.Mail `json:"mail,omitempty"`
}

func (r *SMTPRequest) Describe(c connector.Context) (facts.Facts, error) {
	details := facts.Details{SMTP: r.SMTP}
	if r.Mail != nil {
		details.Mail = r.Mail
	}
	v := r.SMTP
	if v == nil {
		return facts.Facts{Details: details}, nil
	}
	to := slices.Clone(v.To)
	slices.Sort(to)
	sends := "account"
	for _, to := range v.To {
		if !strings.EqualFold(to, c.Options.Address) {
			sends = "anyone"
		}
	}
	return facts.Facts{Operation: &facts.Operation{Action: "send"}, Title: "Send mail to " + strings.Join(v.To, ", "), Parameters: map[string]any{"to": to}, Details: details, Context: facts.Context{Sends: sends}}, nil
}
