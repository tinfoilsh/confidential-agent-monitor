package email

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"mime"
	"mime/multipart"
	"net"
	"net/mail"
	"slices"
	"strings"

	"github.com/emersion/go-sasl"
	"github.com/emersion/go-smtp"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

const (
	smtpTLSScheme = "smtps"
	smtpRefused   = 550
)

type SMTP struct{ *Endpoint }

func ParseSMTP(config json.RawMessage) (*SMTP, error) {
	e, err := parse(config)
	return &SMTP{e}, err
}

// Handler accepts mail from the agent and submits each admitted message with the stored password.
// server builds the stream's server for its host around backend; Data buffers each message, so its
// MaxMessageBytes bounds memory. auth decides the identities AUTH PLAIN accepts, while mail needs no
// AUTH, since the caller admitted the stream. listen yields the stream once as a listener.
func (r *SMTP) Handler(dial func(ctx context.Context, network, address string) (net.Conn, error), password func(context.Context) (string, error), auth sasl.PlainAuthenticator, server func(ctx context.Context, host string, backend smtp.Backend) *smtp.Server, listen func(context.Context, net.Conn) net.Listener) func(context.Context, net.Conn, string, string, uint32, func(context.Context, facts.Event) error) {
	return func(ctx context.Context, s net.Conn, _, host string, _ uint32, gate func(context.Context, facts.Event) error) {
		server := server(ctx, host, smtp.BackendFunc(func(*smtp.Conn) (smtp.Session, error) {
			return &smtpSession{ctx: ctx, gate: gate, relay: r, dial: dial, password: password, auth: auth}, nil
		}))
		defer server.Shutdown(context.Background())
		server.Serve(listen(ctx, s))
	}
}

type smtpSession struct {
	ctx      context.Context
	gate     func(context.Context, facts.Event) error
	relay    *SMTP
	dial     func(context.Context, string, string) (net.Conn, error)
	password func(context.Context) (string, error)
	auth     sasl.PlainAuthenticator
	from     string
	to       []string
}

func (s *smtpSession) AuthMechanisms() []string { return []string{sasl.Plain} }
func (s *smtpSession) Auth(string) (sasl.Server, error) {
	return sasl.NewPlainServer(s.auth), nil
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
	if err := s.gate(s.ctx, facts.Capture((&SMTPRequest{SMTP: &SMTPFacts{From: s.from, To: s.to}, Mail: mailHeaders(message)}).Describe(), nil)); err != nil {
		return &smtp.SMTPError{Code: smtpRefused, EnhancedCode: smtp.EnhancedCode{5, 7, 1}, Message: err.Error()}
	}
	return s.submit(message)
}

func (s *smtpSession) submit(message []byte) error {
	u := s.relay.url
	pass, err := s.password(s.ctx)
	if err != nil {
		return err
	}
	conn, err := s.relay.dial(s.ctx, s.dial, smtpTLSScheme, "587", "465")
	if err != nil {
		return err
	}
	stop := context.AfterFunc(s.ctx, func() { conn.Close() })
	defer func() { stop(); conn.Close() }()
	c := smtp.NewClient(conn)
	if u.Scheme != smtpTLSScheme {
		if c, err = smtp.NewClientStartTLS(conn, &tls.Config{ServerName: u.Hostname()}); err != nil {
			return err
		}
	}
	if err := c.Auth(sasl.NewPlainClient("", u.User.Username(), pass)); err != nil {
		return err
	}
	if err := c.SendMail(s.from, s.to, bytes.NewReader(message)); err != nil {
		return err
	}
	return c.Quit()
}

const multipartPrefix = "multipart/"

// Only top-level attachments are named.
func mailHeaders(message []byte) *MailFacts {
	msg, err := mail.ReadMessage(bytes.NewReader(message))
	if err != nil {
		return nil
	}
	return &MailFacts{
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

type SMTPRequest Details

// Describe keeps the envelope recipients as sent; the host compares them with the connection's own address.
func (r *SMTPRequest) Describe() facts.Observation {
	v := r.SMTP
	to := slices.Clone(v.To)
	slices.Sort(to)
	return facts.Observation{Operation: &facts.Operation{Action: "send"}, Title: "Send mail to " + strings.Join(v.To, ", "), Parameters: map[string]any{"to": to}, Details: Details(*r)}
}
