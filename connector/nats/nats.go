// Package nats provides a Core NATS endpoint inside the authenticated tunnel.
package nats

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"

	nats "github.com/nats-io/nats.go"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/facts"
)

var Kind = connector.Kind{PerMessage: true, Parse: parseNATS, New: func() connector.Server { return new(NATS) }}

func parseNATS(source connector.Setup) (connector.Prepared, error) {
	c := new(natsSetup)
	if err := connector.ParseSetup(source, c, &c.Semantics, &c.Semantics); err != nil {
		return connector.Prepared{}, err
	}
	if err := c.validate(); err != nil {
		return connector.Prepared{}, err
	}
	names, err := c.Declarations("password", "token")
	return connector.Prepared{Source: source, Value: c, SecretNames: names}, err
}

// NATS keeps one immutable setup for each admitted stream.
type NATS struct{ connector.Slot[natsSetup] }

const (
	maxPayload = 1 << 20
	maxLine    = 8192
)

type natsSetup struct {
	connector.SecretConfig
	Address string `json:"url"`
	User    string `json:"user"`
	url     *url.URL
}

func (n *natsSetup) validate() error {
	u, err := connector.ParseURL(n.Address)
	if err != nil {
		return err
	}
	if u.Scheme != "nats" && u.Scheme != "tls" || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" || strings.Contains(u.Host, ",") {
		return errors.New("NATS requires a nats:// or tls:// host URL without a path, query or fragment")
	}
	if n.User == "" {
		n.User = u.User.Username()
	}
	u.User = nil // Authentication is always supplied separately to the client.
	u.Path = ""
	n.url = u
	return nil
}

type dialer struct {
	ctx    context.Context
	dialer connector.Dialer
}

func (d dialer) Dial(network, address string) (net.Conn, error) {
	return d.dialer.DialContext(d.ctx, network, address)
}

type clientOptions struct {
	Verbose      bool `json:"verbose"`
	Echo         bool `json:"echo"`
	Headers      bool `json:"headers"`
	NoResponders bool `json:"no_responders"`
	Protocol     int  `json:"protocol"`
}

type client struct {
	owner   *natsSetup
	s       *connector.Stream
	up      *nats.Conn
	options clientOptions
	writeMu sync.Mutex
	subs    map[string]*nats.Subscription
}

func (owner *NATS) Serve(s *connector.Stream, e *connector.Env) {
	captured := owner.Load()
	if captured == nil {
		return
	}
	n := captured.Value
	n.Secrets = captured.Secrets

	c := &client{owner: &n, s: s, subs: map[string]*nats.Subscription{}}
	// Cluster addresses, upstream names and authentication details never leave
	// the connector. Clients reconnect through the monitor's own address.
	if err := c.write([]byte(`INFO {"server_id":"monitor","server_name":"monitor","version":"2.10.0","proto":1,"headers":true,"max_payload":1048576,"auth_required":false,"tls_required":false}` + "\r\n")); err != nil {
		return
	}
	r := bufio.NewReaderSize(s, maxLine)
	line, err := readLine(r)
	if err != nil {
		return
	}
	verb, args, _ := strings.Cut(line, " ")
	if !strings.EqualFold(verb, "CONNECT") {
		c.fail("CONNECT required")
		return
	}
	c.options = clientOptions{Verbose: true, Echo: true}
	if json.Unmarshal([]byte(args), &c.options) != nil || c.options.Protocol < 0 || c.options.Protocol > 1 || c.options.NoResponders && !c.options.Headers {
		c.fail("invalid CONNECT")
		return
	}
	if err := c.s.Gate(c.s.Context, c.owner.Capture((&Request{Command: "connect"}).Describe())); err != nil {
		c.fail("connection refused")
		return
	}
	password, err := n.Secret(s.Context, "password")
	if err != nil {
		c.fail("credential unavailable")
		return
	}
	token, err := n.Secret(s.Context, "token")
	if err != nil || token != "" && (password != "" || n.User != "") {
		c.fail("invalid credential configuration")
		return
	}
	opts := []nats.Option{
		nats.SetCustomDialer(dialer{s.Context, e.Dialer}), nats.NoReconnect(), nats.Timeout(connector.DialTimeout),
		nats.SkipHostLookup(),
		nats.Name("monitor"), nats.ClosedHandler(func(*nats.Conn) { s.Close() }),
		// Error text can contain provider details or subjects; expose a fixed error.
		nats.ErrorHandler(func(*nats.Conn, *nats.Subscription, error) { s.Close() }),
	}
	if token != "" {
		opts = append(opts, nats.Token(token))
	} else {
		opts = append(opts, nats.UserInfo(n.User, password))
	}
	if !c.options.Echo {
		opts = append(opts, nats.NoEcho())
	}
	up, err := nats.Connect(n.url.String(), opts...)
	if err != nil {
		c.fail("upstream connection failed")
		return
	}
	c.up = up
	defer s.Interrupt(connector.CloseFunc(up.Close))()
	if err := c.ok(); err != nil {
		return
	}
	for {
		line, err := readLine(r)
		if err != nil {
			return
		}
		if err := c.command(line, r); err != nil {
			c.fail("operation refused or malformed")
			return
		}
	}
}

func readLine(r *bufio.Reader) (string, error) {
	b, err := r.ReadSlice('\n')
	if err != nil {
		return "", err
	}
	if len(b) > maxLine || len(b) < 2 || b[len(b)-2] != '\r' {
		return "", errors.New("invalid NATS control line")
	}
	return string(b[:len(b)-2]), nil
}

func (c *client) write(b []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, err := io.Copy(c.s, bytes.NewReader(b))
	return err
}
func (c *client) fail(message string) { c.write([]byte("-ERR '" + message + "'\r\n")) }
func (c *client) ok() error {
	if c.options.Verbose {
		return c.write([]byte("+OK\r\n"))
	}
	return nil
}

func (c *client) command(line string, r *bufio.Reader) error {
	args := strings.Fields(line)
	if len(args) == 0 {
		return errors.New("empty NATS command")
	}
	switch strings.ToUpper(args[0]) {
	case "PUB", "HPUB":
		m, err := message(args, r)
		if err != nil {
			return err
		}
		if m.Header != nil && !c.options.Headers {
			return errors.New("headers were not negotiated")
		}
		if err := c.s.Gate(c.s.Context, c.owner.Capture((&Request{Command: "publish", Subject: m.Subject, Reply: m.Reply, Headers: m.Header, Payload: m.Data}).Describe())); err != nil {
			return err
		}
		if err := c.up.PublishMsg(m); err != nil {
			return err
		}
	case "SUB":
		for sid, sub := range c.subs {
			if !sub.IsValid() {
				delete(c.subs, sid)
			}
		}
		if len(args) != 3 && len(args) != 4 || !subjectValid(args[1], true) {
			return errors.New("invalid subscription")
		}
		subject, queue, sid := args[1], "", args[len(args)-1]
		if !tokenValid(sid) || len(c.subs) >= 1024 {
			return errors.New("invalid subscription ID")
		}
		if c.subs[sid] != nil {
			return errors.New("subscription ID is already in use")
		}
		if len(args) == 4 {
			queue = args[2]
			if !subjectValid(queue, false) {
				return errors.New("invalid queue")
			}
		}
		if err := c.s.Gate(c.s.Context, c.owner.Capture((&Request{Command: "subscribe", Subject: subject, Queue: queue}).Describe())); err != nil {
			return err
		}
		callback := func(m *nats.Msg) { c.deliver(sid, queue, m) }
		var sub *nats.Subscription
		var err error
		if queue == "" {
			sub, err = c.up.Subscribe(subject, callback)
		} else {
			sub, err = c.up.QueueSubscribe(subject, queue, callback)
		}
		if err != nil {
			return err
		}
		if err := sub.SetPendingLimits(128, 4*maxPayload); err != nil {
			sub.Unsubscribe()
			return err
		}
		c.subs[sid] = sub
	case "UNSUB":
		if len(args) != 2 && len(args) != 3 {
			return errors.New("invalid unsubscribe")
		}
		sub := c.subs[args[1]]
		if sub == nil {
			return c.ok()
		}
		if len(args) == 3 {
			n, err := strconv.Atoi(args[2])
			if err != nil || n <= 0 {
				return errors.New("invalid message count")
			}
			if err := sub.AutoUnsubscribe(n); err != nil {
				return err
			}
		} else {
			if err := sub.Unsubscribe(); err != nil {
				return err
			}
			delete(c.subs, args[1])
		}
	case "PING":
		if len(args) != 1 {
			return errors.New("invalid ping")
		}
		// PONG is also a barrier for preceding publishes and subscriptions.
		if err := c.up.FlushTimeout(connector.DialTimeout); err != nil {
			return err
		}
		return c.write([]byte("PONG\r\n"))
	case "PONG":
		if len(args) != 1 {
			return errors.New("invalid pong")
		}
		return nil
	default:
		return errors.New("unsupported NATS command")
	}
	return c.ok()
}

func (c *client) deliver(sid, queue string, m *nats.Msg) {
	if m.Header.Get("Status") == "503" && !c.options.NoResponders {
		return
	}
	if len(m.Data) > maxPayload || !subjectValid(m.Subject, false) || m.Reply != "" && !subjectValid(m.Reply, false) {
		c.s.Close()
		return
	}
	if err := c.s.Gate(c.s.Context, c.owner.Capture((&Request{Command: "receive", Subject: m.Subject, Reply: m.Reply, Queue: queue, Headers: m.Header, Payload: m.Data}).Describe())); err != nil {
		c.s.Close()
		return
	}
	var head []byte
	if c.options.Headers && len(m.Header) > 0 {
		var b bytes.Buffer
		b.WriteString("NATS/1.0")
		if status := m.Header.Get("Status"); status != "" {
			if !tokenValid(status) || strings.ContainsAny(m.Header.Get("Description"), "\r\n") {
				c.s.Close()
				return
			}
			b.WriteString(" " + status)
			if description := m.Header.Get("Description"); description != "" {
				b.WriteString(" " + description)
			}
		}
		b.WriteString("\r\n")
		for name, values := range m.Header {
			if name == "Status" || name == "Description" {
				continue
			}
			if !tokenValid(name) || strings.Contains(name, ":") {
				c.s.Close()
				return
			}
			for _, value := range values {
				if strings.ContainsAny(value, "\r\n") {
					c.s.Close()
					return
				}
				fmt.Fprintf(&b, "%s: %s\r\n", name, value)
			}
		}
		b.WriteString("\r\n")
		head = b.Bytes()
	}
	if len(head)+len(m.Data) > maxPayload {
		c.s.Close()
		return
	}
	verb := "MSG"
	if len(head) != 0 {
		verb = "HMSG"
	}
	line := verb + " " + m.Subject + " " + sid
	if m.Reply != "" {
		line += " " + m.Reply
	}
	if len(head) != 0 {
		line += " " + strconv.Itoa(len(head))
	}
	line += " " + strconv.Itoa(len(head)+len(m.Data)) + "\r\n"
	if len(line) > maxLine {
		c.s.Close()
		return
	}
	b := append([]byte(line), head...)
	b = append(b, m.Data...)
	b = append(b, '\r', '\n')
	if err := c.write(b); err != nil {
		c.s.Close()
	}
}

func message(args []string, r *bufio.Reader) (*nats.Msg, error) {
	hasHeaders := strings.EqualFold(args[0], "HPUB")
	min := 3
	if hasHeaders {
		min++
	}
	if len(args) != min && len(args) != min+1 {
		return nil, errors.New("invalid publish")
	}
	m := &nats.Msg{Subject: args[1]}
	if len(args) == min+1 {
		m.Reply = args[2]
	}
	if !subjectValid(m.Subject, false) || m.Reply != "" && !subjectValid(m.Reply, false) {
		return nil, errors.New("invalid subject")
	}
	n, err := strconv.Atoi(args[len(args)-1])
	if err != nil || n < 0 || n > maxPayload {
		return nil, errors.New("invalid payload size")
	}
	h := 0
	if hasHeaders {
		h, err = strconv.Atoi(args[len(args)-2])
		if err != nil || h < 12 || h > n {
			return nil, errors.New("invalid header size")
		}
	}
	b := make([]byte, n+2)
	if _, err := io.ReadFull(r, b); err != nil {
		return nil, err
	}
	if !bytes.Equal(b[n:], []byte("\r\n")) {
		return nil, errors.New("invalid payload terminator")
	}
	if hasHeaders {
		header := b[:h]
		// Client publishes carry ordinary headers, not server status lines.
		if !bytes.HasPrefix(header, []byte("NATS/1.0\r\n")) || !bytes.HasSuffix(header, []byte("\r\n\r\n")) {
			return nil, errors.New("invalid NATS headers")
		}
		m.Header = nats.Header{}
		fields := string(header[len("NATS/1.0\r\n") : len(header)-2])
		if fields != "" {
			for _, line := range strings.Split(strings.TrimSuffix(fields, "\r\n"), "\r\n") {
				name, value, found := strings.Cut(line, ":")
				if !found || !tokenValid(name) || strings.ContainsAny(value, "\r\n") {
					return nil, errors.New("invalid NATS header")
				}
				// NATS header names are case-sensitive.
				m.Header.Add(name, strings.TrimLeft(value, " \t"))
			}
		}
	}
	m.Data = b[h:n]
	return m, nil
}

func tokenValid(s string) bool {
	if s == "" || !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if unicode.IsSpace(r) || unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func subjectValid(s string, filter bool) bool {
	if !tokenValid(s) {
		return false
	}
	parts := strings.Split(s, ".")
	for i, part := range parts {
		if part == "" {
			return false
		}
		if strings.ContainsAny(part, "*>") {
			if !filter || part != "*" && (part != ">" || i != len(parts)-1) {
				return false
			}
		}
	}
	return true
}

type Request NATSFacts

func (v *Request) Describe() (facts.Facts, error) {
	details := Details{NATS: (*NATSFacts)(v)}
	action := ""
	if slices.Contains([]string{"connect", "subscribe", "receive", "publish"}, v.Command) {
		action = v.Command
	}
	if (action == "subscribe" || action == "receive") && v.Queue != "" {
		action = "consume"
	}
	control := strings.HasPrefix(v.Subject, "$")
	for k := range v.Headers {
		control = control || strings.HasPrefix(strings.ToLower(k), "nats-")
	}
	if action == "publish" && control {
		action = "admin"
	}
	op := &facts.Operation{ID: v.Command, Action: action}
	parameters, _ := facts.JSON[map[string]any](v)
	return facts.Facts{Operation: op, Title: "NATS " + v.Command + " " + v.Subject, Parameters: parameters, Details: details, Context: facts.Context{Sends: "account"}}, nil
}
