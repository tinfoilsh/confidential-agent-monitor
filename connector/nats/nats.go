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
	"time"
	"unicode"
	"unicode/utf8"

	nats "github.com/nats-io/nats.go"
	"github.com/tinfoilsh/confidential-agent-monitor/core/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

type NATS struct {
	RawURL string `json:"url"`
	User   string `json:"user"`
	url    *url.URL
}

func Parse(config json.RawMessage) (*NATS, error) {
	n := new(NATS)
	if err := facts.DecodeNumbers(config, n); err != nil {
		return nil, err
	}
	u, err := url.Parse(n.RawURL)
	switch {
	case err != nil:
		return nil, err
	case u.Scheme == "" || u.Host == "":
		return nil, errors.New("destination requires a URL with a scheme and host")
	}
	if _, set := u.User.Password(); set || u.Query().Has("password") {
		return nil, errors.New("put the password in the service's password credential, not the URL")
	}
	if u.Scheme != "nats" && u.Scheme != "tls" || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" || strings.Contains(u.Host, ",") {
		return nil, errors.New("NATS requires a nats:// or tls:// host URL without a path, query or fragment")
	}
	if n.User == "" {
		n.User = u.User.Username()
	}
	u.User = nil
	u.Path = ""
	n.url = u
	return n, nil
}

func (n *NATS) Hosts() []string { return []string{n.url.Hostname()} }

type dialer struct {
	ctx  context.Context
	dial func(context.Context, string, string) (net.Conn, error)
}

func (d dialer) Dial(network, address string) (net.Conn, error) {
	return d.dial(d.ctx, network, address)
}

type clientOptions struct {
	Verbose      bool `json:"verbose"`
	Echo         bool `json:"echo"`
	Headers      bool `json:"headers"`
	NoResponders bool `json:"no_responders"`
	Protocol     int  `json:"protocol"`
}

type client struct {
	ctx     context.Context
	close   func()
	conn    net.Conn
	gate    connector.Gate
	up      *nats.Conn
	options clientOptions
	limits  Limits
	writeMu sync.Mutex
	subs    map[string]*nats.Subscription
}

type Limits struct {
	Payload, Line, Subscriptions, PendingMessages, PendingBytes int
	Timeout                                                     time.Duration
}

func (n *NATS) Preauthenticated(dial func(ctx context.Context, network, address string) (net.Conn, error), secret func(ctx context.Context, name string) (string, error), limits Limits, name string) connector.Serve {
	return func(ctx context.Context, s net.Conn, _ string, _ connector.Target, gate connector.Gate) {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		n.serve(&client{ctx: ctx, close: func() { cancel(); s.Close() }, conn: s, gate: gate, limits: limits, subs: map[string]*nats.Subscription{}}, dial, secret, name)
	}
}

func (n *NATS) serve(c *client, dial func(context.Context, string, string) (net.Conn, error), secret func(context.Context, string) (string, error), name string) {
	s := c.conn
	id, _ := json.Marshal(name)
	if err := c.write([]byte(`INFO {"server_id":` + string(id) + `,"server_name":` + string(id) + `,"version":"2.10.0","proto":1,"headers":true,"max_payload":` + strconv.Itoa(c.limits.Payload) + `,"auth_required":false,"tls_required":false}` + "\r\n")); err != nil {
		return
	}
	r := bufio.NewReaderSize(s, c.limits.Line)
	line, err := readLine(r, c.limits.Line)
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
	if err := c.gate(c.ctx, facts.Capture((&NATSFacts{Command: "connect"}).Describe(), nil)); err != nil {
		c.fail("connection refused")
		return
	}
	password, err := secret(c.ctx, "password")
	if err != nil {
		c.fail("credential unavailable")
		return
	}
	token, err := secret(c.ctx, "token")
	if err != nil || token != "" && (password != "" || n.User != "") {
		c.fail("invalid credential configuration")
		return
	}
	opts := []nats.Option{
		nats.SetCustomDialer(dialer{c.ctx, dial}), nats.NoReconnect(), nats.Timeout(c.limits.Timeout),
		nats.SkipHostLookup(),
		nats.Name(name), nats.ClosedHandler(func(*nats.Conn) { c.close() }),
		nats.ErrorHandler(func(*nats.Conn, *nats.Subscription, error) { c.close() }),
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
	stop := context.AfterFunc(c.ctx, up.Close)
	defer func() { stop(); up.Close() }()
	if err := c.ok(); err != nil {
		return
	}
	for {
		line, err := readLine(r, c.limits.Line)
		if err != nil {
			return
		}
		if err := c.command(line, r); err != nil {
			c.fail("operation refused or malformed")
			return
		}
	}
}

func readLine(r *bufio.Reader, limit int) (string, error) {
	b, err := r.ReadSlice('\n')
	if err != nil {
		return "", err
	}
	if len(b) > limit || len(b) < 2 || b[len(b)-2] != '\r' {
		return "", errors.New("invalid NATS control line")
	}
	return string(b[:len(b)-2]), nil
}

func (c *client) write(b []byte) error {
	c.writeMu.Lock()
	defer c.writeMu.Unlock()
	_, err := io.Copy(c.conn, bytes.NewReader(b))
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
		m, err := message(args, r, c.limits.Payload)
		if err != nil {
			return err
		}
		if m.Header != nil && !c.options.Headers {
			return errors.New("headers were not negotiated")
		}
		if err := c.gate(c.ctx, facts.Capture((&NATSFacts{Command: "publish", Subject: m.Subject, Reply: m.Reply, Headers: m.Header, Payload: m.Data}).Describe(), nil)); err != nil {
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
		if !tokenValid(sid) || len(c.subs) >= c.limits.Subscriptions {
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
		if err := c.gate(c.ctx, facts.Capture((&NATSFacts{Command: "subscribe", Subject: subject, Queue: queue}).Describe(), nil)); err != nil {
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
		if err := sub.SetPendingLimits(c.limits.PendingMessages, c.limits.PendingBytes); err != nil {
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
		if err := c.up.FlushTimeout(c.limits.Timeout); err != nil {
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
	if len(m.Data) > c.limits.Payload || !subjectValid(m.Subject, false) || m.Reply != "" && !subjectValid(m.Reply, false) {
		c.close()
		return
	}
	if err := c.gate(c.ctx, facts.Capture((&NATSFacts{Command: "receive", Subject: m.Subject, Reply: m.Reply, Queue: queue, Headers: m.Header, Payload: m.Data}).Describe(), nil)); err != nil {
		c.close()
		return
	}
	var head []byte
	if c.options.Headers && len(m.Header) > 0 {
		var b bytes.Buffer
		b.WriteString("NATS/1.0")
		if status := m.Header.Get("Status"); status != "" {
			if !tokenValid(status) || strings.ContainsAny(m.Header.Get("Description"), "\r\n") {
				c.close()
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
				c.close()
				return
			}
			for _, value := range values {
				if strings.ContainsAny(value, "\r\n") {
					c.close()
					return
				}
				fmt.Fprintf(&b, "%s: %s\r\n", name, value)
			}
		}
		b.WriteString("\r\n")
		head = b.Bytes()
	}
	if len(head)+len(m.Data) > c.limits.Payload {
		c.close()
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
	if len(line) > c.limits.Line {
		c.close()
		return
	}
	b := append([]byte(line), head...)
	b = append(b, m.Data...)
	b = append(b, '\r', '\n')
	if err := c.write(b); err != nil {
		c.close()
	}
}

func message(args []string, r *bufio.Reader, limit int) (*nats.Msg, error) {
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
	if err != nil || n < 0 || n > limit {
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

func (v *NATSFacts) Describe() facts.Observation {
	details := Details{NATS: v}
	action := ""
	if slices.Contains([]string{"connect", "subscribe", "receive", "publish"}, v.Command) {
		action = v.Command
	}
	if (action == "subscribe" || action == "receive") && v.Queue != "" {
		action = "consume"
	}
	if action == "publish" && strings.HasPrefix(v.Subject, "$") {
		action = "admin"
		for prefix, subjectAction := range natsSubjectActions {
			if strings.HasPrefix(v.Subject, prefix) {
				action = subjectAction
			}
		}
	}
	control := strings.HasPrefix(v.Reply, "$")
	for k := range v.Headers {
		k = strings.ToLower(k)
		control = control || strings.HasPrefix(k, "nats-") && !slices.Contains(natsPublishHeaders, k)
	}
	if v.Command == "publish" && control {
		action = "admin"
	}
	op := &facts.Operation{ID: v.Command, Action: action}
	parameters, _ := facts.JSON[map[string]any](v)
	return facts.Observation{Operation: op, Title: "NATS " + v.Command + " " + v.Subject, Parameters: parameters, Details: details}
}

var (
	natsPublishHeaders = strings.Fields("nats-msg-id nats-expected-stream nats-expected-last-sequence nats-expected-last-subject-sequence nats-expected-last-subject-sequence-subject nats-expected-last-msg-id")
	natsSubjectActions = map[string]string{
		"$JS.API.INFO": "inspect", "$JS.API.STREAM.NAMES": "inspect", "$JS.API.STREAM.LIST": "inspect",
		"$JS.API.STREAM.INFO.": "inspect", "$JS.API.STREAM.MSG.GET.": "inspect", "$JS.API.DIRECT.GET.": "inspect",
		"$JS.API.CONSUMER.NAMES.": "inspect", "$JS.API.CONSUMER.LIST.": "inspect", "$JS.API.CONSUMER.INFO.": "inspect",
		"$JS.API.CONSUMER.MSG.NEXT.": "consume", "$JS.ACK.": "consume", "$KV.": "store",
	}
)
