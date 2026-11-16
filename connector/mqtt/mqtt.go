package mqtt

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/url"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/eclipse/paho.mqtt.golang/packets"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

type MQTT struct {
	RawURL string `json:"url"`
	User   string `json:"user"`
	url    *url.URL
}

func Parse(config json.RawMessage) (*MQTT, error) {
	m := new(MQTT)
	if err := facts.DecodeNumbers(config, m); err != nil {
		return nil, err
	}
	u, err := url.Parse(m.RawURL)
	switch {
	case err != nil:
		return nil, err
	case u.Scheme == "" || u.Host == "":
		return nil, errors.New("destination requires a URL with a scheme and host")
	}
	if _, set := u.User.Password(); set || u.Query().Has("password") {
		return nil, errors.New("put the password in the service's password credential, not the URL")
	}
	if (u.Scheme != "mqtt" && u.Scheme != "mqtts") || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("MQTT requires an mqtt:// or mqtts:// host URL without a path, query or fragment")
	}
	if m.User != "" {
		u.User = url.User(m.User)
	}
	m.url = u
	return m, nil
}

func (m *MQTT) Hosts() []string { return []string{m.url.Hostname()} }

func (m *MQTT) dial(ctx context.Context, dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	address, port := m.url.Host, "1883"
	if m.url.Scheme == "mqtts" {
		port = "8883"
	}
	if m.url.Port() == "" {
		address = net.JoinHostPort(m.url.Hostname(), port)
	}
	c, err := dial(ctx, "tcp", address)
	if err != nil || m.url.Scheme != "mqtts" {
		return c, err
	}
	t := tls.Client(c, &tls.Config{ServerName: m.url.Hostname()})
	if err := t.HandshakeContext(ctx); err != nil {
		c.Close()
		return nil, err
	}
	return t, nil
}

func (m *MQTT) Handler(dial func(ctx context.Context, network, address string) (net.Conn, error), password func(context.Context) (string, error), maxPacket, maxPending int) func(context.Context, net.Conn, string, string, uint32, func(context.Context, facts.Event) error) {
	return func(ctx context.Context, s net.Conn, _, _ string, _ uint32, gate func(context.Context, facts.Event) error) {
		ctx, cancel := context.WithCancel(ctx)
		defer cancel()
		m.serve(ctx, cancel, s, gate, dial, password, maxPacket, maxPending)
	}
}

func (m *MQTT) serve(ctx context.Context, cancel func(), s net.Conn, gate func(context.Context, facts.Event) error, dial func(context.Context, string, string) (net.Conn, error), secret func(context.Context) (string, error), maxPacket, maxPending int) {
	reader := bufio.NewReader(s)
	packet, err := readPacket(reader, maxPacket)
	if err != nil {
		return
	}
	connect, ok := packet.(*packets.ConnectPacket)
	if !ok {
		return
	}
	refuse := func(code byte) {
		ack := packets.NewControlPacket(packets.Connack).(*packets.ConnackPacket)
		ack.ReturnCode = code
		ack.Write(s)
	}
	if connect.ProtocolName != "MQTT" || connect.ProtocolVersion != 4 {
		refuse(1)
		return
	}
	if connect.Validate() != 0 || !textValid(connect.ClientIdentifier) {
		refuse(2)
		return
	}
	if !connect.CleanSession || connect.WillFlag {
		refuse(5)
		return
	}
	if err := gate(ctx, facts.Capture((&MQTTFacts{Command: "connect"}).Describe(), nil)); err != nil {
		refuse(5)
		return
	}
	password, err := secret(ctx)
	if err != nil || len(password) > 65535 || len(m.url.User.Username()) > 65535 {
		refuse(4)
		return
	}
	id := make([]byte, 10)
	if _, err := rand.Read(id); err != nil {
		return
	}
	connect.ClientIdentifier = "mon" + hex.EncodeToString(id)
	connect.Username, connect.Password = m.url.User.Username(), []byte(password)
	connect.UsernameFlag = connect.Username != "" || password != ""
	connect.PasswordFlag = password != ""
	up, err := m.dial(ctx, dial)
	if err != nil {
		refuse(3)
		return
	}
	stop := context.AfterFunc(ctx, func() { up.Close() })
	defer func() { stop(); up.Close() }()
	if err := connect.Write(up); err != nil {
		return
	}
	replies := bufio.NewReader(up)
	packet, err = readPacket(replies, maxPacket)
	if err != nil {
		return
	}
	ack, ok := packet.(*packets.ConnackPacket)
	if !ok || ack.SessionPresent {
		return
	}
	if err := ack.Write(s); err != nil || ack.ReturnCode != 0 {
		return
	}
	p := proxy{ctx: ctx, s: s, gate: gate, up: up, maxPacket: maxPacket, maxPending: maxPending, pending: map[uint16]*packets.PublishPacket{}}
	pumped := make(chan struct{})
	go func() { defer close(pumped); p.replies(replies); cancel(); s.Close() }()
	defer func() { cancel(); s.Close(); <-pumped }()
	for {
		packet, err := readPacket(reader, maxPacket)
		if err != nil {
			return
		}
		if err := p.request(packet); err != nil {
			return
		}
		if err := packet.Write(up); err != nil {
			return
		}
		if _, ok := packet.(*packets.DisconnectPacket); ok {
			return
		}
	}
}

type proxy struct {
	ctx        context.Context
	s          net.Conn
	gate       func(context.Context, facts.Event) error
	up         net.Conn
	maxPacket  int
	maxPending int
	mu         sync.Mutex
	pending    map[uint16]*packets.PublishPacket
}

func (p *proxy) publish(command string, v *packets.PublishPacket) error {
	return p.gate(p.ctx, facts.Capture((&MQTTFacts{Command: command, Topic: v.TopicName, QoS: v.Qos, Retain: v.Retain, Payload: v.Payload}).Describe(), nil))
}

func (p *proxy) request(packet packets.ControlPacket) error {
	switch v := packet.(type) {
	case *packets.PublishPacket:
		p.mu.Lock()
		old := p.pending[v.MessageID]
		conflict := v.Qos != 0 && old != nil && (v.Qos != 2 || !v.Dup || old.TopicName != v.TopicName || old.Retain != v.Retain || !bytes.Equal(old.Payload, v.Payload))
		p.mu.Unlock()
		if conflict {
			return errors.New("MQTT packet ID is already in use")
		}
		if err := p.publish("publish", v); err != nil {
			return err
		}
		if v.Qos == 2 {
			p.mu.Lock()
			defer p.mu.Unlock()
			if len(p.pending) >= p.maxPending && p.pending[v.MessageID] == nil {
				return errors.New("too many pending MQTT publishes")
			}
			p.pending[v.MessageID] = v
		}
	case *packets.PubrelPacket:
		p.mu.Lock()
		publish := p.pending[v.MessageID]
		p.mu.Unlock()
		if publish == nil {
			return errors.New("unknown MQTT publish")
		}
		return p.publish("publish", publish)
	case *packets.SubscribePacket:
		for i, topic := range v.Topics {
			if err := p.gate(p.ctx, facts.Capture((&MQTTFacts{Command: "subscribe", Topic: topic, QoS: v.Qoss[i]}).Describe(), nil)); err != nil {
				return err
			}
		}
	case *packets.UnsubscribePacket:
	case *packets.PubackPacket, *packets.PubrecPacket, *packets.PubcompPacket, *packets.PingreqPacket, *packets.DisconnectPacket:
	default:
		return errors.New("unexpected MQTT client packet")
	}
	return nil
}

func (p *proxy) replies(r *bufio.Reader) {
	for {
		packet, err := readPacket(r, p.maxPacket)
		if err != nil {
			return
		}
		switch v := packet.(type) {
		case *packets.PublishPacket:
			if err := p.publish("receive", v); err != nil {
				return
			}
		case *packets.PubcompPacket:
			p.mu.Lock()
			delete(p.pending, v.MessageID)
			p.mu.Unlock()
		case *packets.PubackPacket, *packets.PubrecPacket, *packets.PubrelPacket, *packets.SubackPacket, *packets.UnsubackPacket, *packets.PingrespPacket:
		default:
			return
		}
		if err := packet.Write(p.s); err != nil {
			return
		}
	}
}

func readPacket(r *bufio.Reader, maxPacket int) (packets.ControlPacket, error) {
	first, err := r.ReadByte()
	if err != nil {
		return nil, err
	}
	kind, flags := first>>4, first&15
	if kind == 0 || kind > 14 {
		return nil, errors.New("invalid MQTT packet type")
	}
	if kind == packets.Publish {
		qos := flags >> 1 & 3
		if qos == 3 || qos == 0 && flags&8 != 0 {
			return nil, errors.New("invalid MQTT publish flags")
		}
	} else {
		want := byte(0)
		if kind == packets.Subscribe || kind == packets.Unsubscribe || kind == packets.Pubrel {
			want = 2
		}
		if flags != want {
			return nil, errors.New("invalid MQTT packet flags")
		}
	}
	raw := []byte{first}
	n := 0
	for i := 0; ; i++ {
		b, err := r.ReadByte()
		if err != nil {
			return nil, err
		}
		raw = append(raw, b)
		n |= int(b&127) << (7 * i)
		if n > maxPacket || i == 3 && b&128 != 0 {
			return nil, errors.New("MQTT packet too large")
		}
		if b&128 == 0 {
			break
		}
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	raw = append(raw, body...)
	p, err := packets.ReadPacket(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	var canonical bytes.Buffer
	if err := p.Write(&canonical); err != nil || !bytes.Equal(raw, canonical.Bytes()) {
		return nil, errors.New("malformed MQTT packet")
	}
	if err := validate(p); err != nil {
		return nil, err
	}
	return p, nil
}

func validate(p packets.ControlPacket) error {
	bad := errors.New("malformed MQTT packet")
	switch v := p.(type) {
	case *packets.ConnectPacket:
		if v.WillQos > 2 || !v.WillFlag && (v.WillQos != 0 || v.WillRetain) {
			return bad
		}
	case *packets.PublishPacket:
		if !topicValid(v.TopicName, false) || v.Qos != 0 && v.MessageID == 0 {
			return bad
		}
	case *packets.SubscribePacket:
		if v.MessageID == 0 || len(v.Topics) == 0 {
			return bad
		}
		for i, t := range v.Topics {
			if !topicValid(t, true) || v.Qoss[i] > 2 {
				return bad
			}
		}
	case *packets.UnsubscribePacket:
		if v.MessageID == 0 || len(v.Topics) == 0 {
			return bad
		}
		for _, t := range v.Topics {
			if !topicValid(t, true) {
				return bad
			}
		}
	case *packets.ConnackPacket:
		if v.ReturnCode > 5 {
			return bad
		}
	case *packets.SubackPacket:
		if len(v.ReturnCodes) == 0 {
			return bad
		}
		for _, code := range v.ReturnCodes {
			if code > 2 && code != 128 {
				return bad
			}
		}
	}
	switch p.(type) {
	case *packets.PubackPacket, *packets.PubrecPacket, *packets.PubrelPacket, *packets.PubcompPacket, *packets.SubackPacket, *packets.UnsubackPacket:
		if p.Details().MessageID == 0 {
			return bad
		}
	}
	return nil
}

func textValid(s string) bool {
	if !utf8.ValidString(s) {
		return false
	}
	for _, r := range s {
		if r == 0 || r >= 0xFDD0 && r <= 0xFDEF || r&0xFFFF == 0xFFFE || r&0xFFFF == 0xFFFF {
			return false
		}
	}
	return true
}

func topicValid(s string, filter bool) bool {
	if s == "" || !textValid(s) {
		return false
	}
	if !filter {
		return !strings.ContainsAny(s, "+#")
	}
	if strings.HasPrefix(s, "$share/") {
		return false
	}
	levels := strings.Split(s, "/")
	for i, level := range levels {
		if strings.Contains(level, "#") && (level != "#" || i != len(levels)-1) {
			return false
		}
		if strings.Contains(level, "+") && level != "+" {
			return false
		}
	}
	return true
}

func (v *MQTTFacts) Describe() facts.Observation {
	details := Details{MQTT: v}
	action := ""
	if slices.Contains([]string{"connect", "subscribe", "receive", "publish"}, v.Command) {
		action = v.Command
	}
	if v.Command == "publish" && v.Retain {
		action = "retain"
	}
	op := &facts.Operation{ID: v.Command, Action: action}
	parameters, _ := facts.JSON[map[string]any](v)
	return facts.Observation{Operation: op, Title: "MQTT " + v.Command + " " + v.Topic, Parameters: parameters, Details: details}
}
