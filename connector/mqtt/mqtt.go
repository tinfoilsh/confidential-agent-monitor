// Package mqtt mediates MQTT 3.1.1 clean sessions over the monitor tunnel.
package mqtt

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/eclipse/paho.mqtt.golang/packets"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/facts"
)

const maxPacket = 1 << 20

type MQTT struct{ connector.Endpoint }

func (m *MQTT) UnmarshalJSON(raw []byte) error {
	if err := json.Unmarshal(raw, &m.Endpoint); err != nil {
		return err
	}
	u := &m.URL
	if (u.Scheme != "mqtt" && u.Scheme != "mqtts") || u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("MQTT requires an mqtt:// or mqtts:// host URL without a path, query or fragment")
	}
	return nil
}

func (m *MQTT) Serve(s *connector.Stream, e *connector.Env) {
	defer s.Close()
	reader := bufio.NewReader(s)
	packet, err := readPacket(reader)
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
	// Persistent sessions can resume subscriptions without SUBSCRIBE. Wills can
	// publish after revocation or a monitor crash, when no gate can run.
	if !connect.CleanSession || connect.WillFlag {
		refuse(5)
		return
	}
	if err := s.Gate(&Request{Command: "connect"}); err != nil {
		refuse(5)
		return
	}
	password, err := m.Password.Value(s.Context)
	if err != nil || len(password) > 65535 || len(m.URL.User.Username()) > 65535 {
		refuse(4)
		return
	}
	// Never let an agent pick an upstream session ID or evict another client.
	id := make([]byte, 10)
	if _, err := rand.Read(id); err != nil {
		return
	}
	connect.ClientIdentifier = "mon" + hex.EncodeToString(id)
	connect.Username, connect.Password = m.URL.User.Username(), []byte(password)
	connect.UsernameFlag = connect.Username != "" || password != ""
	connect.PasswordFlag = password != ""
	up, err := connector.DialURL(s.Context, e.Dialer, &m.URL, "mqtts", "1883", "8883")
	if err != nil {
		refuse(3)
		return
	}
	defer s.Interrupt(up)()
	if err := connect.Write(up); err != nil {
		return
	}
	replies := bufio.NewReader(up)
	packet, err = readPacket(replies)
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
	p := proxy{s: s, up: up, pending: map[uint16]*packets.PublishPacket{}}
	done := make(chan struct{})
	go func() { defer close(done); defer s.Close(); p.replies(replies) }()
	defer func() { s.Close(); up.Close(); <-done }()
	for {
		packet, err := readPacket(reader)
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
	s       *connector.Stream
	up      net.Conn
	mu      sync.Mutex
	pending map[uint16]*packets.PublishPacket
}

func (p *proxy) publish(command string, v *packets.PublishPacket) error {
	return p.s.Gate(&Request{Command: command, Topic: v.TopicName, QoS: v.Qos, Retain: v.Retain, Payload: v.Payload})
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
			if len(p.pending) >= 16 && p.pending[v.MessageID] == nil {
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
		// QoS 2 takes effect on PUBREL, potentially after a policy change.
		return p.publish("publish", publish)
	case *packets.SubscribePacket:
		for i, topic := range v.Topics {
			if err := p.s.Gate(&Request{Command: "subscribe", Topic: topic, QoS: v.Qoss[i]}); err != nil {
				return err
			}
		}
	case *packets.UnsubscribePacket:
		// Removing a subscription only reduces access.
	case *packets.PubackPacket, *packets.PubrecPacket, *packets.PubcompPacket, *packets.PingreqPacket, *packets.DisconnectPacket:
	default:
		return errors.New("unexpected MQTT client packet")
	}
	return nil
}

func (p *proxy) replies(r *bufio.Reader) {
	for {
		packet, err := readPacket(r)
		if err != nil {
			return
		}
		switch v := packet.(type) {
		case *packets.PublishPacket:
			// Check the concrete topic, even for wildcard or retained deliveries.
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

// Bound allocations before handing a packet to the library. Re-encoding must
// consume exactly the original packet, rejecting trailing or noncanonical data.
func readPacket(r *bufio.Reader) (packets.ControlPacket, error) {
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
	// Shared subscriptions change delivery semantics and are outside MQTT 3.1.1.
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

type Request struct {
	Command string `json:"command"`
	Topic   string `json:"topic"`
	QoS     byte   `json:"qos"`
	Retain  bool   `json:"retain"`
	Payload []byte `json:"payload,omitempty"`
}

func (v *Request) Describe(c connector.Context) (facts.Facts, connector.Approval, error) {
	details := map[string]any{"mqtt": v}
	action := ""
	if slices.Contains([]string{"connect", "subscribe", "receive", "publish"}, v.Command) {
		action = v.Command
	}
	if v.Command == "publish" && v.Retain {
		action = "retain"
	}
	op := &facts.Operation{ID: v.Command, Action: action}
	if action == "" {
		op = nil
	}
	return facts.Facts{Operation: op, Title: "MQTT " + v.Command + " " + v.Topic, Parameters: connector.JSONFields(v), Details: details, Context: facts.Context{Sends: "account"}}, connector.Approval{}, nil
}
