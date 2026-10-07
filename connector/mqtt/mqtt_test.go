package mqtt

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/eclipse/paho.mqtt.golang/packets"
	"github.com/tinfoilsh/monitor/connector"
)

func mqttFixture(t *testing.T, gate func(connector.Event) error) (net.Conn, *bufio.Reader, <-chan net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err == nil {
			c.SetDeadline(time.Now().Add(10 * time.Second))
			accepted <- c
		}
	}()
	var m MQTT
	raw, _ := json.Marshal(map[string]any{"url": "mqtt://stored-user@" + ln.Addr().String(), "password": "stored-password"})
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	agent, monitor := net.Pipe()
	agent.SetDeadline(time.Now().Add(10 * time.Second))
	s := connector.NewStream(t.Context())
	s.Conn = monitor
	s.Gate = gate
	env := &connector.Env{Dialer: connector.NewDialer([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})}
	done := make(chan struct{})
	go func() { defer close(done); m.Serve(s, env) }()
	t.Cleanup(func() { agent.Close(); s.Close(); <-done })
	return agent, bufio.NewReader(agent), accepted
}

func connectPacket() *packets.ConnectPacket {
	p := packets.NewControlPacket(packets.Connect).(*packets.ConnectPacket)
	p.ProtocolName, p.ProtocolVersion, p.CleanSession = "MQTT", 4, true
	p.ClientIdentifier = "agent-chosen-id"
	p.Username, p.Password = "agent-user", []byte("agent-secret")
	p.UsernameFlag, p.PasswordFlag = true, true
	return p
}

func mustPacket(t *testing.T, r *bufio.Reader) packets.ControlPacket {
	t.Helper()
	p, err := readPacket(r)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func mustWrite(t *testing.T, p packets.ControlPacket, w net.Conn) {
	t.Helper()
	if err := p.Write(w); err != nil {
		t.Fatal(err)
	}
}

func handshake(t *testing.T, agent net.Conn, r *bufio.Reader, accepted <-chan net.Conn) (net.Conn, *bufio.Reader) {
	t.Helper()
	mustWrite(t, connectPacket(), agent)
	var up net.Conn
	select {
	case up = <-accepted:
	case <-time.After(3 * time.Second):
		t.Fatal("upstream was not connected")
	}
	t.Cleanup(func() { up.Close() })
	ur := bufio.NewReader(up)
	p := mustPacket(t, ur).(*packets.ConnectPacket)
	if p.Username != "stored-user" || string(p.Password) != "stored-password" || p.ClientIdentifier == "agent-chosen-id" || !p.CleanSession {
		t.Fatalf("credential/session substitution failed: user=%q id=%q", p.Username, p.ClientIdentifier)
	}
	mustWrite(t, packets.NewControlPacket(packets.Connack), up)
	if ack := mustPacket(t, r).(*packets.ConnackPacket); ack.ReturnCode != 0 {
		t.Fatal("connect failed")
	}
	return up, ur
}

func TestMQTTCredentialsPublishAndRetainedDelivery(t *testing.T) {
	events := make(chan connector.MQTTLayer, 20)
	a, r, accepted := mqttFixture(t, func(e connector.Event) error { events <- *e.MQTT; return nil })
	up, ur := handshake(t, a, r, accepted)
	p := packets.NewControlPacket(packets.Publish).(*packets.PublishPacket)
	p.TopicName, p.Payload, p.Retain = "lights/set", []byte(`{"on":true}`), true
	mustWrite(t, p, a)
	got := mustPacket(t, ur).(*packets.PublishPacket)
	if !got.Retain || !bytes.Equal(got.Payload, p.Payload) {
		t.Fatal("publish changed")
	}
	sub := packets.NewControlPacket(packets.Subscribe).(*packets.SubscribePacket)
	sub.MessageID, sub.Topics, sub.Qoss = 1, []string{"sensors/+"}, []byte{0}
	mustWrite(t, sub, a)
	mustPacket(t, ur)
	p.TopicName = "sensors/temperature"
	mustWrite(t, p, up)
	if got := mustPacket(t, r).(*packets.PublishPacket); got.TopicName != p.TopicName {
		t.Fatal("delivery changed")
	}
	commands := []string{"connect", "publish", "subscribe", "receive"}
	for _, want := range commands {
		select {
		case e := <-events:
			if e.Command != want {
				t.Fatalf("got %s, want %s", e.Command, want)
			}
		case <-time.After(time.Second):
			t.Fatal("missing event")
		}
	}
}

func TestMQTTDeniedDeliveryAndQoS2Release(t *testing.T) {
	for _, mode := range []string{"receive", "publish"} {
		t.Run(mode, func(t *testing.T) {
			var deny atomic.Bool
			a, r, accepted := mqttFixture(t, func(e connector.Event) error {
				if deny.Load() && e.MQTT.Command == mode {
					return errors.New("denied")
				}
				return nil
			})
			up, ur := handshake(t, a, r, accepted)
			p := packets.NewControlPacket(packets.Publish).(*packets.PublishPacket)
			p.TopicName, p.Payload = "private/value", []byte("secret")
			if mode == "receive" {
				deny.Store(true)
				mustWrite(t, p, up)
				if _, err := readPacket(r); err == nil {
					t.Fatal("denied delivery reached agent")
				}
			} else {
				p.Qos, p.MessageID = 2, 7
				mustWrite(t, p, a)
				mustPacket(t, ur)
				rec := packets.NewControlPacket(packets.Pubrec).(*packets.PubrecPacket)
				rec.MessageID = 7
				mustWrite(t, rec, up)
				mustPacket(t, r)
				deny.Store(true)
				rel := packets.NewControlPacket(packets.Pubrel).(*packets.PubrelPacket)
				rel.MessageID = 7
				mustWrite(t, rel, a)
				if _, err := readPacket(ur); err == nil {
					t.Fatal("revoked QoS 2 publish was released")
				}
			}
		})
	}
}

func TestMQTTRefusesPersistentSessionsAndWills(t *testing.T) {
	for _, mode := range []string{"persistent", "will"} {
		t.Run(mode, func(t *testing.T) {
			a, r, accepted := mqttFixture(t, func(connector.Event) error { t.Error("unsupported connect reached policy"); return nil })
			p := connectPacket()
			if mode == "persistent" {
				p.CleanSession = false
			} else {
				p.WillFlag = true
				p.WillTopic = "doors/unlock"
				p.WillMessage = []byte("yes")
			}
			mustWrite(t, p, a)
			if got := mustPacket(t, r).(*packets.ConnackPacket); got.ReturnCode != 5 {
				t.Fatal("unsafe session accepted")
			}
			select {
			case c := <-accepted:
				c.Close()
				t.Fatal("unsupported session reached broker")
			default:
			}
		})
	}
}

func TestMQTTMalformedFrames(t *testing.T) {
	for _, raw := range [][]byte{
		{0x30, 0xff, 0xff, 0x7f}, // allocation bound
		{0xc0, 0x80, 0},          // noncanonical length
		{0xc0, 1, 0},             // trailing body
		{0xc1, 0},                // reserved flags
		{0x36, 3, 0, 1, 'a'},     // invalid QoS
		{0x82, 2, 0, 1},          // empty subscription
		{0x40, 2, 0, 0},          // zero packet ID
	} {
		if _, err := readPacket(bufio.NewReader(bytes.NewReader(raw))); err == nil {
			t.Fatalf("accepted %x", raw)
		}
	}
	for _, topic := range []string{"", "a/#/b", "a+b", "$share/group/a", "a\x00b"} {
		if topicValid(topic, true) {
			t.Fatalf("accepted filter %q", topic)
		}
	}
	for _, topic := range []string{"sensors/+", "sensors/#", "/+/value", "#"} {
		if !topicValid(topic, true) {
			t.Fatalf("refused filter %q", topic)
		}
	}
	if _, err := readPacket(bufio.NewReader(strings.NewReader("\x30\x05\x00"))); err == nil {
		t.Fatal("truncated frame accepted")
	}
}

func FuzzMQTTFrame(f *testing.F) {
	f.Add([]byte{0xc0, 0})
	f.Add([]byte{0x30, 3, 0, 1, 'a'})
	f.Fuzz(func(t *testing.T, b []byte) { readPacket(bufio.NewReader(bytes.NewReader(b))) })
}
