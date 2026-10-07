package nats

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinfoilsh/monitor/connector"
)

type brokerFrame struct {
	line string
	body []byte
}
type testBroker struct {
	conn   net.Conn
	mu     sync.Mutex
	frames chan brokerFrame
	closed chan struct{}
}

func (b *testBroker) send(raw string) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	_, err := io.WriteString(b.conn, raw)
	return err
}
func (b *testBroker) next(t *testing.T) brokerFrame {
	t.Helper()
	select {
	case f := <-b.frames:
		return f
	case <-time.After(3 * time.Second):
		t.Fatal("missing broker request")
		return brokerFrame{}
	}
}

func natsFixture(t *testing.T, gate func(connector.Event) error) (net.Conn, *bufio.Reader, *testBroker) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	b := &testBroker{frames: make(chan brokerFrame, 32), closed: make(chan struct{})}
	ready := make(chan struct{})
	go func() {
		defer close(b.closed)
		conn, err := ln.Accept()
		if err != nil {
			close(ready)
			return
		}
		b.conn = conn
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		close(ready)
		defer conn.Close()
		b.send("INFO {\"server_id\":\"fixture\",\"version\":\"2.10.0\",\"proto\":1,\"headers\":true,\"max_payload\":1048576}\r\n")
		r := bufio.NewReaderSize(conn, maxLine)
		for {
			line, err := readLine(r)
			if err != nil {
				return
			}
			if line == "PING" {
				if b.send("PONG\r\n") != nil {
					return
				}
				continue
			}
			frame := brokerFrame{line: line}
			if strings.HasPrefix(line, "PUB ") || strings.HasPrefix(line, "HPUB ") {
				parts := strings.Fields(line)
				var n int
				fmt.Sscan(parts[len(parts)-1], &n)
				frame.body = make([]byte, n+2)
				if _, err := io.ReadFull(r, frame.body); err != nil {
					return
				}
			}
			b.frames <- frame
		}
	}()
	var n NATS
	raw, _ := json.Marshal(map[string]any{"url": "nats://stored-user@" + ln.Addr().String(), "password": "stored-password"})
	if err := json.Unmarshal(raw, &n); err != nil {
		t.Fatal(err)
	}
	agent, monitor := net.Pipe()
	agent.SetDeadline(time.Now().Add(10 * time.Second))
	s := connector.NewStream(t.Context())
	s.Conn = monitor
	s.Gate = gate
	env := &connector.Env{Dialer: connector.NewDialer([]netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")})}
	done := make(chan struct{})
	go func() { defer close(done); n.Serve(s, env) }()
	t.Cleanup(func() {
		agent.Close()
		s.Close()
		ln.Close()
		<-done
		<-ready
		if b.conn != nil {
			b.conn.Close()
		}
		<-b.closed
	})
	r := bufio.NewReader(agent)
	info, err := readLine(r)
	if err != nil || !strings.HasPrefix(info, "INFO ") || strings.Contains(info, "stored") {
		t.Fatalf("INFO: %s %v", info, err)
	}
	io.WriteString(agent, "CONNECT {\"verbose\":false,\"headers\":true,\"no_responders\":true,\"protocol\":1,\"user\":\"agent\",\"pass\":\"agent-secret\"}\r\n")
	io.WriteString(agent, "PING\r\n")
	if line, err := readLine(r); err != nil || line != "PONG" {
		t.Fatalf("PING: %q %v", line, err)
	}
	<-ready
	frame := b.next(t)
	if !strings.HasPrefix(frame.line, "CONNECT ") {
		t.Fatalf("handshake: %q", frame.line)
	}
	var auth map[string]any
	json.Unmarshal([]byte(strings.TrimPrefix(frame.line, "CONNECT ")), &auth)
	if auth["user"] != "stored-user" || auth["pass"] != "stored-password" || strings.Contains(frame.line, "agent-secret") {
		t.Fatal("upstream did not use stored credentials")
	}
	return agent, r, b
}

func TestNATSRequestReplyHeadersAndQueue(t *testing.T) {
	events := make(chan connector.NATSLayer, 16)
	a, r, b := natsFixture(t, func(e connector.Event) error { events <- *e.NATS; return nil })
	io.WriteString(a, "SUB results.* workers client-sub\r\n")
	sub := b.next(t)
	parts := strings.Fields(sub.line)
	if len(parts) != 4 || parts[0] != "SUB" || parts[1] != "results.*" || parts[2] != "workers" {
		t.Fatalf("subscription: %s", sub.line)
	}
	sid := parts[3]
	head := "NATS/1.0\r\nTrace: test\r\n\r\n"
	io.WriteString(a, fmt.Sprintf("HPUB jobs.report results.one %d %d\r\n%srun\r\n", len(head), len(head)+3, head))
	pub := b.next(t)
	if !strings.HasPrefix(pub.line, "HPUB jobs.report results.one ") || !bytes.Contains(pub.body, []byte("Trace: test\r\n")) || !bytes.HasSuffix(pub.body, []byte("run\r\n")) {
		t.Fatalf("publish: %q %q", pub.line, pub.body)
	}
	if err := b.send("MSG results.one " + sid + " reply.here 4\r\ndone\r\n"); err != nil {
		t.Fatal(err)
	}
	line, err := readLine(r)
	if err != nil || line != "MSG results.one client-sub reply.here 4" {
		t.Fatalf("delivery: %q %v", line, err)
	}
	data := make([]byte, 6)
	io.ReadFull(r, data)
	if string(data) != "done\r\n" {
		t.Fatalf("payload: %q", data)
	}
	for _, want := range []string{"connect", "subscribe", "publish", "receive"} {
		select {
		case e := <-events:
			if e.Command != want {
				t.Fatalf("event: %+v, want %s", e, want)
			}
			if want == "publish" && e.Reply != "results.one" {
				t.Fatal("reply subject missing from policy")
			}
			if want == "receive" && e.Queue != "workers" {
				t.Fatal("queue missing from policy")
			}
		case <-time.After(time.Second):
			t.Fatal("missing event")
		}
	}
}

func TestNATSDeniesPublishAndDelivery(t *testing.T) {
	for _, command := range []string{"publish", "receive"} {
		t.Run(command, func(t *testing.T) {
			var deny atomic.Bool
			a, r, b := natsFixture(t, func(e connector.Event) error {
				if deny.Load() && e.NATS.Command == command {
					return errors.New("denied")
				}
				return nil
			})
			if command == "publish" {
				deny.Store(true)
				io.WriteString(a, "PUB doors.unlock 3\r\nyes\r\n")
				line, err := readLine(r)
				if err != nil || !strings.HasPrefix(line, "-ERR ") {
					t.Fatalf("denial: %q %v", line, err)
				}
			} else {
				io.WriteString(a, "SUB private.> 1\r\n")
				sub := strings.Fields(b.next(t).line)
				deny.Store(true)
				b.send("MSG private.value " + sub[len(sub)-1] + " 6\r\nsecret\r\n")
				if line, err := readLine(r); err == nil {
					t.Fatalf("denied message delivered: %q", line)
				}
			}
			select {
			case frame := <-b.frames:
				if strings.HasPrefix(frame.line, "PUB ") {
					t.Fatal("denied publish reached broker")
				}
			case <-b.closed:
			}
		})
	}
}

func TestNATSFramingAndSubjects(t *testing.T) {
	for _, line := range []string{"PUB a -1", "PUB a 1048577", "PUB a.* 0", "PUB a reply.> 0", "HPUB a 12 1", "PUB a 1 extra extra"} {
		if _, err := message(strings.Fields(line), bufio.NewReader(strings.NewReader("x\r\n"))); err == nil {
			t.Fatalf("accepted %q", line)
		}
	}
	for _, raw := range []string{"x\n", strings.Repeat("x", maxLine) + "\r\n", "no terminator"} {
		if _, err := readLine(bufio.NewReaderSize(strings.NewReader(raw), maxLine)); err == nil {
			t.Fatal("malformed control line accepted")
		}
	}
	for _, s := range []string{"", "a..b", "a.>.b", "a*", "a.>.", "a\x00b"} {
		if subjectValid(s, true) {
			t.Fatalf("invalid subject accepted: %q", s)
		}
	}
	for _, s := range []string{"a.*", "a.>", "_INBOX.reply", "$JS.API.INFO"} {
		if !subjectValid(s, true) {
			t.Fatalf("valid subject refused: %q", s)
		}
	}
	head := "NATS/1.0\r\n\r\nignored\r\n\r\n"
	if _, err := message([]string{"HPUB", "a", fmt.Sprint(len(head)), fmt.Sprint(len(head))}, bufio.NewReader(strings.NewReader(head+"\r\n"))); err == nil {
		t.Fatal("trailing headers accepted")
	}
}

func FuzzNATSPublish(f *testing.F) {
	f.Add("PUB a 1", []byte("x\r\n"))
	f.Fuzz(func(t *testing.T, line string, body []byte) {
		args := strings.Fields(line)
		if len(args) > 0 {
			message(args, bufio.NewReader(bytes.NewReader(body)))
		}
	})
}
