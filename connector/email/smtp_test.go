package email_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"net/textproto"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/email"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/netx"
)

func TestSMTPUsesSuppliedServerAndAuthAndGatesSubmission(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	relay, err := email.ParseSMTP(json.RawMessage(`{"url":"smtps://mail.example.test","user":"sender"}`))
	if err != nil {
		t.Fatal(err)
	}
	var dials atomic.Int32
	var deny atomic.Bool
	serve := relay.Handler(
		func(context.Context, string, string) (net.Conn, error) {
			dials.Add(1)
			return nil, errors.New("no upstream in this test")
		},
		func(context.Context) (string, error) { return "stored", nil },
		func(_, username, _ string) error {
			if username != "agent" {
				return errors.New("unknown identity")
			}
			return nil
		},
		func(_ context.Context, _ string, backend smtp.Backend) *smtp.Server {
			s := smtp.NewServer(backend)
			s.Domain, s.AllowInsecureAuth, s.MaxMessageBytes = "mail.custom.test", true, 1<<10
			return s
		},
		netx.Listen)
	agent, stream := net.Pipe()
	defer agent.Close()
	agent.SetDeadline(time.Now().Add(10 * time.Second))
	go serve(ctx, stream, "", "smtp.test", 587, func(context.Context, facts.Event) error {
		if deny.Load() {
			return errors.New("denied for test")
		}
		return nil
	})
	conn := textproto.NewConn(agent)
	reply := func(line string) (int, string) {
		t.Helper()
		if line != "" {
			if err := conn.PrintfLine("%s", line); err != nil {
				t.Fatal(err)
			}
		}
		code, message, _ := conn.ReadResponse(0)
		return code, message
	}
	send := func(body string) int {
		t.Helper()
		for _, line := range []string{"MAIL FROM:<agent@custom.test>", "RCPT TO:<someone@example.test>", "DATA"} {
			if code, message := reply(line); code >= 400 {
				t.Fatalf("%s: %d %s", line, code, message)
			}
		}
		w := conn.DotWriter()
		w.Write([]byte("Subject: test\r\n\r\n" + body + "\r\n"))
		w.Close()
		code, _ := reply("")
		return code
	}
	plain := func(username string) string {
		return "AUTH PLAIN " + base64.StdEncoding.EncodeToString([]byte("\x00"+username+"\x00secret"))
	}

	if code, message := reply(""); code != 220 || !strings.HasPrefix(message, "mail.custom.test ") {
		t.Fatalf("greeting %d %q does not use the supplied domain", code, message)
	}
	reply("EHLO agent.test")
	if code, _ := reply(plain("stranger")); code == 235 {
		t.Fatal("AUTH accepted an identity the supplied authenticator refuses")
	}
	if code, message := reply(plain("agent")); code != 235 {
		t.Fatalf("AUTH refused the supplied authenticator's identity: %d %s", code, message)
	}
	if code := send(strings.Repeat("line\r\n", 1<<10)); code != 552 || dials.Load() != 0 {
		t.Fatalf("oversized message: %d, dials %d", code, dials.Load())
	}
	deny.Store(true)
	if code := send("hello"); code != 550 || dials.Load() != 0 {
		t.Fatalf("denied message: %d, dials %d", code, dials.Load())
	}
	deny.Store(false)
	if send("hello"); dials.Load() != 1 {
		t.Fatalf("admitted message dialed upstream %d times", dials.Load())
	}
}
