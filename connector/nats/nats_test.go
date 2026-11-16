package nats_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/connector/nats"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

func TestNATSUsesSuppliedNameAndGatesPublishes(t *testing.T) {
	endpoint, err := nats.Parse(json.RawMessage(`{"url":"nats://nats.example.test:4222"}`))
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var upstream []string
	closed := make(chan struct{})
	dial := func(context.Context, string, string) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			defer close(closed)
			defer server.Close()
			server.SetDeadline(time.Now().Add(10 * time.Second))
			io.WriteString(server, `INFO {"server_id":"upstream","version":"2.10.0","proto":1,"headers":true,"max_payload":1024}`+"\r\n")
			r := bufio.NewReader(server)
			for {
				line, err := r.ReadString('\n')
				if err != nil {
					return
				}
				mu.Lock()
				upstream = append(upstream, line)
				mu.Unlock()
				if strings.HasPrefix(line, "PING") {
					io.WriteString(server, "PONG\r\n")
				}
			}
		}()
		return client, nil
	}
	limits := nats.Limits{Payload: 1 << 10, Line: 1 << 10, Subscriptions: 1, PendingMessages: 1, PendingBytes: 1 << 10, Timeout: 5 * time.Second}
	serve := endpoint.Preauthenticated(dial, func(context.Context, string) (string, error) { return "", nil }, limits, "custom-nats")
	agent, stream := net.Pipe()
	defer agent.Close()
	agent.SetDeadline(time.Now().Add(10 * time.Second))
	go serve(t.Context(), stream, "", "nats.test", 4222, func(_ context.Context, e facts.Event) error {
		if o, err := e.Decode(); err != nil || o.Parameters["subject"] == "denied" {
			return errors.New("denied for test")
		}
		return nil
	})
	replies := bufio.NewReader(agent)
	read := func() string {
		t.Helper()
		line, err := replies.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		return line
	}

	if info := read(); !strings.Contains(info, `"server_id":"custom-nats","server_name":"custom-nats"`) {
		t.Fatalf("INFO does not carry the supplied name: %s", info)
	}
	io.WriteString(agent, "CONNECT {\"verbose\":false}\r\nPUB allowed 2\r\nhi\r\nPING\r\n")
	if pong := read(); pong != "PONG\r\n" {
		t.Fatalf("admitted publish: %q", pong)
	}
	io.WriteString(agent, "PUB denied 2\r\nno\r\n")
	if refusal := read(); !strings.HasPrefix(refusal, "-ERR") {
		t.Fatalf("denied publish: %q", refusal)
	}
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("refused publish did not close the upstream connection")
	}
	mu.Lock()
	defer mu.Unlock()
	sent := strings.Join(upstream, "")
	if !strings.Contains(sent, `"name":"custom-nats"`) || !strings.Contains(sent, "PUB allowed 2\r\nhi\r\n") || strings.Contains(sent, "denied") {
		t.Fatalf("upstream received %q", sent)
	}
}
