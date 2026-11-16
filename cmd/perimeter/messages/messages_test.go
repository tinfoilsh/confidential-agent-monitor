package messages_test

import (
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/messages"
)

func stream(body string) *http.Response {
	return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(body))}
}

func TestStreamConvertsChunksWithinSuppliedLimits(t *testing.T) {
	chunks := `data: {"id":"c1","choices":[{"delta":{"content":"Hi"}}]}

data: {"id":"c1","choices":[{"delta":{"tool_calls":[{"index":0,"id":"t1","function":{"name":"run","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":3,"completion_tokens":2}}

data: [DONE]

`
	limits := messages.Limits{ErrorBytes: 1 << 10, ResultBytes: 1 << 10, EventBytes: 1 << 10}
	resp, err := messages.Response(nil, stream(chunks), "model", true, limits)
	if err != nil {
		t.Fatal(err)
	}
	out, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"event: message_start", `{"text":"Hi","type":"text_delta"}`, `"type":"tool_use"`, `"stop_reason":"tool_use"`, "event: message_stop"} {
		if !strings.Contains(string(out), want) {
			t.Fatalf("missing %s in %s", want, out)
		}
	}

	limits.EventBytes = 32
	resp, err = messages.Response(nil, stream(chunks), "model", true, limits)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(resp.Body); err == nil {
		t.Fatal("an event over the supplied limit was converted")
	}
}
