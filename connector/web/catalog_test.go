package web_test

import (
	"context"
	"encoding/json"
	"io/fs"
	"net/http"
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/tinfoilsh/confidential-agent-monitor/connector/web"
)

var noSlots = web.Slots{
	Claim:  func(string, uint32) int { return -1 },
	Covers: func(string, string) bool { return false },
	Bind: func(*http.Request, string, func(string) string) ([]string, func(*http.Request, func(context.Context, string) (string, error)) (*http.Request, error), error) {
		return nil, nil, nil
	},
}

type summary struct {
	Action  string   `json:"action"`
	Effects []string `json:"effects,omitempty"`
}

func TestShippedHTTPCatalogProjection(t *testing.T) {
	presets := os.DirFS("../../cmd/perimeter/presets")
	files, err := fs.Glob(presets, "*.json")
	if err != nil || len(files) == 0 {
		t.Fatalf("shipped presets: %v", err)
	}
	for _, file := range files {
		t.Run(strings.TrimSuffix(file, ".json"), func(t *testing.T) {
			source, err := fs.ReadFile(presets, file)
			if err != nil {
				t.Fatal(err)
			}
			setup, err := web.New(source, nil, nil, noSlots)
			if err != nil {
				t.Fatal(err)
			}
			var legacy struct {
				HTTP *struct {
					Operations map[string]summary `json:"operations"`
				} `json:"http"`
			}
			if err := json.Unmarshal(source, &legacy); err != nil {
				t.Fatal(err)
			}
			if (setup.Preset == nil) != (legacy.HTTP == nil) {
				t.Fatalf("preset presence changed")
			}
			if setup.Preset == nil {
				return
			}
			got := map[string]summary{}
			for id, op := range setup.Preset.Operations {
				got[id] = summary{op.Action, op.Effects}
			}
			want := legacy.HTTP.Operations
			if want == nil {
				want = map[string]summary{}
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("catalog changed: got %#v, want %#v", got, want)
			}
		})
	}
}

// The host, not the parser, decides which effect words are valid.
func TestParseKeepsPresetEffectWords(t *testing.T) {
	setup, err := web.Parse(json.RawMessage(`{"hosts":["example.com"]}`),
		json.RawMessage(`{"http":{"operations":{"get":{"action":"get","effects":["custom"],"method":"GET","origin":"https://example.com","path":"/","scope":{}}}}}`),
		nil, func(json.RawMessage) (web.Slots, error) { return noSlots, nil })
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(setup.Preset.Operations["get"].Effects, []string{"custom"}) {
		t.Fatal(setup.Preset.Operations)
	}
}
