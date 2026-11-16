package web_test

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/tinfoilsh/confidential-agent-monitor/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/web"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/policy/standard"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/presets"
)

func TestShippedHTTPCatalogProjection(t *testing.T) {
	vocabulary := standard.Vocabulary()
	set, err := presets.Load(vocabulary, presets.Files)
	if err != nil {
		t.Fatal(err)
	}
	for name, preset := range set {
		t.Run(name, func(t *testing.T) {
			var parsed struct {
				HTTP *web.Preset `json:"http"`
			}
			if err := json.Unmarshal(preset.Source, &parsed); err != nil {
				t.Fatal(err)
			}
			got, err := parsed.HTTP.Catalog(vocabulary)
			if err != nil {
				t.Fatal(err)
			}
			var legacy struct {
				HTTP *struct {
					Operations map[string]facts.OperationSummary `json:"operations"`
				} `json:"http"`
			}
			if err := json.Unmarshal(preset.Source, &legacy); err != nil {
				t.Fatal(err)
			}
			var want map[string]facts.OperationSummary
			if legacy.HTTP != nil {
				want = legacy.HTTP.Operations
				if want == nil {
					want = map[string]facts.OperationSummary{}
				}
			}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("catalog changed: got %#v, want %#v", got, want)
			}
			entry, err := json.Marshal(preset.Entry(true, got))
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]json.RawMessage
			json.Unmarshal(entry, &fields)
			_, present := fields["operations"]
			if present != (legacy.HTTP != nil) {
				t.Fatalf("operations presence changed: %s", entry)
			}
		})
	}
}

func TestParseUsesSuppliedVocabularyAcrossWorkerEncoding(t *testing.T) {
	v := standard.Vocabulary()
	v.Effects["custom"] = facts.Obligations{}
	source := connector.Setup{Vocabulary: v, Config: json.RawMessage(`{"hosts":["example.com"]}`), Definition: json.RawMessage(`{"http":{"operations":{"get":{"action":"get","effects":["custom"],"method":"GET","origin":"https://example.com","path":"/","scope":{}}}}}`)}
	raw, err := json.Marshal(source)
	if err != nil {
		t.Fatal(err)
	}
	var workerSource connector.Setup
	if err := json.Unmarshal(raw, &workerSource); err != nil {
		t.Fatal(err)
	}
	prepared, err := web.Parse(workerSource)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(prepared.Operations["get"].Effects, []string{"custom"}) {
		t.Fatal(prepared.Operations)
	}
	workerSource.Vocabulary = standard.Vocabulary()
	if _, err := web.Parse(workerSource); err == nil {
		t.Fatal("undeclared effect accepted")
	}
}
