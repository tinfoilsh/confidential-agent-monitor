package tinfoil

import (
	"encoding/json"
	"reflect"
	"testing"

	"github.com/tinfoilsh/confidential-agent-monitor/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/policy/standard"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/presets"
)

func TestAttestedHTTPProjectsCatalogWithoutOpeningTransport(t *testing.T) {
	vocabulary := standard.Vocabulary()
	set, err := presets.Load(vocabulary, Presets)
	if err != nil {
		t.Fatal(err)
	}
	for name, p := range set {
		cfg := p.Catalog.Connection["tinfoil"]
		if cfg == nil {
			continue
		}
		prepared, err := Kind.Parse(connector.Setup{Config: cfg, Definition: p.Source, Vocabulary: vocabulary})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var old struct {
			HTTP struct {
				Operations map[string]facts.OperationSummary `json:"operations"`
			} `json:"http"`
		}
		if err := json.Unmarshal(p.Source, &old); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(prepared.Operations, old.HTTP.Operations) {
			t.Fatalf("%s: operations changed", name)
		}
	}
}
