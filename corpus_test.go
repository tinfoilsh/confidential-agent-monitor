package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"io/fs"
	"os"
	"testing"

	"github.com/tinfoilsh/monitor/connector"
)

// corpusFile holds requests captured with -corpus; move them here from the dev file to keep them.
const corpusFile = "testdata/corpus.jsonl"

var update = flag.Bool("update", false, "rewrite "+corpusFile+" with the operation each request reaches now")

// TestCorpus replays captured requests against the shipped presets; each must reach the operation it recorded.
func TestCorpus(t *testing.T) {
	raw, err := os.ReadFile(corpusFile)
	if errors.Is(err, fs.ErrNotExist) {
		t.Skip("no captured requests in " + corpusFile)
	}
	if err != nil {
		t.Fatal(err)
	}
	cfg := &config{}
	if cfg.resolved, err = presets(); err != nil {
		t.Fatal(err)
	}
	query, _, err := preparePolicies(t.Context(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	for i, line := range bytes.Split(bytes.TrimSpace(raw), []byte("\n")) {
		var e corpusEntry
		if err := connector.DecodeNumbers(line, &e); err != nil {
			t.Fatalf("line %d: %v", i+1, err)
		}
		if e.Preset == "github_api" {
			e.Preset = "github"
		}
		a := account{Preset: e.Preset, PolicyOptions: policyOptions{Origin: e.Origin}, Contents: "anyone", Sends: "anyone"}
		d, err := evaluateDecision(t.Context(), query, input{Protocol: "http", Account: &namedAccount{"corpus", a}, Access: access{Level: "allow"},
			Label: cleanLabel, Event: &connector.Event{HTTP: e.HTTP, GraphQL: e.GraphQL}})
		if err != nil {
			t.Fatalf("line %d: %v", i+1, err)
		}
		if d.Operation != e.Operation && !*update {
			t.Errorf("line %d: %s %s%s reaches %q, recorded %q", i+1, e.HTTP.Method, e.HTTP.Origin, e.HTTP.Path, d.Operation, e.Operation)
		}
		e.Operation = d.Operation
		json.NewEncoder(&out).Encode(e)
	}
	if *update {
		if err := os.WriteFile(corpusFile, out.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}
