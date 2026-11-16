package main

import (
	"context"
	"slices"
	"testing"
)

func TestProgramEvaluatesSuppliedQueriesAndFailsClosed(t *testing.T) {
	ctx := context.Background()
	modules := map[string]string{"custom.rego": `package custom
answer := input.value + data.offset`}
	p, err := prepareRego(ctx, modules, map[string]any{"offset": 2}, map[string]string{"calculate": "data.custom.answer"})
	if err != nil {
		t.Fatal(err)
	}
	var got int
	if err := p.Eval(ctx, "calculate", map[string]any{"value": 40}, &got); err != nil || got != 42 {
		t.Fatalf("got %v, %v", got, err)
	}
	var b bool
	if err := p.Eval(ctx, "decision", map[string]any{}, &b); err == nil {
		t.Fatal("missing query accepted")
	}
	if err := p.Eval(ctx, "calculate", map[string]any{"value": 40}, &b); err == nil {
		t.Fatal("wrong result shape accepted")
	}
	if err := p.Eval(ctx, "calculate", map[string]any{}, &got); err == nil {
		t.Fatal("undefined result accepted")
	}
	if _, err := prepareRego(ctx, map[string]string{"bad.rego": "package"}, nil, nil); err == nil {
		t.Fatal("unparsable module accepted")
	}
}

func TestPackageResistsBracketedPaths(t *testing.T) {
	for source, want := range map[string][]string{
		"package custom.base":      {"custom", "base"},
		`package custom["base.x"]`: {"custom", "base.x"},
	} {
		got, err := regoPackage("m.rego", source)
		if err != nil || !slices.Equal(got, want) {
			t.Fatalf("%s: got %v, %v", source, got, err)
		}
	}
}
