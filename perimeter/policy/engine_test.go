package policy_test

import (
	"context"
	"testing"

	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/policy"
)

func TestLibraryOwnsQueriesAndProtectedNamespaces(t *testing.T) {
	ctx := context.Background()
	library := policy.Library{
		Modules: map[string]string{"custom.rego": `package custom
answer := input.value + data.offset`},
		Queries:  map[string]string{"calculate": "data.custom.answer"},
		Reserved: []string{"custom", "offset"}, Data: map[string]any{"offset": 2},
		BasePackage: "data.custom.base",
	}
	e, err := policy.Prepare(ctx, library, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	got, err := policy.Eval[int](ctx, e, "calculate", map[string]any{"value": 40})
	if err != nil || got != 42 {
		t.Fatalf("got %v, %v", got, err)
	}
	if _, err := policy.Eval[bool](ctx, e, "decision", map[string]any{}); err == nil {
		t.Fatal("missing query accepted")
	}
	if _, err := policy.Eval[bool](ctx, e, "calculate", map[string]any{"value": 40}); err == nil {
		t.Fatal("wrong result shape accepted")
	}
	if _, err := policy.Prepare(ctx, library, "", map[string]any{"offset": 99}, nil); err == nil {
		t.Fatal("protected data replaced")
	}
	if _, err := policy.Prepare(ctx, library, "", nil, map[string]string{"override": `package custom.base
answer := true`}); err == nil {
		t.Fatal("protected module replaced")
	}
	if _, err := policy.Prepare(ctx, library, `package custom.base
answer := true`, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := policy.Prepare(ctx, library, `package other
answer := true`, nil, nil); err == nil {
		t.Fatal("wrong base namespace accepted")
	}
}
