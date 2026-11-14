package policy

import (
	"context"
	_ "embed"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/tinfoilsh/monitor/facts"
)

//go:embed lib.rego
var library string

// Base is an optional module in basePackage, set once at start, that every engine loads; lib.rego reads its hooks.
var Base string

const basePackage = "data.perimeter.base"

type Decision struct {
	Deny         []string            `json:"deny"`
	Requirements []facts.Requirement `json:"requirements"`
	Sends        string              `json:"sends"`
	Next         facts.Label         `json:"next"`
}

// Engine is a prepared policy.
type Engine struct {
	decision, admin rego.PreparedEvalQuery
}

func Prepare(ctx context.Context, data map[string]any, policies map[string]string, confidentiality, integrity bool) (*Engine, error) {
	reserved := []string{"perimeter", "lattices", "levels"}
	for _, name := range reserved {
		if _, ok := data[name]; ok {
			return nil, fmt.Errorf("data.%s is reserved for the Perimeter", name)
		}
	}
	store := maps.Clone(data)
	if store == nil {
		store = map[string]any{}
	}
	store["levels"] = map[string]any{"audiences": facts.Audiences, "trusts": facts.Trusts, "effects": facts.Effects}
	store["lattices"] = map[string]any{"confidentiality": confidentiality, "integrity": integrity}
	opts := []func(*rego.Rego){rego.Module("perimeter/lib.rego", library),
		rego.Store(inmem.NewFromObjectWithOpts(store, inmem.OptReturnASTValuesOnRead(true))), rego.StrictBuiltinErrors(true)}
	if Base != "" {
		module, err := ast.ParseModule("perimeter/base.rego", Base)
		if err == nil && module.Package.Path.String() != basePackage {
			err = fmt.Errorf("the base policy must be package %s, not %s", basePackage, module.Package.Path)
		}
		if err != nil {
			return nil, err
		}
		opts = append(opts, rego.ParsedModule(module))
	}
	for _, name := range slices.Sorted(maps.Keys(policies)) {
		filename := "policies/" + name
		module, err := ast.ParseModule(filename, policies[name])
		if err != nil {
			return nil, err
		}
		for _, r := range reserved {
			if module.Package.Path.HasPrefix(ast.MustParseRef("data." + r)) {
				return nil, fmt.Errorf("policy %s: data.%s is reserved for the Perimeter", name, r)
			}
		}
		opts = append(opts, rego.ParsedModule(module))
	}
	var e Engine
	for query, prepared := range map[string]*rego.PreparedEvalQuery{"data.perimeter.decision": &e.decision, "data.perimeter.admin_deny": &e.admin} {
		var err error
		if *prepared, err = rego.New(append(slices.Clip(opts), rego.Query(query))...).PrepareForEval(ctx); err != nil {
			return nil, err
		}
	}
	return &e, nil
}

func (e *Engine) Decide(ctx context.Context, input map[string]any) (Decision, error) {
	return eval[Decision](ctx, e.decision, input)
}

// AdminDeny lists why policy refuses the admin call described by input; an empty list admits it.
func (e *Engine) AdminDeny(ctx context.Context, input map[string]any) ([]string, error) {
	return eval[[]string](ctx, e.admin, input)
}

func eval[T any](ctx context.Context, query rego.PreparedEvalQuery, input map[string]any) (T, error) {
	var none T
	// Each evaluation owns its lazy objects: OPA caches fields as it reads them.
	results, err := query.Eval(ctx, rego.EvalParsedInput(ast.LazyObject(input)))
	if err != nil {
		return none, fmt.Errorf("policy: %w", err)
	}
	if len(results) != 1 || len(results[0].Expressions) != 1 {
		return none, errors.New("policy returned no decision")
	}
	d, err := facts.JSON[T](results[0].Expressions[0].Value)
	if err != nil {
		return none, fmt.Errorf("policy returned an invalid decision: %w", err)
	}
	return d, nil
}
