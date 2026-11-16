package policy

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

// Library supplies trusted modules, protected data and named queries. Prepare never
// installs defaults; the application chooses a library alongside its vocabulary.
type Library struct {
	Modules     map[string]string
	Queries     map[string]string
	Reserved    []string
	BasePackage string
	Data        map[string]any
}

type Engine struct {
	queries map[string]rego.PreparedEvalQuery
}

func Prepare(ctx context.Context, library Library, base string, data map[string]any, policies map[string]string) (*Engine, error) {
	reserved := library.Reserved
	for _, name := range reserved {
		if _, ok := data[name]; ok {
			return nil, fmt.Errorf("data.%s is reserved for the Perimeter", name)
		}
	}
	store := maps.Clone(data)
	if store == nil {
		store = map[string]any{}
	}
	maps.Copy(store, library.Data)
	opts := []func(*rego.Rego){rego.Store(inmem.NewFromObjectWithOpts(store, inmem.OptReturnASTValuesOnRead(true))), rego.StrictBuiltinErrors(true)}
	for _, name := range slices.Sorted(maps.Keys(library.Modules)) {
		opts = append(opts, rego.Module(name, library.Modules[name]))
	}
	if base != "" {
		module, err := ast.ParseModule("perimeter/base.rego", base)
		if err == nil && module.Package.Path.String() != library.BasePackage {
			err = fmt.Errorf("the base policy must be package %s, not %s", library.BasePackage, module.Package.Path)
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
	e := &Engine{queries: map[string]rego.PreparedEvalQuery{}}
	for _, name := range slices.Sorted(maps.Keys(library.Queries)) {
		prepared, err := rego.New(append(slices.Clip(opts), rego.Query(library.Queries[name]))...).PrepareForEval(ctx)
		if err != nil {
			return nil, err
		}
		e.queries[name] = prepared
	}
	return e, nil
}

// Eval decodes one named query's result. Missing and malformed decisions fail closed.
func Eval[T any](ctx context.Context, e *Engine, name string, in any) (T, error) {
	query, ok := e.queries[name]
	if !ok {
		var zero T
		return zero, fmt.Errorf("policy query %s is not configured", name)
	}
	return eval[T](ctx, query, in)
}

func eval[T any](ctx context.Context, query rego.PreparedEvalQuery, in any) (T, error) {
	var none T
	input, err := facts.JSON[map[string]any](in)
	if err != nil {
		return none, err
	}
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
