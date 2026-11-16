// Package rego compiles Rego modules and evaluates their named queries.
package rego

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"

	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

// Program compiles Rego modules and evaluates named queries, failing closed.
type Program struct {
	queries map[string]rego.PreparedEvalQuery
}

// Prepare compiles modules, named by filename, over data and prepares each named query.
func Prepare(ctx context.Context, modules map[string]string, data map[string]any, queries map[string]string) (*Program, error) {
	if data == nil {
		data = map[string]any{}
	}
	opts := []func(*rego.Rego){rego.Store(inmem.NewFromObjectWithOpts(data, inmem.OptReturnASTValuesOnRead(true))), rego.StrictBuiltinErrors(true)}
	for _, name := range slices.Sorted(maps.Keys(modules)) {
		module, err := ast.ParseModule(name, modules[name])
		if err != nil {
			return nil, err
		}
		opts = append(opts, rego.ParsedModule(module))
	}
	p := &Program{queries: map[string]rego.PreparedEvalQuery{}}
	for _, name := range slices.Sorted(maps.Keys(queries)) {
		prepared, err := rego.New(append(slices.Clip(opts), rego.Query(queries[name]))...).PrepareForEval(ctx)
		if err != nil {
			return nil, err
		}
		p.queries[name] = prepared
	}
	return p, nil
}

// Package returns the path of a module's package after data, such as ["a", "b"] for package a.b.
func Package(filename, source string) ([]string, error) {
	module, err := ast.ParseModule(filename, source)
	if err != nil {
		return nil, err
	}
	var path []string
	for _, term := range module.Package.Path[1:] {
		name, ok := term.Value.(ast.String)
		if !ok {
			return nil, fmt.Errorf("%s: package path must be constant", filename)
		}
		path = append(path, string(name))
	}
	return path, nil
}

// Eval decodes one named query's result into out. Missing and malformed decisions fail closed.
func (p *Program) Eval(ctx context.Context, name string, input any, out any) error {
	query, ok := p.queries[name]
	if !ok {
		return fmt.Errorf("policy query %s is not configured", name)
	}
	in, err := facts.JSON[map[string]any](input)
	if err != nil {
		return err
	}
	// Each evaluation owns its lazy objects: OPA caches fields as it reads them.
	results, err := query.Eval(ctx, rego.EvalParsedInput(ast.LazyObject(in)))
	if err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	if len(results) != 1 || len(results[0].Expressions) != 1 {
		return errors.New("policy returned no decision")
	}
	if err := decodeRego(results[0].Expressions[0].Value, out); err != nil {
		return fmt.Errorf("policy returned an invalid decision: %w", err)
	}
	return nil
}

func decodeRego(value any, out any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return facts.DecodeNumbers(raw, out)
}
