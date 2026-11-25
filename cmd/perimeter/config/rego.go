package config

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"

	"github.com/google/jsonschema-go/jsonschema"
	"github.com/open-policy-agent/opa/v1/ast"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

type Program struct {
	query rego.PreparedEvalQuery
}

func prepareRego(ctx context.Context, modules map[string]string, data map[string]any, input *ast.SchemaSet) (*Program, error) {
	if data == nil {
		data = map[string]any{}
	}
	opts := []func(*rego.Rego){rego.Store(inmem.NewFromObjectWithOpts(data, inmem.OptReturnASTValuesOnRead(true))), rego.StrictBuiltinErrors(true), rego.Schemas(input)}
	for _, name := range slices.Sorted(maps.Keys(modules)) {
		module, err := ast.ParseModule(name, modules[name])
		if err != nil {
			return nil, err
		}
		opts = append(opts, rego.ParsedModule(module))
	}
	query, err := rego.New(append(opts, rego.Query(decisionQuery))...).PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}
	return &Program{query: query}, nil
}

// A rule that reads a field the input lacks never applies, which fails open for an approval, so reading one is a type error.
func inputSchema[F any]() (*ast.SchemaSet, error) {
	opts := &jsonschema.ForOptions{TypeSchemas: map[reflect.Type]*jsonschema.Schema{reflect.TypeFor[json.RawMessage](): {}}}
	input, err := jsonschema.For[DecisionInput](opts)
	if err == nil {
		input.Properties["facts"], err = jsonschema.For[F](opts)
	}
	var schema any
	if err == nil {
		schema, err = facts.JSON[any](input)
	}
	if err != nil {
		return nil, err
	}
	set := ast.NewSchemaSet()
	set.Put(ast.SchemaRootRef, schema)
	return set, nil
}

func regoModule(filename, source string) (*ast.Module, []string, error) {
	module, err := ast.ParseModule(filename, source)
	if err != nil {
		return nil, nil, err
	}
	var path []string
	for _, term := range module.Package.Path[1:] {
		name, ok := term.Value.(ast.String)
		if !ok {
			return nil, nil, fmt.Errorf("%s: package path must be constant", filename)
		}
		path = append(path, string(name))
	}
	return module, path, nil
}

func (p *Program) Decide(ctx context.Context, input DecisionInput) (Decision, error) {
	var d Decision
	in, err := facts.JSON[map[string]any](input)
	if err != nil {
		return d, err
	}
	results, err := p.query.Eval(ctx, rego.EvalParsedInput(ast.LazyObject(in)))
	if err != nil {
		return d, fmt.Errorf("policy: %w", err)
	}
	if len(results) != 1 || len(results[0].Expressions) != 1 {
		return d, errors.New("policy returned no decision")
	}
	raw, err := json.Marshal(results[0].Expressions[0].Value)
	if err == nil {
		err = facts.DecodeNumbers(raw, &d)
	}
	if err == nil {
		err = d.Validate()
	}
	if err != nil {
		return d, fmt.Errorf("policy returned an invalid decision: %w", err)
	}
	return d, nil
}
