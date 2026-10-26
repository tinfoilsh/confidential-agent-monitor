package web

import (
	"encoding/json"
	"net/url"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

// graphql returns nil for batches, persisted queries, URL envelopes, fragment spreads, directives and unset variables.
func graphql(body any, query url.Values) *GraphQLFacts {
	envelope, _ := body.(map[string]any)
	text, ok := envelope["query"].(string)
	if !ok {
		return nil
	}
	for key, value := range envelope {
		switch key {
		case "query":
		case "operationName":
			if _, ok := value.(string); !ok && value != nil {
				return nil
			}
		case "variables":
			if _, ok := value.(map[string]any); !ok && value != nil {
				return nil
			}
		default:
			return nil
		}
	}
	for _, key := range []string{"query", "operationName", "variables", "extensions"} {
		if query.Has(key) {
			return nil
		}
	}
	doc, err := parser.ParseQuery(&ast.Source{Input: text})
	if err != nil {
		return nil
	}
	op := selectOperation(doc.Operations, envelope["operationName"])
	if op == nil || len(op.Directives) > 0 {
		return nil
	}
	provided, _ := envelope["variables"].(map[string]any)
	declared, vars := map[string]bool{}, map[string]any{}
	for _, d := range op.VariableDefinitions {
		if declared[d.Variable] || len(d.Directives) > 0 {
			return nil
		}
		declared[d.Variable] = true
		if d.DefaultValue != nil {
			if vars[d.Variable], ok = value(d.DefaultValue, nil); !ok {
				return nil
			}
		}
	}
	for name, v := range provided {
		if !declared[name] {
			return nil
		}
		vars[name] = v
	}
	fields, ok := selections(op.SelectionSet, vars)
	if !ok {
		return nil
	}
	return &GraphQLFacts{Kind: string(op.Operation), Fields: fields}
}

// An operation name selects exactly one operation; without one, the document must hold only one.
func selectOperation(ops ast.OperationList, name any) *ast.OperationDefinition {
	if name == nil || name == "" {
		if len(ops) == 1 {
			return ops[0]
		}
		return nil
	}
	var selected *ast.OperationDefinition
	for _, op := range ops {
		if op.Name == name {
			if selected != nil {
				return nil
			}
			selected = op
		}
	}
	return selected
}

// selections returns the fields of one level and checks every level beneath it the same way.
func selections(set ast.SelectionSet, vars map[string]any) ([]GraphQLFieldFacts, bool) {
	fields := []GraphQLFieldFacts{}
	for _, s := range set {
		switch s := s.(type) {
		case *ast.Field:
			if len(s.Directives) > 0 {
				return nil, false
			}
			args := map[string]any{}
			for _, a := range s.Arguments {
				if _, dup := args[a.Name]; dup {
					return nil, false
				}
				v, ok := value(a.Value, vars)
				if !ok {
					return nil, false
				}
				args[a.Name] = v
			}
			if _, ok := selections(s.SelectionSet, vars); !ok {
				return nil, false
			}
			fields = append(fields, GraphQLFieldFacts{Name: s.Name, Arguments: args})
		case *ast.InlineFragment:
			if len(s.Directives) > 0 {
				return nil, false
			}
			inner, ok := selections(s.SelectionSet, vars)
			if !ok {
				return nil, false
			}
			fields = append(fields, inner...)
		default:
			return nil, false
		}
	}
	return fields, true
}

// value refuses unset variables, which the server may replace with unknown defaults, and repeated object fields.
func value(v *ast.Value, vars map[string]any) (any, bool) {
	switch v.Kind {
	case ast.Variable:
		set, ok := vars[v.Raw]
		return set, ok
	case ast.IntValue, ast.FloatValue:
		return json.Number(v.Raw), true
	case ast.StringValue, ast.BlockValue, ast.EnumValue:
		return v.Raw, true
	case ast.BooleanValue:
		return v.Raw == "true", true
	case ast.NullValue:
		return nil, true
	case ast.ListValue:
		list := []any{}
		for _, c := range v.Children {
			item, ok := value(c.Value, vars)
			if !ok {
				return nil, false
			}
			list = append(list, item)
		}
		return list, true
	case ast.ObjectValue:
		object := map[string]any{}
		for _, c := range v.Children {
			if _, dup := object[c.Name]; dup {
				return nil, false
			}
			item, ok := value(c.Value, vars)
			if !ok {
				return nil, false
			}
			object[c.Name] = item
		}
		return object, true
	}
	return nil, false
}
