package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"

	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/parser"
)

var errDirectives = errors.New("directives such as @include are not supported")

func graphql(body any, query url.Values) (*GraphQLFacts, error) {
	envelope, _ := body.(map[string]any)
	text, ok := envelope["query"].(string)
	if !ok {
		return nil, errors.New("send a JSON object with a query string and Content-Type: application/json")
	}
	for key, value := range envelope {
		switch key {
		case "query":
		case "operationName":
			if _, ok := value.(string); !ok && value != nil {
				return nil, errors.New("operationName must be a string")
			}
		case "variables":
			if _, ok := value.(map[string]any); !ok && value != nil {
				return nil, errors.New("variables must be an object")
			}
		default:
			return nil, fmt.Errorf("the field %s is not supported", key)
		}
	}
	for _, key := range []string{"query", "operationName", "variables", "extensions"} {
		if query.Has(key) {
			return nil, fmt.Errorf("%s cannot be sent in the URL", key)
		}
	}
	doc, err := parser.ParseQuery(&ast.Source{Input: text})
	if err != nil {
		return nil, err
	}
	op := selectOperation(doc.Operations, envelope["operationName"])
	if op == nil {
		return nil, errors.New("operationName must name exactly one operation in the document")
	}
	if len(op.Directives) > 0 {
		return nil, errDirectives
	}
	provided, _ := envelope["variables"].(map[string]any)
	declared, vars := map[string]bool{}, map[string]any{}
	for _, d := range op.VariableDefinitions {
		if declared[d.Variable] {
			return nil, fmt.Errorf("variable $%s is declared twice", d.Variable)
		}
		if len(d.Directives) > 0 {
			return nil, errDirectives
		}
		declared[d.Variable] = true
		if d.DefaultValue != nil {
			if vars[d.Variable], err = value(d.DefaultValue, nil); err != nil {
				return nil, err
			}
		}
	}
	for name, v := range provided {
		if !declared[name] {
			return nil, fmt.Errorf("variable $%s is not declared", name)
		}
		vars[name] = v
	}
	fields, err := selections(op.SelectionSet, vars)
	if err != nil {
		return nil, err
	}
	return &GraphQLFacts{Kind: string(op.Operation), Fields: fields}, nil
}

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

func selections(set ast.SelectionSet, vars map[string]any) ([]GraphQLFieldFacts, error) {
	fields := []GraphQLFieldFacts{}
	for _, s := range set {
		switch s := s.(type) {
		case *ast.Field:
			if len(s.Directives) > 0 {
				return nil, errDirectives
			}
			args := map[string]any{}
			for _, a := range s.Arguments {
				if _, dup := args[a.Name]; dup {
					return nil, fmt.Errorf("%s repeats the argument %s", s.Name, a.Name)
				}
				v, err := value(a.Value, vars)
				if err != nil {
					return nil, err
				}
				args[a.Name] = v
			}
			if _, err := selections(s.SelectionSet, vars); err != nil {
				return nil, err
			}
			fields = append(fields, GraphQLFieldFacts{Name: s.Name, Arguments: args})
		case *ast.InlineFragment:
			if len(s.Directives) > 0 {
				return nil, errDirectives
			}
			inner, err := selections(s.SelectionSet, vars)
			if err != nil {
				return nil, err
			}
			fields = append(fields, inner...)
		default:
			return nil, errors.New("named fragments are not supported; use inline fragments such as ... on Issue")
		}
	}
	return fields, nil
}

func value(v *ast.Value, vars map[string]any) (any, error) {
	switch v.Kind {
	case ast.Variable:
		set, ok := vars[v.Raw]
		if !ok {
			return nil, fmt.Errorf("variable $%s has no value", v.Raw)
		}
		return set, nil
	case ast.IntValue, ast.FloatValue:
		return json.Number(v.Raw), nil
	case ast.StringValue, ast.BlockValue, ast.EnumValue:
		return v.Raw, nil
	case ast.BooleanValue:
		return v.Raw == "true", nil
	case ast.NullValue:
		return nil, nil
	case ast.ListValue:
		list := []any{}
		for _, c := range v.Children {
			item, err := value(c.Value, vars)
			if err != nil {
				return nil, err
			}
			list = append(list, item)
		}
		return list, nil
	case ast.ObjectValue:
		object := map[string]any{}
		for _, c := range v.Children {
			if _, dup := object[c.Name]; dup {
				return nil, fmt.Errorf("an object repeats the key %s", c.Name)
			}
			item, err := value(c.Value, vars)
			if err != nil {
				return nil, err
			}
			object[c.Name] = item
		}
		return object, nil
	}
	return nil, fmt.Errorf("unsupported value %s", v.Raw)
}
