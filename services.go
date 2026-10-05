package main

import (
	"context"
	"encoding/json"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"errors"
	"fmt"
	"net/textproto"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/tinfoilsh/monitor/connector/web"
)

// A service record is trusted security configuration, so parse refuses anything it does not recognize.
type service struct {
	Title      string             `json:"title"`
	Operations []serviceOperation `json:"operations"`
}

// Omitted fields keep their defaults when policy reads the record: no extra query keys, body none,
// and a grant of the whole scope. A null query, header or body field condition requires absence.
// The origin tenantOrigin stands for the account's policy_options.origin.
type serviceOperation struct {
	ID         string                    `json:"id"`
	Action     string                    `json:"action"`
	Effects    []string                  `json:"effects"`
	Method     string                    `json:"method"`
	Origin     string                    `json:"origin"`
	Path       string                    `json:"path"`
	Query      map[string]*string        `json:"query,omitempty"`
	Headers    map[string]*string        `json:"headers,omitempty"`
	Fields     map[string]jsontext.Value `json:"fields,omitempty"`
	Params     []string                  `json:"params,omitempty"`
	OpenParams bool                      `json:"open_params,omitempty"`
	Body       string                    `json:"body,omitempty"`
	GraphQL    *graphqlMatch             `json:"graphql,omitempty"`
	Scope      map[string]selector       `json:"scope"`
	Grant      *[]string                 `json:"grant,omitempty"`
}

type graphqlMatch struct {
	Operation string `json:"operation"`
	Field     string `json:"field"`
}

type selector struct {
	From   string `json:"from"`
	At     string `json:"at"`
	Header string `json:"header,omitempty"`
	Type   string `json:"type,omitempty"`
}

var (
	operationID  = regexp.MustCompile(`^[A-Za-z0-9_.-]+$`)
	actionName   = regexp.MustCompile(`^[a-z0-9_]+(\.[a-z0-9_]+)*$`)
	capture      = regexp.MustCompile(`^([^{}]*)\{([A-Za-z0-9_]+)(\*?)\}([^{}]*)$`)
	bodies       = []string{"", "none", "json", "form", "any", "graphql"}
	scopeTypes   = []string{"", "string", "number", "boolean", "array", "object"}
	selectorBody = map[string]string{"form": "form", "body": "json", "argument": "graphql"}
)

const tenantOrigin = "{origin}"

// vocabulary maps each effect lib.rego defines to whether it changes anything.
var vocabulary = sync.OnceValues(func() (map[string]bool, error) {
	rs, err := rego.New(append(templateModules(), rego.Query("data.monitor.vocabulary"))...).Eval(context.Background())
	if err != nil {
		return nil, err
	}
	effects := map[string]bool{}
	for e, obligations := range rs[0].Expressions[0].Value.(map[string]any) {
		effects[e] = obligations.(map[string]any)["change"] == true
	}
	return effects, nil
})

func parseServices(raw any) (map[string]service, error) {
	if raw == nil {
		return nil, nil
	}
	if err := noNull(raw); err != nil {
		return nil, err
	}
	encoded, _ := json.Marshal(raw)
	var services map[string]service
	// Unlike encoding/json, v2 matches field names exactly, so the keys policy reads are the keys validated.
	if err := jsonv2.Unmarshal(encoded, &services, jsonv2.RejectUnknownMembers(true)); err != nil {
		return nil, fmt.Errorf("data.services: %w", err)
	}
	effects, err := vocabulary()
	if err != nil {
		return nil, err
	}
	for svc, s := range services {
		ids := map[string]bool{}
		for i, o := range s.Operations {
			if err := o.validate(effects); err != nil {
				return nil, fmt.Errorf("data.services.%s operation %d: %w", svc, i, err)
			}
			if ids[o.ID] {
				return nil, fmt.Errorf("data.services.%s: operation %s is repeated", svc, o.ID)
			}
			ids[o.ID] = true
		}
		if s.Title == "" || len(s.Operations) == 0 {
			return nil, fmt.Errorf("data.services.%s needs a title and operations", svc)
		}
	}
	return services, nil
}

func (o *serviceOperation) validate(vocabulary map[string]bool) error {
	switch {
	case !operationID.MatchString(o.ID):
		return fmt.Errorf("id %q must be letters, digits, '_', '.' or '-'", o.ID)
	case !actionName.MatchString(o.Action):
		return fmt.Errorf("action %q must be dotted lowercase words", o.Action)
	case len(o.Effects) == 0:
		return fmt.Errorf("%s needs effects", o.ID)
	case !slices.Contains(web.Methods, o.Method):
		return fmt.Errorf("%s has unsupported method %q", o.ID, o.Method)
	case o.Origin != tenantOrigin && !web.ValidOrigin(o.Origin):
		return fmt.Errorf("%s origin must be https://host[:port] in lowercase without the default port, or %s", o.ID, tenantOrigin)
	case !slices.Contains(bodies, o.Body) || (o.Body == "graphql") != (o.GraphQL != nil):
		return fmt.Errorf("%s has an unsupported body, or graphql without body graphql", o.ID)
	case o.GraphQL != nil && (o.GraphQL.Field == "" || (o.GraphQL.Operation != "query" && o.GraphQL.Operation != "mutation")):
		return fmt.Errorf("%s graphql needs operation query or mutation and a field", o.ID)
	case o.Scope == nil:
		return fmt.Errorf("%s needs a scope; {} binds approvals to the operation alone", o.ID)
	}
	changes := false
	for i, e := range o.Effects {
		change, known := vocabulary[e]
		if !known || slices.Contains(o.Effects[:i], e) {
			return fmt.Errorf("%s has an unknown or repeated effect %q", o.ID, e)
		}
		changes = changes || change
	}
	if !changes && o.Body == "any" {
		return fmt.Errorf("%s changes nothing but accepts an opaque body", o.ID)
	}
	captures, err := routeCaptures(o.Path)
	if err != nil {
		return fmt.Errorf("%s: %w", o.ID, err)
	}
	for key := range o.Query {
		if key == "" || slices.Contains(o.Params, key) {
			return fmt.Errorf("%s query key %q is empty or also a param", o.ID, key)
		}
	}
	for key := range o.Headers {
		if key == "" || textproto.CanonicalMIMEHeaderKey(key) != key {
			return fmt.Errorf("%s header %q must be in canonical form", o.ID, key)
		}
	}
	// Conditions keep their exact JSON, so a number is never rounded into another value.
	for key, value := range o.Fields {
		kind := value.Kind()
		pointer := strings.HasPrefix(key, "/") && !strings.Contains(key, "~")
		if !(o.Body == "json" && pointer && kind != '[' && kind != '{') && !(o.Body == "form" && key != "" && (kind == '"' || kind == 'n')) {
			return fmt.Errorf("%s field %q needs a JSON pointer and a scalar on a json body, or a key and a string on a form body", o.ID, key)
		}
	}
	for field, s := range o.Scope {
		if err := s.validate(o, captures); err != nil {
			return fmt.Errorf("%s scope %s: %w", o.ID, field, err)
		}
	}
	if o.Grant != nil {
		for _, field := range *o.Grant {
			if _, ok := o.Scope[field]; !ok {
				return fmt.Errorf("%s grants %s, which is not in its scope", o.ID, field)
			}
		}
	}
	return nil
}

// noNull refuses null except as an operation's query, header or body field condition, where it means absence;
// elsewhere it would read as a default, such as a grant of the whole scope.
func noNull(raw any) error {
	services, _ := raw.(map[string]any)
	for _, s := range services {
		service, _ := s.(map[string]any)
		for key, value := range service {
			operations, ok := value.([]any)
			if key != "operations" || !ok {
				if err := nulls(value, false); err != nil {
					return err
				}
				continue
			}
			for _, o := range operations {
				operation, ok := o.(map[string]any)
				if !ok {
					return nulls(o, false)
				}
				for field, value := range operation {
					if err := nulls(value, field == "query" || field == "headers" || field == "fields"); err != nil {
						return err
					}
				}
			}
		}
	}
	return nil
}

func nulls(v any, conditions bool) error {
	switch v := v.(type) {
	case nil:
		return errors.New("data.services: null is allowed only as a query, header or body field condition")
	case map[string]any:
		for _, item := range v {
			if item == nil && conditions {
				continue
			}
			if err := nulls(item, false); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range v {
			if err := nulls(item, false); err != nil {
				return err
			}
		}
	}
	return nil
}

// routeCaptures checks a path pattern and returns its capture names.
func routeCaptures(path string) ([]string, error) {
	parts := strings.Split(path, "/")
	if parts[0] != "" || len(parts) < 2 {
		return nil, fmt.Errorf("path %q must start with /", path)
	}
	var names []string
	for i, part := range parts[1:] {
		if !strings.ContainsAny(part, "{}") {
			if part == "" && i < len(parts)-2 || part == "." || part == ".." {
				return nil, fmt.Errorf("path %q has an empty or dot segment", path)
			}
			continue
		}
		m := capture.FindStringSubmatch(part)
		rest := m != nil && m[3] == "*"
		if m == nil || slices.Contains(names, m[2]) || rest && (i < len(parts)-2 || m[1] != "" || m[4] != "") {
			return nil, fmt.Errorf("path %q has a malformed or repeated capture %q", path, part)
		}
		names = append(names, m[2])
	}
	return names, nil
}

func (s selector) validate(o *serviceOperation, captures []string) error {
	pointer := strings.HasPrefix(s.At, "/") || s.At == ""
	switch {
	case !slices.Contains(scopeTypes, s.Type):
		return fmt.Errorf("unknown type %q", s.Type)
	case (s.From == "header_json") != (s.Header != ""):
		return fmt.Errorf("header names the header_json source")
	case selectorBody[s.From] != "" && o.Body != selectorBody[s.From]:
		return fmt.Errorf("from %s needs body %s", s.From, selectorBody[s.From])
	}
	switch s.From {
	case "path":
		if !slices.Contains(captures, s.At) {
			return fmt.Errorf("the path has no capture %q", s.At)
		}
	case "query":
		if _, required := o.Query[s.At]; s.At != "" && !o.OpenParams && !required && !slices.Contains(o.Params, s.At) {
			return fmt.Errorf("query key %q is not accepted by the operation", s.At)
		}
	case "form":
	case "header":
		if s.At == "" || textproto.CanonicalMIMEHeaderKey(s.At) != s.At {
			return fmt.Errorf("header %q must be in canonical form", s.At)
		}
	case "header_json":
		if textproto.CanonicalMIMEHeaderKey(s.Header) != s.Header || !pointer || strings.Contains(s.At, "~") {
			return fmt.Errorf("needs a canonical header and a JSON pointer without ~")
		}
	case "body", "argument":
		if !pointer || strings.Contains(s.At, "~") {
			return fmt.Errorf("at %q must be a JSON pointer without ~", s.At)
		}
	default:
		return fmt.Errorf("unknown source %q", s.From)
	}
	return nil
}
