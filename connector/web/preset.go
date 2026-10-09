package web

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/facts"
)

type Request struct {
	HTTP    *facts.HTTP    `json:"http"`
	GraphQL *facts.GraphQL `json:"graphql,omitempty"`
}

func (r *Request) Describe(c connector.Context) (facts.Facts, error) {
	details := facts.Details{HTTP: r.HTTP}
	if r.GraphQL != nil {
		details.GraphQL = r.GraphQL
	}
	f := facts.Facts{Details: details}
	h := r.HTTP
	p, _ := c.Spec.(*CompiledPreset)
	if p != nil {
		return p.Match(r, c, f)
	}
	action := "browse"
	if !slices.Contains([]string{"GET", "HEAD", "OPTIONS"}, h.Method) {
		action = "submit"
	}
	f.Operation = &facts.Operation{Action: action}
	f.Title = h.Method + " " + h.Host + h.Path
	f.Parameters = map[string]any{"host": h.Host}
	return f, nil
}

// Preset contains reviewed HTTP operations, including GraphQL requests.
type Preset struct {
	Operations map[string]Operation `json:"operations"`
	Slots      bool                 `json:"slots,omitempty"`
}

func (p *Preset) validate() error {
	for id, o := range p.Operations {
		if o.Enabled != nil && !*o.Enabled {
			continue
		}
		if id == "" || o.Action == "" || !facts.ValidEffects(o.Effects) {
			return fmt.Errorf("invalid operation %q", id)
		}
		if o.Method == "" || o.Origin == "" || o.Path == "" || o.Scope == nil {
			return fmt.Errorf("operation %s needs method, origin, path and scope", id)
		}
		for _, name := range o.Grant {
			if _, ok := o.Scope[name]; !ok {
				return fmt.Errorf("grant names missing scope %s", name)
			}
		}
		if !slices.Contains([]string{"", "me", "team", "anyone", "account"}, o.Sends) || !slices.Contains([]string{"", "none", "json", "form", "any", "graphql"}, o.Body) {
			return fmt.Errorf("invalid audience or body kind for %s", id)
		}
		if g := o.GraphQL; g != nil {
			if o.Body != "graphql" || (g.Field == "") == (len(g.Fields) == 0) || !slices.Contains([]string{"query", "mutation", "subscription"}, g.Operation) {
				return fmt.Errorf("invalid graphql matcher for %s", id)
			}
		} else if o.Body == "graphql" {
			return fmt.Errorf("missing graphql matcher for %s", id)
		}
	}

	return nil
}

type Operation struct {
	Enabled    *bool               `json:"enabled,omitempty"`
	ID         string              `json:"-"`
	Action     string              `json:"action"`
	Effects    []string            `json:"effects"`
	Method     string              `json:"method"`
	Origin     string              `json:"origin"`
	Path       string              `json:"path"`
	Query      map[string]any      `json:"query,omitempty"`
	Headers    map[string]any      `json:"headers,omitempty"`
	Fields     map[string]any      `json:"fields,omitempty"`
	Params     []string            `json:"params,omitempty"`
	OpenParams bool                `json:"open_params,omitempty"`
	Body       string              `json:"body,omitempty"`
	GraphQL    *GraphQLMatch       `json:"graphql,omitempty"`
	Scope      map[string]Selector `json:"scope"`
	Grant      []string            `json:"grant,omitempty"`
	Sends      string              `json:"sends,omitempty"`
}

type GraphQLMatch struct {
	Operation string   `json:"operation"`
	Field     string   `json:"field,omitempty"`
	Fields    []string `json:"fields,omitempty"`
}

type Selector struct {
	From       string `json:"from,omitempty"`
	Header     string `json:"header,omitempty"`
	TrimSuffix string `json:"trim_suffix,omitempty"`
	At         string `json:"at"`
	Type       string `json:"type,omitempty"`
	Optional   bool   `json:"optional,omitempty"`
}

type compiledSelector struct {
	Selector
	name    string
	pointer func(any) (any, bool)
}

func (compiled *compiledOperation) matches(r *Request, headers map[string][]string) (bool, error) {
	o, h := compiled.operation, r.HTTP
	for k, v := range o.Query {
		if !condition(h.Query, k, v) {
			return false, nil
		}
	}
	for _, conditionSpec := range compiled.headers {
		if !condition(headers, conditionSpec.key, conditionSpec.value) {
			return false, nil
		}
	}

	for k := range h.Query {
		if _, ok := o.Query[k]; !ok && !o.OpenParams && !compiled.params[k] {
			return false, nil
		}
	}
	body := o.Body
	if body == "" {
		body = "none"
	}
	for k, v := range o.Fields {
		switch body {
		case "form":
			if !condition(h.Form, k, v) {
				return false, nil
			}
		case "json":
			got, present := compiled.fields[k](h.Body)
			if v == nil {
				if present {
					return false, nil
				}
			} else if !present || !connector.EqualJSON(got, v) {
				return false, nil
			}
		default:
			return false, nil
		}
	}
	if body == "any" {
		return true, nil
	}
	if body == "graphql" {
		g, spec := r.GraphQL, o.GraphQL
		if g == nil {
			return false, fmt.Errorf("the GraphQL document could not be decoded")
		}
		if h.BodyKind != "json" || g.Kind != spec.Operation || len(g.Fields) == 0 {
			return false, nil
		}
		if spec.Field != "" {
			return spec.Field == "*" || len(g.Fields) == 1 && g.Fields[0].Name == spec.Field, nil
		}
		return !slices.ContainsFunc(g.Fields, func(f facts.GraphQLField) bool { return !slices.Contains(spec.Fields, f.Name) }), nil
	}
	return h.BodyKind == body, nil
}

func condition(values map[string][]string, key string, want any) bool {
	got, present := values[key]
	if want == nil {
		return !present
	}
	s, ok := want.(string)
	return ok && len(got) == 1 && got[0] == s
}

func compileSelector(raw Selector) (compiledSelector, error) {
	spec := compiledSelector{Selector: raw}
	if !slices.Contains([]string{"path", "query", "form", "body", "header", "header_json", "argument", "http"}, spec.From) || !connector.ValidJSONType(spec.Type) {
		return spec, fmt.Errorf("invalid selector source %q or type %q", spec.From, spec.Type)
	}
	if slices.Contains([]string{"body", "header_json", "argument", "http"}, spec.From) {
		at := spec.At
		var err error
		spec.pointer, err = connector.CompilePointer(at)
		if err != nil {
			return spec, err
		}
	}
	spec.Optional = spec.Optional && slices.Contains([]string{"query", "form", "body", "argument"}, spec.From)
	return spec, nil
}

func (spec compiledSelector) value(r *Request, caps map[string]string, httpFields map[string]any) (any, bool) {
	h, at := r.HTTP, spec.At
	switch spec.From {
	case "path":
		v, ok := caps[at]
		return strings.TrimSuffix(v, spec.TrimSuffix), ok
	case "http":
		return spec.pointer(httpFields)
	case "body":
		return spec.pointer(h.Body)
	case "header_json":
		value, present := h.HeaderJSON[spec.Header]
		if !present {
			return nil, false
		}
		return spec.pointer(value)
	case "argument":
		if r.GraphQL != nil && len(r.GraphQL.Fields) == 1 {
			return spec.pointer(r.GraphQL.Fields[0].Arguments)
		}
		return nil, false
	default:
		values := map[string][]string(h.Query)
		if spec.From == "form" {
			values = h.Form
		}
		if spec.From == "header" {
			values = h.Headers
		}
		if at == "" && spec.From != "header" {
			if values == nil {
				values = map[string][]string{}
			}
			return values, true
		}
		v, ok := values[at]
		if len(v) != 1 {
			return invalidSelection{}, ok
		}
		return v[0], true
	}
}

// An invalid selection is present but can never satisfy a declared JSON type.
type invalidSelection struct{}

type pathPart struct {
	literal, name, prefix, suffix string
	rest                          bool
}

func compilePath(pattern string) ([]pathPart, error) {
	if pattern == "*" {
		return nil, nil
	}
	parts := strings.Split(pattern, "/")
	out := make([]pathPart, 0, len(parts))
	for i, part := range parts {
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "*}") && i == len(parts)-1 {
			name := part[1 : len(part)-2]
			if name == "" {
				return nil, fmt.Errorf("empty path capture")
			}
			out = append(out, pathPart{name: name, rest: true})
			continue
		}
		prefix, rest, has := strings.Cut(part, "{")
		if !has {
			out = append(out, pathPart{literal: part})
			continue
		}
		name, suffix, ok := strings.Cut(rest, "}")
		if !ok || name == "" || strings.ContainsAny(name+suffix, "{}*") {
			return nil, fmt.Errorf("invalid path capture %s", part)
		}
		out = append(out, pathPart{name: name, prefix: prefix, suffix: suffix})
	}
	return out, nil
}

func pathCaptures(pattern []pathPart, values []string) (map[string]string, bool) {
	var out map[string]string
	for i, part := range pattern {
		if i >= len(values) {
			return nil, false
		}
		if part.name == "" {
			if part.literal != values[i] {
				return nil, false
			}
			continue
		}
		value := values[i]
		if part.rest {
			value = strings.Join(values[i:], "/")
			if value == "" {
				return nil, false
			}
		} else {
			if !strings.HasPrefix(value, part.prefix) || !strings.HasSuffix(value, part.suffix) || len(value) <= len(part.prefix)+len(part.suffix) {
				return nil, false
			}
			value = value[len(part.prefix) : len(value)-len(part.suffix)]
		}
		if out == nil {
			out = map[string]string{}
		}
		out[part.name] = value
		if part.rest {
			return out, true
		}
	}
	return out, pattern == nil || len(pattern) == len(values)
}

type headerCondition struct {
	key   string
	value any
}

type compiledOperation struct {
	operation  *Operation
	path       []pathPart
	selectors  []compiledSelector
	params     map[string]bool
	fields     map[string]func(any) (any, bool)
	headers    []headerCondition
	definition json.RawMessage
}

type routeKey struct{ origin, method string }

type routeNode struct {
	literal     map[string]*routeNode
	capture     *routeNode
	exact, rest []*compiledOperation
}

// CompiledPreset retains a validated specification; only it can match requests.
type CompiledPreset struct {
	routes map[routeKey]*routeNode
	slots  bool
}

// Compile takes ownership of spec and its maps and slices.
func (spec *Preset) Compile() (*CompiledPreset, error) {
	p := spec
	if err := p.validate(); err != nil {
		return nil, err
	}
	compiled := &CompiledPreset{routes: map[routeKey]*routeNode{}, slots: p.Slots}
	for id, operation := range p.Operations {
		if operation.Enabled != nil && !*operation.Enabled {
			continue
		}
		operation.ID = id
		o := &operation
		parts, err := compilePath(o.Path)
		if err != nil {
			return nil, err
		}
		var selectors []compiledSelector
		for _, name := range slices.Sorted(maps.Keys(o.Scope)) {
			spec, err := compileSelector(o.Scope[name])
			if err != nil {
				return nil, err
			}
			spec.name = name
			selectors = append(selectors, spec)
		}
		definition, err := json.Marshal([]any{o, p.Slots})
		if err != nil {
			return nil, err
		}
		op := &compiledOperation{operation: o, path: parts, selectors: selectors, definition: definition,
			params: map[string]bool{}, fields: map[string]func(any) (any, bool){}}
		for _, key := range o.Params {
			op.params[key] = true
		}
		for key, value := range o.Headers {
			op.headers = append(op.headers, headerCondition{strings.ToLower(key), value})
		}
		if o.Body == "json" {
			for at := range o.Fields {
				op.fields[at], err = connector.CompilePointer(at)
				if err != nil {
					return nil, err
				}
			}
		}
		key := routeKey{o.Origin, o.Method}
		node := compiled.routes[key]
		if node == nil {
			node = &routeNode{}
			compiled.routes[key] = node
		}
		if parts == nil {
			node.rest = append(node.rest, op)
			continue
		}
		for _, part := range parts {
			if part.rest {
				break
			}
			if part.name != "" {
				if node.capture == nil {
					node.capture = &routeNode{}
				}
				node = node.capture
			} else {
				if node.literal == nil {
					node.literal = map[string]*routeNode{}
				}
				child := node.literal[part.literal]
				if child == nil {
					child = &routeNode{}
					node.literal[part.literal] = child
				}
				node = child
			}
		}
		if parts[len(parts)-1].rest {
			node.rest = append(node.rest, op)
		} else {
			node.exact = append(node.exact, op)
		}
	}
	return compiled, nil
}

func (node *routeNode) candidates(path []string, out []*compiledOperation) []*compiledOperation {
	if node == nil {
		return out
	}
	out = append(out, node.rest...)
	if len(path) == 0 {
		return append(out, node.exact...)
	}
	out = node.literal[path[0]].candidates(path[1:], out)
	if path[0] != "" {
		out = node.capture.candidates(path[1:], out)
	}
	return out
}

// Match selects exactly one reviewed operation. Unknown requests keep their
// protocol details, but receive no operation or inferred effects.
func (p *CompiledPreset) Match(r *Request, c connector.Context, f facts.Facts) (facts.Facts, error) {
	h := r.HTTP
	f.Title = fmt.Sprintf("%s: %s %s", c.Title, h.Method, h.Path)
	config, _ := c.Config.(*HTTP)
	if p.slots && (config == nil || !slices.ContainsFunc(config.Slots, func(slot Slot) bool {
		return h.Origin == slot.Origin && under(h.Path, slot.Path)
	})) {
		return f, fmt.Errorf("the request is outside this API's address")
	}
	parts := strings.Split(h.Path, "/")
	origins, methods := []string{h.Origin, "*"}, []string{h.Method, "*"}
	if c.Options.Origin == h.Origin || c.Options.Origin == "*" {
		origins = append(origins, "{origin}")
	}
	var candidates []*compiledOperation
	for _, origin := range origins {
		for _, method := range methods {
			candidates = p.routes[routeKey{origin, method}].candidates(parts, candidates)
		}
	}
	slices.SortFunc(candidates, func(a, b *compiledOperation) int { return strings.Compare(a.operation.ID, b.operation.ID) })
	headers := map[string][]string{}
	for key, values := range h.Headers {
		headers[strings.ToLower(key)] = append(headers[strings.ToLower(key)], values...)
	}
	var matched *compiledOperation
	var captures map[string]string
	for _, candidate := range candidates {
		caps, matches := pathCaptures(candidate.path, parts)
		if !matches {
			continue
		}
		matches, err := candidate.matches(r, headers)
		if err != nil {
			return f, err
		}
		if matches {
			if matched != nil {
				return f, fmt.Errorf("the request matches more than one reviewed operation")
			}
			matched, captures = candidate, caps
		}
	}
	if matched == nil {
		return f, nil
	}
	o := matched.operation
	parameters := make(map[string]any, len(matched.selectors))
	var errs []error
	var httpFields map[string]any
	for _, spec := range matched.selectors {
		if spec.From == "http" && httpFields == nil {
			httpFields, _ = facts.JSON[map[string]any](h)
		}
		value, present := spec.value(r, captures, httpFields)
		if err := connector.CheckSelection(spec.name, value, present, spec.Type, spec.Optional); err != nil {
			errs = append(errs, err)
		} else if present {
			parameters[spec.name] = value
		}
	}
	grant := project(parameters, o.Grant)
	f.Operation = &facts.Operation{ID: o.ID, Action: o.Action, Effects: o.Effects}
	f.Title = fmt.Sprintf("%s: %s", c.Title, o.ID)
	f.Parameters = parameters
	f.Context.Sends = o.Sends
	f.Scope, f.Definition = grant, matched.definition
	return f, errors.Join(errs...)
}

// project selects the parameter values bound to a saved approval. Nil means
// all parameters; an explicitly empty selection stays empty.
func project(parameters map[string]any, names []string) map[string]any {
	if names == nil {
		return nil
	}
	out := make(map[string]any, len(names))
	for _, name := range names {
		if value, ok := parameters[name]; ok {
			out[name] = value
		}
	}
	return out
}
