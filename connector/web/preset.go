package web

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"regexp"
	"slices"
	"strings"

	"github.com/tinfoilsh/confidential-agent-monitor/connector/catalog"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

type Request struct {
	HTTP    *HTTPFacts    `json:"http"`
	GraphQL *GraphQLFacts `json:"graphql,omitempty"`
	Invalid string        `json:"invalid,omitempty"`
	place   func(*http.Request, func(context.Context, string) (string, error)) (*http.Request, error)
	answer  http.HandlerFunc
	gqlErr  error
}

func (r *Request) Describe(config *Setup) (facts.Observation, error) {
	if r.HTTP != nil && config.Preset != nil && len(config.Preset.SensitiveQuery) != 0 {
		described, layer := *r, *r.HTTP
		layer.Query = maps.Clone(r.HTTP.Query)
		for _, key := range config.Preset.SensitiveQuery {
			if values, present := layer.Query[key]; present {
				fingerprints := make([]string, len(values))
				for i, value := range values {
					fingerprints[i] = fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(value)))
				}
				layer.Query[key] = fingerprints
			}
		}
		described.HTTP = &layer
		return described.describe(config)
	}
	return r.describe(config)
}

func (r *Request) describe(config *Setup) (facts.Observation, error) {
	if r.HTTP == nil {
		return facts.Observation{}, errors.New("missing HTTP request")
	}
	f := facts.Observation{Details: Details{HTTP: r.HTTP, GraphQL: r.GraphQL}}
	h := r.HTTP
	f.Title = h.Method + " " + h.Host + h.Path
	if r.Invalid != "" {
		return f, errors.New(r.Invalid)
	}
	if r.answer != nil {
		f.Operation = &facts.Operation{Action: SignInAction, Effects: []string{"session"}}
		f.Title = config.title + ": sign in"
		return f, nil
	}
	if p := config.Preset; p != nil {
		return p.Match(r, config, f)
	}
	if strings.Contains(h.Path, "//") {
		return f, errNoncanonicalPath
	}
	if h.WebSocket {
		return f, nil
	}
	action := "browse"
	if !slices.Contains([]string{"GET", "HEAD", "OPTIONS"}, h.Method) {
		action = "submit"
	}
	f.Operation = &facts.Operation{Action: action}
	f.Parameters = map[string]any{"host": h.Host}
	return f, nil
}

type Preset struct {
	Operations     map[string]Operation `json:"operations"`
	Origins        map[string][]string  `json:"origins,omitempty"`
	Slots          bool                 `json:"slots,omitempty"`
	SensitiveQuery []string             `json:"sensitive_query,omitempty"`
	FormatSuffixes []string             `json:"format_suffixes,omitempty"`
	TrailingSlash  bool                 `json:"trailing_slash,omitempty"`
	routes         map[routeKey]*routeNode
	hosts          map[string][][]pathPart
}

func (p *Preset) UnmarshalJSON(raw []byte) error {
	type plain Preset
	if err := facts.DecodeNumbers(raw, (*plain)(p)); err != nil {
		return err
	}
	return p.compile()
}

func Operations(definition json.RawMessage) (map[string]catalog.OperationSummary, error) {
	var preset struct {
		HTTP *struct {
			Operations map[string]catalog.OperationSummary `json:"operations"`
		} `json:"http"`
	}
	if err := json.Unmarshal(definition, &preset); err != nil || preset.HTTP == nil {
		return nil, err
	}
	ops := map[string]catalog.OperationSummary{}
	for id, o := range preset.HTTP.Operations {
		if len(o.Effects) == 0 {
			return nil, fmt.Errorf("invalid operation %q", id)
		}
		ops[id] = catalog.OperationSummary{Action: o.Action, Effects: o.Effects}
	}
	return ops, nil
}

func (p *Preset) validate() error {
	for i, key := range p.SensitiveQuery {
		if key == "" || slices.Contains(p.SensitiveQuery[:i], key) {
			return errors.New("sensitive query names must be nonempty and unique")
		}
	}
	if slices.ContainsFunc(p.FormatSuffixes, func(suffix string) bool { return len(suffix) < 2 || suffix[0] != '.' || strings.Contains(suffix, "/") }) {
		return errors.New("format suffixes must start with a dot and contain no slash")
	}
	for id, o := range p.Operations {
		if id == "" || o.Action == "" {
			return fmt.Errorf("invalid operation %q", id)
		}
		if o.Method == "" || o.Origin == "" || o.Path == "" || o.Scope == nil {
			return fmt.Errorf("operation %s needs method, origin, path and scope", id)
		}
		if set, named := strings.CutPrefix(o.Origin, "{"); named && set != "origin}" && p.Origins[strings.TrimSuffix(set, "}")] == nil {
			return fmt.Errorf("operation %s uses an undefined origin set", id)
		}
		for _, key := range p.SensitiveQuery {
			if o.Query[key] != nil {
				return fmt.Errorf("operation %s cannot match a literal sensitive query value", id)
			}
		}
		if len(o.Present) > 0 && o.Body != BodyJSON {
			return fmt.Errorf("operation %s needs a json body to require present fields", id)
		}
		if o.WebSocket && (o.Method != "GET" || !slices.Contains([]string{"", bodyNone, BodyJSON}, o.Body)) {
			return fmt.Errorf("WebSocket operation %s needs GET and a none or json body", id)
		}
		for _, name := range o.Grant {
			if _, ok := o.Scope[name]; !ok {
				return fmt.Errorf("grant names missing scope %s", name)
			}
		}
		if !slices.Contains([]string{"", bodyNone, BodyJSON, bodyForm, bodyAny, bodyGraphQL}, o.Body) {
			return fmt.Errorf("invalid body kind for %s", id)
		}
		if g := o.GraphQL; g != nil {
			if o.Body != bodyGraphQL || (g.Field == "") == (len(g.Fields) == 0) || !slices.Contains([]string{"query", "mutation", "subscription"}, g.Operation) {
				return fmt.Errorf("invalid graphql matcher for %s", id)
			}
		} else if o.Body == bodyGraphQL {
			return fmt.Errorf("missing graphql matcher for %s", id)
		}
	}

	return nil
}

type Operation struct {
	WebSocket    bool                `json:"websocket,omitempty"`
	ID           string              `json:"-"`
	Action       string              `json:"action"`
	Effects      []string            `json:"effects"`
	Method       string              `json:"method"`
	Origin       string              `json:"origin"`
	Path         string              `json:"path"`
	PathPatterns map[string]string   `json:"path_patterns,omitempty"`
	Query        map[string]any      `json:"query,omitempty"`
	Headers      map[string]any      `json:"headers,omitempty"`
	Fields       map[string]any      `json:"fields,omitempty"`
	Present      []string            `json:"present,omitempty"`
	Params       []string            `json:"params,omitempty"`
	OpenParams   bool                `json:"open_params,omitempty"`
	Body         string              `json:"body,omitempty"`
	GraphQL      *GraphQLMatch       `json:"graphql,omitempty"`
	Scope        map[string]Selector `json:"scope"`
	Grant        []string            `json:"grant,omitempty"`
	Sends        json.RawMessage     `json:"sends,omitempty"`
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
	facts.Selector
}

var keyPlaceholder = regexp.MustCompile(`\{[^{}]+\}`)

var selectorSources = map[string]struct{ json, optional bool }{
	"path": {}, "query": {optional: true}, "form": {optional: true}, "body": {json: true, optional: true},
	"header_json": {json: true, optional: true}, "argument": {json: true, optional: true}, "http": {json: true}, "host": {},
}

type selection struct {
	*Request
	captures, host map[string]string
	fields         map[string]any
}

func (s *selection) httpFields() map[string]any {
	if s.fields == nil {
		s.fields, _ = facts.JSON[map[string]any](s.HTTP)
	}
	return s.fields
}

func (compiled *compiledOperation) matches(r *Request, headers map[string][]string) (bool, error) {
	o, h := compiled.operation, r.HTTP
	if o.WebSocket != h.WebSocket {
		return false, nil
	}
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
		if _, ok := o.Query[k]; !ok && !o.OpenParams && !compiled.params[k] && !slices.ContainsFunc(compiled.keys, func(key *regexp.Regexp) bool { return key.MatchString(k) }) {
			return false, nil
		}
	}
	body := o.Body
	if body == "" {
		body = bodyNone
	}
	for k, v := range o.Fields {
		switch body {
		case bodyForm:
			if !condition(h.Form, k, v) {
				return false, nil
			}
		case BodyJSON:
			got, present := compiled.fields[k](h.Body)
			if v == nil {
				if present {
					return false, nil
				}
			} else if !present || !facts.Equal(got, v) {
				return false, nil
			}
		default:
			return false, nil
		}
	}
	for _, at := range o.Present {
		if _, present := compiled.fields[at](h.Body); !present {
			return false, nil
		}
	}
	if body == bodyAny {
		return true, nil
	}
	if body == bodyGraphQL {
		g, spec := r.GraphQL, o.GraphQL
		if r.gqlErr != nil {
			return false, fmt.Errorf("the GraphQL document could not be decoded: %w", r.gqlErr)
		}
		if g == nil || h.BodyKind != BodyJSON || g.Kind != spec.Operation || len(g.Fields) == 0 {
			return false, nil
		}
		if spec.Field != "" {
			return spec.Field == "*" || len(g.Fields) == 1 && g.Fields[0].Name == spec.Field, nil
		}
		return !slices.ContainsFunc(g.Fields, func(f GraphQLFieldFacts) bool { return !slices.Contains(spec.Fields, f.Name) }), nil
	}
	return h.BodyKind == body, nil
}

func condition(values map[string][]string, key string, want any) bool {
	got, present := values[key]
	if want == nil {
		return !present
	}
	s, ok := want.(string)
	return len(got) == 1 && (want == true || ok && got[0] == s)
}

func (spec Selector) Compile() (facts.Selector, func(any) (any, bool), error) {
	source, ok := selectorSources[spec.From]
	if !ok || !spec.Valid() || !source.json && slices.Contains([]string{"number", "boolean", "null"}, spec.Type) {
		return spec.Selector, nil, fmt.Errorf("invalid selector source %q or type %q", spec.From, spec.Type)
	}
	var pointer func(any) (any, bool)
	if source.json {
		var err error
		if pointer, err = facts.CompilePointer(spec.At); err != nil {
			return spec.Selector, nil, err
		}
	}
	checked := spec.Selector
	checked.Optional = checked.Optional && source.optional
	spec.Header = http.CanonicalHeaderKey(spec.Header)
	return checked, func(doc any) (any, bool) { return spec.value(doc.(*selection), pointer) }, nil
}

func (spec Selector) value(r *selection, pointer func(any) (any, bool)) (any, bool) {
	h, at := r.HTTP, spec.At
	switch spec.From {
	case "path":
		v, ok := r.captures[at]
		return strings.TrimSuffix(v, spec.TrimSuffix), ok
	case "host":
		v, ok := r.host[at]
		return v, ok
	case "http":
		return pointer(r.httpFields())
	case "body":
		return pointer(h.Body)
	case "header_json":
		value, present := h.HeaderJSON[spec.Header]
		if !present {
			return invalidSelection{}, h.Headers[spec.Header] != nil
		}
		return pointer(value)
	case "argument":
		if r.GraphQL != nil && len(r.GraphQL.Fields) == 1 {
			return pointer(r.GraphQL.Fields[0].Arguments)
		}
		return nil, false
	default:
		values := map[string][]string(h.Query)
		if spec.From == "form" {
			values = h.Form
		}
		if at == "" {
			object := map[string]any{}
			for key, entries := range values {
				object[key] = entries
			}
			return object, true
		}
		v, ok := values[at]
		if spec.Type == "array" {
			items, _ := facts.JSON[[]any](v)
			return items, ok
		}
		if len(v) != 1 {
			return invalidSelection{}, ok
		}
		return v[0], true
	}
}

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
			if value == "" || strings.HasPrefix(value, "/") || strings.Contains(value, "//") {
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
	return out, pattern == nil && !strings.Contains(strings.Join(values, "/"), "//") || len(pattern) == len(values)
}

// capture also tries the spellings the preset opts into, except where they would change a captured value.
func (p *Preset) capture(pattern []pathPart, parts []string) (map[string]string, bool) {
	captures, matches := pathCaptures(pattern, parts)
	if matches || len(pattern) == 0 || pattern[len(pattern)-1].rest {
		return captures, matches
	}
	slashed, stripped := p.spellings(parts)
	if captures, matches = pathCaptures(pattern, slashed); matches || pattern[len(pattern)-1].name != "" {
		return captures, matches
	}
	return pathCaptures(pattern, stripped)
}

func (p *Preset) spellings(parts []string) (slashed, stripped []string) {
	last := len(parts) - 1
	switch {
	case !p.TrailingSlash:
	case parts[last] != "":
		slashed = append(slices.Clip(parts), "")
	case last > 1 && parts[last-1] != "":
		slashed = parts[:last]
	}
	for _, suffix := range p.FormatSuffixes {
		if base, ok := strings.CutSuffix(parts[last], suffix); ok && base != "" {
			stripped = append(slices.Clone(parts[:last]), base)
		}
	}
	return slashed, stripped
}

type headerCondition struct {
	key   string
	value any
}

type compiledOperation struct {
	operation    *Operation
	path         []pathPart
	pathPatterns map[string]*regexp.Regexp
	selectors    []facts.Compiled
	params       map[string]bool
	keys         []*regexp.Regexp
	fields       map[string]func(any) (any, bool)
	headers      []headerCondition
}

type routeKey struct{ origin, method string }

type routeNode struct {
	literal     map[string]*routeNode
	capture     *routeNode
	exact, rest []*compiledOperation
}

func (p *Preset) compile() error {
	if err := p.validate(); err != nil {
		return err
	}
	p.hosts = map[string][][]pathPart{}
	for name, templates := range p.Origins {
		for _, template := range templates {
			parts, err := compilePath(strings.ReplaceAll(template, ".", "/"))
			if err != nil || strings.Count(template, "/") != 2 || !strings.HasPrefix(template, "https://") && !strings.HasPrefix(template, "http://") ||
				slices.ContainsFunc(parts, func(part pathPart) bool { return part.rest }) {
				return fmt.Errorf("invalid origin template %s", template)
			}
			for _, other := range p.hosts[name] {
				if len(other) == len(parts) && !slices.EqualFunc(other, parts, func(a, b pathPart) bool { return a.name == b.name }) {
					return fmt.Errorf("origin templates in %s with the same number of labels must capture the same names in the same labels", name)
				}
			}
			p.hosts[name] = append(p.hosts[name], parts)
		}
	}
	p.routes = map[routeKey]*routeNode{}
	for id, operation := range p.Operations {
		operation.ID = id
		o := &operation
		parts, err := compilePath(o.Path)
		if err != nil {
			return err
		}
		pathPatterns := map[string]*regexp.Regexp{}
		for name, pattern := range o.PathPatterns {
			count := 0
			for _, part := range parts {
				if part.name == name {
					count++
				}
			}
			if name == "" || count != 1 {
				return fmt.Errorf("operation %s needs exactly one path capture named %q", id, name)
			}
			compiled, err := regexp.Compile(pattern)
			if err == nil {
				compiled, err = regexp.Compile(`\A(?:` + pattern + `)\z`)
			}
			if err != nil {
				return fmt.Errorf("operation %s has an invalid path pattern for %s: %w", id, name, err)
			}
			pathPatterns[name] = compiled
		}
		selectors, err := facts.Compile(o.Scope)
		if err != nil {
			return err
		}
		op := &compiledOperation{operation: o, path: parts, pathPatterns: pathPatterns, selectors: selectors,
			params: map[string]bool{}, fields: map[string]func(any) (any, bool){}}
		bound := o.OpenParams
		for name, s := range o.Scope {
			bound = bound || s.From == "query" && s.At == "" && (o.Grant == nil || slices.Contains(o.Grant, name))
		}
		for _, key := range o.Params {
			if !strings.ContainsAny(key, "{}") {
				op.params[key] = true
				continue
			}
			pieces := keyPlaceholder.Split(key, -1)
			if !bound || strings.ContainsAny(strings.Join(pieces, ""), "{}") {
				return fmt.Errorf("operation %s needs a well-formed query key template %s and a scope binding the whole query", id, key)
			}
			for i, piece := range pieces {
				pieces[i] = regexp.QuoteMeta(piece)
			}
			op.keys = append(op.keys, regexp.MustCompile(`\A`+strings.Join(pieces, ".*")+`\z`))
		}
		for key, value := range o.Headers {
			op.headers = append(op.headers, headerCondition{strings.ToLower(key), value})
		}
		if o.Body == BodyJSON {
			for _, at := range append(slices.Collect(maps.Keys(o.Fields)), o.Present...) {
				op.fields[at], err = facts.CompilePointer(at)
				if err != nil {
					return err
				}
			}
		}
		key := routeKey{o.Origin, o.Method}
		node := p.routes[key]
		if node == nil {
			node = &routeNode{}
			p.routes[key] = node
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
	return nil
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

func (p *Preset) Match(r *Request, config *Setup, f facts.Observation) (facts.Observation, error) {
	h := r.HTTP
	f.Title = fmt.Sprintf("%s: %s %s", config.title, h.Method, h.Path)
	if p.Slots && !config.slots.Covers(h.Origin, h.Path) {
		return f, errors.New("the request is outside this API's address")
	}
	parts := strings.Split(h.Path, "/")
	local := parts
	origins, methods := []string{h.Origin, "*"}, []string{h.Method, "*"}
	if rest, under := strings.CutPrefix(h.Path, config.base); under && strings.HasPrefix(rest, "/") && (config.origin == h.Origin || config.origin == "*") {
		origins, local = append(origins, "{origin}"), strings.Split(rest, "/")
	}
	path := func(origin string) []string {
		if origin == "{origin}" {
			return local
		}
		return parts
	}
	hosts, labels := map[string]map[string]string{}, strings.Split(strings.ReplaceAll(h.Origin, ".", "/"), "/")
	for name, templates := range p.hosts {
		set := "{" + name + "}"
		for _, template := range templates {
			captures, matches := pathCaptures(template, labels)
			for _, value := range captures {
				matches = matches && !strings.Contains(value, ":")
			}
			if _, seen := hosts[set]; matches && !seen {
				hosts[set] = captures
				if !slices.Contains(origins, set) {
					origins = append(origins, set)
				}
			}
		}
	}
	var candidates []*compiledOperation
	for _, origin := range origins {
		slashed, stripped := p.spellings(path(origin))
		for _, spelling := range [][]string{path(origin), slashed, stripped} {
			for _, method := range methods {
				candidates = p.routes[routeKey{origin, method}].candidates(spelling, candidates)
			}
		}
	}
	slices.SortFunc(candidates, func(a, b *compiledOperation) int { return strings.Compare(a.operation.ID, b.operation.ID) })
	candidates = slices.Compact(candidates)
	headers := map[string][]string{}
	for key, values := range h.Headers {
		headers[strings.ToLower(key)] = append(headers[strings.ToLower(key)], values...)
	}
	var matched *compiledOperation
	var captures map[string]string
	for _, candidate := range candidates {
		caps, matches := p.capture(candidate.path, path(candidate.operation.Origin))
		if !matches {
			continue
		}
		for name, pattern := range candidate.pathPatterns {
			if !pattern.MatchString(caps[name]) {
				matches = false
				break
			}
		}
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
		if strings.Contains(h.Path, "//") {
			return f, errNoncanonicalPath
		}
		return f, nil
	}
	o := matched.operation
	parameters, err := facts.Select(matched.selectors, &selection{Request: r, captures: captures, host: hosts[o.Origin]})
	for name, value := range hosts[o.Origin] {
		if _, selected := o.Scope[name]; !selected {
			parameters[name] = value
		}
	}
	grant := facts.Project(parameters, o.Grant)
	f.Operation = &facts.Operation{ID: o.ID, Action: o.Action, Effects: o.Effects}
	f.Title = fmt.Sprintf("%s: %s", config.title, o.ID)
	f.Parameters = parameters
	f.Scope = grant
	return f, err
}
