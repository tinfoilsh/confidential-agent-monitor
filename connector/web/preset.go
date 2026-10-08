package web

import (
	"errors"
	"fmt"
	"maps"
	"net/http"
	"net/url"
	"slices"
	"strings"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/facts"
)

type HTTPDetails struct {
	Method   string      `json:"method"`
	Origin   string      `json:"origin"`
	Host     string      `json:"host"`
	Path     string      `json:"path"`
	Query    url.Values  `json:"query"`
	Headers  http.Header `json:"headers"`
	Secrets  []string    `json:"secrets"`
	BodyKind string      `json:"body_kind"`
	Body     any         `json:"body,omitempty"`
	Form     url.Values  `json:"form,omitempty"`
	// HeaderJSON holds single header values that are JSON objects, as Dropbox-API-Arg is.
	HeaderJSON map[string]any `json:"header_json,omitempty"`
}

type GraphQLDetails struct {
	Kind   string         `json:"kind"`
	Fields []GraphQLField `json:"fields"`
}

type GraphQLField struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

type Request struct {
	HTTP    *HTTPDetails    `json:"http"`
	GraphQL *GraphQLDetails `json:"graphql,omitempty"`
}

func (r *Request) Describe(c connector.Context) (facts.Facts, connector.Approval, error) {
	details := map[string]any{"http": r.HTTP}
	if r.GraphQL != nil {
		details["graphql"] = r.GraphQL
	}
	f := facts.Facts{Details: details}
	h := r.HTTP
	if h == nil {
		return f, connector.Approval{}, fmt.Errorf("HTTP request is missing")
	}
	p, _ := c.Specs["http"].(*Preset)
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
	return f, connector.Approval{}, nil
}

// Preset contains reviewed HTTP operations, including GraphQL requests.
type Preset struct {
	Operations []Operation `json:"operations"`
	Slots      bool        `json:"slots,omitempty"`
}

func (p *Preset) Validate() error {
	seen := map[string]bool{}
	for _, o := range p.Operations {
		if o.ID == "" || o.Action == "" || seen[o.ID] || !facts.ValidEffects(o.Effects) {
			return fmt.Errorf("invalid or repeated operation %q", o.ID)
		}
		seen[o.ID] = true
		if o.Method == "" || o.Origin == "" || o.Path == "" || o.Scope == nil {
			return fmt.Errorf("operation %s needs method, origin, path and scope", o.ID)
		}
		if _, err := captures(o.Path, o.Path); err != nil {
			return err
		}
		if err := validateSelectors(o.Scope); err != nil {
			return err
		}
		if o.Body == "json" {
			for at := range o.Fields {
				if !connector.ValidJSONPointer(at) {
					return fmt.Errorf("invalid field path %q", at)
				}
			}
		}
		for _, name := range o.Grant {
			if _, ok := o.Scope[name]; !ok {
				return fmt.Errorf("grant names missing scope %s", name)
			}
		}
		if !slices.Contains([]string{"", "me", "team", "anyone", "account"}, o.Sends) || !slices.Contains([]string{"", "none", "json", "form", "any", "graphql"}, o.Body) {
			return fmt.Errorf("invalid audience or body kind for %s", o.ID)
		}
		if g := o.GraphQL; g != nil {
			if o.Body != "graphql" || (g.Field == "") == (len(g.Fields) == 0) || !slices.Contains([]string{"query", "mutation", "subscription"}, g.Operation) {
				return fmt.Errorf("invalid graphql matcher for %s", o.ID)
			}
		} else if o.Body == "graphql" {
			return fmt.Errorf("missing graphql matcher for %s", o.ID)
		}
	}

	return nil
}

type Operation struct {
	ID            string              `json:"id"`
	Action        string              `json:"action"`
	Effects       []string            `json:"effects"`
	Method        string              `json:"method"`
	Origin        string              `json:"origin"`
	Path          string              `json:"path"`
	Query         map[string]any      `json:"query,omitempty"`
	Headers       map[string]any      `json:"headers,omitempty"`
	Fields        map[string]any      `json:"fields,omitempty"`
	Params        []string            `json:"params,omitempty"`
	OpenParams    bool                `json:"open_params,omitempty"`
	Body          string              `json:"body,omitempty"`
	GraphQL       *GraphQLMatch       `json:"graphql,omitempty"`
	Scope         map[string]Selector `json:"scope"`
	Grant         []string            `json:"grant,omitempty"`
	Sends         string              `json:"sends,omitempty"`
	RequiresTrust *bool               `json:"requires_trust,omitempty"`
}

type GraphQLMatch struct {
	Operation string   `json:"operation"`
	Field     string   `json:"field,omitempty"`
	Fields    []string `json:"fields,omitempty"`
}

type Selector struct {
	From       string `json:"from"`
	At         string `json:"at"`
	Type       string `json:"type,omitempty"`
	Optional   bool   `json:"optional,omitempty"`
	Header     string `json:"header,omitempty"`
	TrimSuffix string `json:"trim_suffix,omitempty"`
}

func validateSelectors(scope map[string]Selector) error {
	for name, s := range scope {
		if !slices.Contains([]string{"path", "query", "form", "body", "header", "header_json", "argument", "http"}, s.From) || !connector.ValidJSONType(s.Type) {
			return fmt.Errorf("invalid selector %s", name)
		}
		if slices.Contains([]string{"body", "header_json", "argument", "http"}, s.From) {
			if err := (connector.JSONSelector{At: s.At, Type: s.Type, Optional: s.Optional}).Validate(); err != nil {
				return fmt.Errorf("selector %s: %w", name, err)
			}
		}
	}
	return nil
}

func matchOperation(o Operation, r Request, originOption string) (bool, error) {
	h := r.HTTP
	origin := o.Origin
	if origin == "{origin}" {
		origin = originOption
	}
	if (o.Method != "*" && h.Method != o.Method) || (origin != "*" && h.Origin != origin) {
		return false, nil
	}
	caps, err := captures(o.Path, h.Path)
	if err != nil || caps == nil {
		return false, nil
	}
	for k, v := range o.Query {
		if !condition(h.Query, k, v) {
			return false, nil
		}
	}
	headers := map[string][]string{}
	for k, v := range h.Headers {
		headers[strings.ToLower(k)] = append(headers[strings.ToLower(k)], v...)
	}
	for k, v := range o.Headers {
		if !condition(headers, strings.ToLower(k), v) {
			return false, nil
		}
	}
	for k := range h.Query {
		if _, ok := o.Query[k]; !ok && !o.OpenParams && !slices.Contains(o.Params, k) {
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
			got, present := connector.JSONPointer(h.Body, k)
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
		return !slices.ContainsFunc(g.Fields, func(f GraphQLField) bool { return !slices.Contains(spec.Fields, f.Name) }), nil
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

func captures(pattern, value string) (map[string]string, error) {
	pp, vv := strings.Split(pattern, "/"), strings.Split(value, "/")
	out := map[string]string{}
	if pattern == "*" {
		return out, nil
	}
	for i, part := range pp {
		if i >= len(vv) {
			return nil, nil
		}
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "*}") && i == len(pp)-1 {
			name := part[1 : len(part)-2]
			if name == "" {
				return nil, fmt.Errorf("empty path capture")
			}
			rest := strings.Join(vv[i:], "/")
			if rest == "" {
				return nil, nil
			}
			out[name] = rest
			return out, nil
		}
		prefix, rest, has := strings.Cut(part, "{")
		if !has {
			if part != vv[i] {
				return nil, nil
			}
			continue
		}
		name, suffix, ok := strings.Cut(rest, "}")
		if !ok || name == "" || strings.ContainsAny(name+suffix, "{}*") {
			return nil, fmt.Errorf("invalid path capture %s", part)
		}
		if !strings.HasPrefix(vv[i], prefix) || !strings.HasSuffix(vv[i], suffix) || len(vv[i]) <= len(prefix)+len(suffix) {
			return nil, nil
		}
		out[name] = vv[i][len(prefix) : len(vv[i])-len(suffix)]
	}
	if len(pp) != len(vv) {
		return nil, nil
	}
	return out, nil
}

func extract(spec Selector, r Request, caps map[string]string) (any, bool) {
	h := r.HTTP
	at := spec.At
	switch spec.From {
	case "path":
		v, ok := caps[at]
		return strings.TrimSuffix(v, spec.TrimSuffix), ok
	case "http":
		return connector.JSONPointer(connector.JSONFields(h), at)
	case "body":
		return connector.JSONPointer(h.Body, at)
	case "header_json":
		value, present := h.HeaderJSON[spec.Header]
		if !present {
			return nil, false
		}
		return connector.JSONPointer(value, at)
	case "argument":
		if r.GraphQL != nil && len(r.GraphQL.Fields) == 1 {
			return connector.JSONPointer(r.GraphQL.Fields[0].Arguments, at)
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
			return connector.JSONFields(values), true
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

func selectScope(selectors map[string]Selector, r Request, caps map[string]string) (map[string]any, error) {
	var errs []error
	scope := map[string]any{}
	for _, name := range slices.Sorted(maps.Keys(selectors)) {
		spec := selectors[name]
		v, present := extract(spec, r, caps)
		optional := spec.Optional && slices.Contains([]string{"query", "form", "body", "argument"}, spec.From)
		if err := connector.CheckSelection(name, v, present, spec.Type, optional); err != nil {
			errs = append(errs, err)
		} else if present {
			scope[name] = v
		}
	}
	return scope, errors.Join(errs...)
}

// Match selects exactly one reviewed operation. Unknown requests keep their
// protocol details, but receive no operation or inferred effects.
func (p *Preset) Match(r *Request, c connector.Context, f facts.Facts) (facts.Facts, connector.Approval, error) {
	h := r.HTTP
	f.Title = fmt.Sprintf("%s: %s %s", c.Title, h.Method, h.Path)
	var config struct {
		Slots []struct{ Origin, Path string }
	}
	var options struct{ Origin string }
	if err := c.DecodeConfig(&config); err != nil {
		return f, connector.Approval{}, err
	}
	if err := c.DecodeOptions(&options); err != nil {
		return f, connector.Approval{}, err
	}
	if p.Slots && !slices.ContainsFunc(config.Slots, func(slot struct{ Origin, Path string }) bool {
		prefix := strings.TrimSuffix(slot.Path, "/")
		return h.Origin == slot.Origin && (h.Path == prefix || strings.HasPrefix(h.Path, prefix+"/"))
	}) {
		return f, connector.Approval{}, fmt.Errorf("the request is outside this API's address")
	}
	var matched *Operation
	for i := range p.Operations {
		o := &p.Operations[i]
		matches, err := matchOperation(*o, *r, options.Origin)
		if err != nil {
			return f, connector.Approval{}, err
		}
		if matches {
			if matched != nil {
				return f, connector.Approval{}, fmt.Errorf("the request matches more than one reviewed operation")
			}
			matched = o
		}
	}
	if matched == nil {
		return f, connector.Approval{}, nil
	}
	o := *matched
	caps, _ := captures(o.Path, h.Path)
	scope, err := selectScope(o.Scope, *r, caps)
	requiresTrust := slices.ContainsFunc(o.Effects, func(e string) bool { return e != "read" })
	if o.RequiresTrust != nil {
		requiresTrust = *o.RequiresTrust
	}
	var grant map[string]any
	if o.Grant != nil {
		grant = map[string]any{}
		for _, key := range o.Grant {
			if v, ok := scope[key]; ok {
				grant[key] = v
			}
		}
	}
	f.Operation = &facts.Operation{ID: o.ID, Action: o.Action, Effects: slices.Clone(o.Effects), RequiresTrust: requiresTrust}
	f.Title = fmt.Sprintf("%s: %s", c.Title, o.ID)
	f.Parameters = scope
	f.Context.Sends = o.Sends
	return f, connector.Approval{Scope: grant, Definition: []any{o, p.Slots}}, err
}
