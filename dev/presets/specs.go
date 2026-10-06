package main

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi2"
	"github.com/getkin/kin-openapi/openapi2conv"
	"github.com/getkin/kin-openapi/openapi3"
	postman "github.com/rbretecher/go-postman-collection"
	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/validator"
	discovery "google.golang.org/api/discovery/v1"
	"sigs.k8s.io/yaml"
)

// A specOp is one documented request, in the preset's path syntax, before effects are drafted.
type specOp struct {
	ID, Summary, Method, Origin, Path string
	Tags                              []string
	Params                            []string
	Query                             map[string]string // literal query conditions
	Required                          []param           // required query or body members that may name a resource
	Body                              string
	Headers, Fields                   map[string]string
	GraphQL                           []string
}

type param struct{ Name, From, Type string }

// A specAuth is where a spec says its credential goes.
// User puts the secret in the Basic username, as BambooHR does.
type specAuth struct {
	Header string `json:"header,omitempty"`
	Prefix string `json:"prefix,omitempty"`
	Query  string `json:"query,omitempty"`
	Basic  bool   `json:"basic,omitempty"`
	User   bool   `json:"user,omitempty"`
	SigV4  string `json:"sigv4,omitempty"`
}

type parsed struct {
	Ops  []specOp
	Auth *specAuth
}

// Google's global parameters that carry credentials; every other documented parameter is allowed.
var credentialParams = []string{"key", "access_token", "oauth_token"}

var (
	multiParam  = regexp.MustCompile(`\{[^}]*\}[^/{]*\{`)
	pathParam   = regexp.MustCompile(`\{([^}]+)\}`)
	resourceKey = regexp.MustCompile(`(?i)(^|_)(id|ids|key|name|slug|arn|url|owner|repo|channel|user|email|board|project|team|org|folder|file|sheet|calendar|database|table|bucket|list|space|workspace|site|drive|page|account|chat|thread|queue|topic)$|[a-z](Id|Ids|Key|Name|Arn|Url)$`)
)

// patternPath turns a spec path into the preset syntax: one {name} per segment, a greedy last segment as {name*}.
func patternPath(p string) string {
	p = strings.NewReplacer("{+", "{", "+}", "*}").Replace(p)
	segs := strings.Split(p, "/")
	for i, s := range segs {
		if multiParam.MatchString(s) {
			names := pathParam.FindAllStringSubmatch(s, -1)
			var parts []string
			for _, n := range names {
				parts = append(parts, n[1])
			}
			segs[i] = "{" + strings.Join(parts, "_") + "}"
		}
		if strings.HasSuffix(segs[i], "*}") && i != len(segs)-1 {
			segs[i] = strings.Replace(segs[i], "*}", "}", 1)
		}
	}
	return strings.Join(segs, "/")
}

func splitServer(raw string) (origin, base string) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || strings.Contains(u.Host, "{") {
		return "{origin}", ""
	}
	return "https://" + strings.ToLower(u.Host), strings.TrimSuffix(u.Path, "/")
}

func parseOpenAPI(src []byte, swagger bool, location string) (parsed, error) {
	var doc *openapi3.T
	loader := openapi3.NewLoader()
	if swagger {
		var d2 openapi2.T
		js, err := yaml.YAMLToJSON(src)
		if err == nil {
			err = json.Unmarshal(js, &d2)
		}
		if err == nil {
			doc, err = openapi2conv.ToV3(&d2)
		}
		if err != nil {
			return parsed{}, err
		}
	} else {
		base, err := url.Parse(location)
		if err != nil {
			return parsed{}, err
		}
		loader.IsExternalRefsAllowed = true
		if doc, err = loader.LoadFromDataWithPath(src, base); err != nil {
			return parsed{}, err
		}
	}
	origin, base := "{origin}", ""
	if len(doc.Servers) > 0 {
		origin, base = splitServer(doc.Servers[0].URL)
	}
	var out parsed
	if doc.Components == nil {
		doc.Components = &openapi3.Components{}
	}
	if doc.Paths == nil {
		doc.Paths = openapi3.NewPaths()
	}
	for _, scheme := range sortedValues(doc.Components.SecuritySchemes) {
		if s := scheme.Value; s != nil && out.Auth == nil {
			switch {
			case s.Type == "http" && strings.EqualFold(s.Scheme, "basic"):
				out.Auth = &specAuth{Basic: true}
			case s.Type == "http" && strings.EqualFold(s.Scheme, "bearer"), s.Type == "oauth2":
				out.Auth = &specAuth{Header: "Authorization", Prefix: "Bearer "}
			case s.Type == "apiKey" && s.In == "header":
				out.Auth = &specAuth{Header: s.Name}
			case s.Type == "apiKey" && s.In == "query":
				out.Auth = &specAuth{Query: s.Name}
			}
		}
	}
	for _, p := range slices.Sorted(func(yield func(string) bool) {
		for k := range doc.Paths.Map() {
			if !yield(k) {
				return
			}
		}
	}) {
		item := doc.Paths.Value(p)
		for method, op := range item.Operations() {
			o := specOp{ID: op.OperationID, Summary: op.Summary + " " + op.Description, Method: method, Origin: origin, Path: patternPath(base + p), Tags: op.Tags, Body: "none"}
			if op.Servers != nil && len(*op.Servers) > 0 {
				var opBase string
				o.Origin, opBase = splitServer((*op.Servers)[0].URL)
				o.Path = patternPath(opBase + p)
			}
			for _, ref := range append(slices.Clone(item.Parameters), op.Parameters...) {
				if q := ref.Value; q != nil && q.In == "query" && !slices.Contains(o.Params, q.Name) {
					o.Params = append(o.Params, q.Name)
					if q.Required && resourceKey.MatchString(q.Name) {
						o.Required = append(o.Required, param{q.Name, "query", "string"})
					}
				}
			}
			if rb := op.RequestBody; rb != nil && rb.Value != nil {
				o.Body = "any"
				json, form := rb.Value.Content.Get("application/json"), rb.Value.Content.Get("application/x-www-form-urlencoded")
				switch {
				case len(rb.Value.Content) == 1 && json != nil && rb.Value.Required:
					o.Body = "json"
					o.Required = append(o.Required, members(json.Schema, "body")...)
				case len(rb.Value.Content) == 1 && form != nil && rb.Value.Required:
					o.Body = "form"
					o.Required = append(o.Required, members(form.Schema, "form")...)
				}
			}
			out.Ops = append(out.Ops, o)
		}
	}
	return out, nil
}

// members lists a body schema's required scalar members that may name a resource.
func members(ref *openapi3.SchemaRef, from string) []param {
	if ref == nil || ref.Value == nil {
		return nil
	}
	var out []param
	for _, name := range ref.Value.Required {
		p := ref.Value.Properties[name]
		if p == nil || p.Value == nil || !resourceKey.MatchString(name) {
			continue
		}
		switch t := p.Value.Type; {
		case t.Is("string"):
			out = append(out, param{name, from, "string"})
		case t.Is("integer"), t.Is("number"):
			out = append(out, param{name, from, "number"})
		}
	}
	return out
}

func sortedValues[V any](m map[string]V) []V {
	var out []V
	for _, k := range slices.Sorted(func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	}) {
		out = append(out, m[k])
	}
	return out
}

func parseDiscovery(src []byte) (parsed, error) {
	var doc discovery.RestDescription
	if err := json.Unmarshal(src, &doc); err != nil {
		return parsed{}, err
	}
	origin, base := splitServer(doc.RootUrl + doc.ServicePath)
	var global []string
	for name := range doc.Parameters {
		if !slices.Contains(credentialParams, name) {
			global = append(global, name)
		}
	}
	sort.Strings(global)
	out := parsed{Auth: &specAuth{Header: "Authorization", Prefix: "Bearer "}}
	var walk func(methods map[string]discovery.RestMethod, resources map[string]discovery.RestResource)
	walk = func(methods map[string]discovery.RestMethod, resources map[string]discovery.RestResource) {
		for _, m := range sortedValues(methods) {
			p := m.FlatPath
			if p == "" {
				p = m.Path
			}
			o := specOp{ID: strings.TrimPrefix(m.Id, doc.Name+"."), Summary: m.Description, Method: m.HttpMethod, Origin: origin, Path: patternPath(base + "/" + p), Body: "none"}
			o.Params = slices.Clone(global)
			for _, name := range slices.Sorted(func(yield func(string) bool) {
				for k := range m.Parameters {
					if !yield(k) {
						return
					}
				}
			}) {
				if m.Parameters[name].Location == "query" {
					o.Params = append(o.Params, name)
				}
			}
			if m.Request != nil {
				o.Body = "json"
			}
			if parts := strings.Split(o.ID, "."); len(parts) > 1 {
				o.Tags = []string{parts[len(parts)-2]}
			}
			out.Ops = append(out.Ops, o)
			// Media uploads go to /upload with the same method; their body is the file.
			if m.MediaUpload != nil && m.MediaUpload.Protocols != nil && m.MediaUpload.Protocols.Simple != nil {
				u := o
				// An absolute upload path is complete; a relative one is under the service path.
				u.ID, u.Body, u.Path = o.ID+".upload", "any", patternPath(m.MediaUpload.Protocols.Simple.Path)
				if !strings.HasPrefix(m.MediaUpload.Protocols.Simple.Path, "/") {
					u.Path = patternPath(base + "/" + m.MediaUpload.Protocols.Simple.Path)
				}
				u.Params = append(slices.Clone(o.Params), "uploadType")
				out.Ops = append(out.Ops, u)
			}
		}
		for _, r := range sortedValues(resources) {
			walk(r.Methods, r.Resources)
		}
	}
	walk(doc.Methods, doc.Resources)
	return out, nil
}

// parseGraphQL drafts one operation per root query and mutation field of an SDL schema.
func parseGraphQL(src []byte, origin, path string) (parsed, error) {
	source := &ast.Source{Name: "schema.graphql", Input: string(src)}
	schema, err := gqlparser.LoadSchema(source)
	// Some published SDL declares the built-in scalars, which the prelude declares too.
	if err != nil && strings.Contains(err.Error(), "Cannot redeclare type") {
		schema, err = validator.LoadSchema(source)
	}
	if err != nil {
		return parsed{}, err
	}
	var out parsed
	for kind, root := range map[string]*ast.Definition{"query": schema.Query, "mutation": schema.Mutation} {
		if root == nil {
			continue
		}
		for _, f := range root.Fields {
			if strings.HasPrefix(f.Name, "__") {
				continue
			}
			o := specOp{ID: f.Name, Summary: f.Description, Method: "POST", Origin: origin, Path: path, Body: "graphql", GraphQL: []string{kind, f.Name}, Tags: []string{kind}}
			for _, a := range f.Arguments {
				if a.Type.NonNull && resourceKey.MatchString(a.Name) {
					o.Required = append(o.Required, param{a.Name, "argument", "string"})
				}
			}
			out.Ops = append(out.Ops, o)
		}
	}
	slices.SortFunc(out.Ops, func(a, b specOp) int { return strings.Compare(a.GraphQL[0]+a.ID, b.GraphQL[0]+b.ID) })
	return out, nil
}

// botocore models are plain JSON with no Go parser; this reads only the members drafting needs.
type botocoreModel struct {
	Metadata struct {
		Protocol, TargetPrefix, EndpointPrefix, ServiceFullName, SigningName string
	}
	Operations map[string]struct {
		Name          string
		HTTP          struct{ Method, RequestURI string } `json:"http"`
		Input         *struct{ Shape string }
		Documentation string
	}
	Shapes map[string]struct {
		Required []string
		Members  map[string]struct {
			Shape, Location, LocationName string
		}
		Type string
	}
}

func parseBotocore(src []byte) (parsed, error) {
	var m botocoreModel
	if err := json.Unmarshal(src, &m); err != nil {
		return parsed{}, err
	}
	out := parsed{Auth: &specAuth{SigV4: cmp.Or(m.Metadata.SigningName, m.Metadata.EndpointPrefix)}}
	for _, name := range slices.Sorted(func(yield func(string) bool) {
		for k := range m.Operations {
			if !yield(k) {
				return
			}
		}
	}) {
		op := m.Operations[name]
		o := specOp{ID: name, Summary: op.Documentation, Method: op.HTTP.Method, Origin: "{origin}", Tags: []string{m.Metadata.EndpointPrefix}}
		var input string
		if op.Input != nil {
			input = op.Input.Shape
		}
		shape := m.Shapes[input]
		switch m.Metadata.Protocol {
		case "json":
			o.Method, o.Path, o.Body = "POST", "/", "any"
			o.Headers = map[string]string{"X-Amz-Target": m.Metadata.TargetPrefix + "." + name}
		case "query", "ec2":
			o.Method, o.Path, o.Body = "POST", "/", "form"
			o.Fields = map[string]string{"Action": name}
			for _, r := range shape.Required {
				if resourceKey.MatchString(r) && m.Shapes[shape.Members[r].Shape].Type == "string" {
					o.Required = append(o.Required, param{r, "form", "string"})
				}
			}
		case "rest-json", "rest-xml":
			uri, query, _ := strings.Cut(op.HTTP.RequestURI, "?")
			o.Path, o.Body = patternPath(uri), "any"
			if op.HTTP.Method == "GET" || op.HTTP.Method == "HEAD" || op.HTTP.Method == "DELETE" {
				o.Body = "none"
			}
			if query != "" {
				o.Query = map[string]string{}
				for _, kv := range strings.Split(query, "&") {
					k, v, _ := strings.Cut(kv, "=")
					o.Query[k] = v
				}
			}
			for _, member := range sortedValues(shape.Members) {
				if member.Location == "querystring" {
					o.Params = append(o.Params, member.LocationName)
				}
			}
		default:
			return parsed{}, fmt.Errorf("botocore protocol %s is not supported", m.Metadata.Protocol)
		}
		out.Ops = append(out.Ops, o)
	}
	return out, nil
}

func parsePostman(src []byte) (parsed, error) {
	c, err := postman.ParseCollection(bytes.NewReader(src))
	if err != nil {
		return parsed{}, err
	}
	var out parsed
	var walk func(items []*postman.Items, tags []string)
	walk = func(items []*postman.Items, tags []string) {
		for _, it := range items {
			if it.Request == nil || it.Request.URL == nil {
				walk(it.Items, append(slices.Clone(tags), it.Name))
				continue
			}
			u := it.Request.URL
			var segs []string
			for _, s := range u.Path {
				if strings.HasPrefix(s, ":") {
					s = "{" + s[1:] + "}"
				} else if strings.HasPrefix(s, "{{") {
					s = "{" + strings.Trim(s, "{}") + "}"
				}
				segs = append(segs, s)
			}
			origin := "{origin}"
			if host := strings.Join(u.Host, "."); host != "" && !strings.Contains(host, "{") {
				origin = "https://" + strings.ToLower(host)
			}
			o := specOp{ID: it.Name, Summary: it.Name, Method: string(it.Request.Method), Origin: origin, Path: patternPath("/" + strings.Join(segs, "/")), Tags: tags, Body: "none"}
			for _, q := range u.Query {
				o.Params = append(o.Params, q.Key)
			}
			if b := it.Request.Body; b != nil && b.Mode != "" {
				o.Body = "any"
			}
			out.Ops = append(out.Ops, o)
		}
	}
	walk(c.Items, nil)
	return out, nil
}
