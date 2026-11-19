package main

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"maps"
	"mime"
	"net/http"
	"net/url"
	"reflect"
	"regexp"
	"regexp/syntax"
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

type specOp struct {
	ID, Summary, Method, Origin, Path string
	Base                              string
	Tags                              []string
	Resource                          string
	Params                            []string
	Query                             map[string]any
	PathPatterns                      map[string]string
	Required                          []param
	Body                              string
	Headers, Fields                   map[string]any
	GraphQL                           []string
	BodyType                          string
	SourceID, SourceURL, SourceHash   string
	Unsupported                       string
	Effects                           []string
	Reviewed                          bool   `json:"-"`
	Opaque                            bool   `json:"-"`
	Server                            bool   `json:"-"`
	ArgHeader                         string `json:"-"`
	Parent, Readable                  bool
}

type param struct {
	Name, From, Type string
	Optional         bool
}

type specAuth struct {
	Header string `json:"header,omitempty"`
	Prefix string `json:"prefix,omitempty"`
	Query  string `json:"query,omitempty"`
	Basic  bool   `json:"basic,omitempty"`
	User   bool   `json:"user,omitempty"`
	SigV4  string `json:"sigv4,omitempty"`
}

type parsed struct {
	Ops, Excluded  []specOp
	Auth           *specAuth
	Warnings       []string
	EndpointPrefix string
	Partition      *botocorePartition
	Origins        map[string][]string
	Version        string
}

var credentialParams = []string{"key", "access_token", "oauth_token", "bearer_token"}

var (
	multiParam  = regexp.MustCompile(`\{[^}]*\}[^/{]*\{`)
	pathParam   = regexp.MustCompile(`\{([^}]+)\}`)
	postmanVar  = regexp.MustCompile(`\{\{\s*([^{}]*?)\s*\}\}`)
	regexParam  = regexp.MustCompile(`\{([^{}:/]+):((?:[^{}/]|\{[^{}/]*\})+)\}`)
	resourceKey = regexp.MustCompile(`(?i)(^|_)(id|ids|keys?|names?|slug|arn|url|owners?|repos?|channels?|users?|emails?|boards?|projects?|teams?|orgs?|folders?|files?|sheets?|calendars?|databases?|tables?|buckets?|lists?|spaces?|workspaces?|sites?|drives?|pages?|accounts?|chats?|threads?|queues?|topics?|groups?|records?|recipients?)$|[a-z](Id|Ids|Key|Name|Arn|Url)$`)
)

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
	_, rest, scheme := strings.Cut(raw, "://")
	if !scheme && strings.HasPrefix(raw, "{") {
		rest = raw
	}
	if host, path, _ := strings.Cut(rest, "/"); strings.Contains(host, "{") {
		return "{origin}", strings.TrimSuffix("/"+path, "/")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return "{origin}", ""
	}
	if u.Host == "" || u.Scheme != "https" {
		return "{origin}", strings.TrimSuffix(u.Path, "/")
	}
	return "https://" + strings.ToLower(u.Host), strings.TrimSuffix(u.Path, "/")
}

func serverHost(raw string) string {
	_, rest, _ := strings.Cut(raw, "://")
	host, _, _ := strings.Cut(rest, "/")
	return host
}

// serverOrigin substitutes the default of each enumerated variable; other variables remain as host label captures.
func serverOrigin(s *openapi3.Server) string {
	raw := s.URL
	for name, v := range s.Variables {
		if len(v.Enum) > 0 || v.Default != "" && serverHost(s.URL) == "{"+name+"}" {
			raw = strings.ReplaceAll(raw, "{"+name+"}", v.Default)
		}
	}
	origin, _ := splitServer(raw)
	if host := serverHost(raw); origin == "{origin}" && strings.HasPrefix(raw, "https://") && strings.Contains(host, "{") {
		return "https://" + strings.TrimSuffix(host, ":443")
	}
	return origin
}

func joinPath(base, route string) string {
	if route == "/" && base != "" {
		return base
	}
	return base + route
}

func parseOpenAPI(src []byte, swagger bool, location, prefix string, files map[string][]byte, encodings []string) (parsed, error) {
	var err error
	if src, err = requestDocument(src, swagger, len(files) > 0); err == nil && len(files) > 0 {
		if src, err = bundle(src, location, files); err == nil {
			src, err = requestDocument(src, swagger, false)
		}
	}
	if err != nil {
		return parsed{}, err
	}
	var doc *openapi3.T
	loader := openapi3.NewLoader()
	severalBodies := map[string]bool{}
	if swagger {
		var d2 openapi2.T
		js, err := yaml.YAMLToJSON(src)
		if err == nil {
			err = json.Unmarshal(js, &d2)
		}
		resolve := func(p *openapi2.Parameter) *openapi2.Parameter {
			if name, ok := strings.CutPrefix(p.Ref, "#/parameters/"); ok && d2.Parameters[name] != nil {
				return d2.Parameters[name]
			}
			return p
		}
		form := func(p *openapi2.Parameter) bool { return resolve(p).In == "formData" }
		for path, item := range d2.Paths {
			shared := item.Parameters[:0]
			for _, p := range item.Parameters {
				if !form(p) && resolve(p).In != "body" {
					shared = append(shared, p)
					continue
				}
				for _, op := range item.Operations() {
					if form(p) || !slices.ContainsFunc(op.Parameters, func(q *openapi2.Parameter) bool { return resolve(q).In == "body" }) {
						op.Parameters = append(openapi2.Parameters{p}, op.Parameters...)
					}
				}
			}
			item.Parameters = shared
			for method, op := range item.Operations() {
				body := func(p *openapi2.Parameter) bool { return resolve(p).In == "body" }
				if i := slices.IndexFunc(op.Parameters, body); i >= 0 && slices.ContainsFunc(op.Parameters[i+1:], body) {
					op.Parameters = slices.DeleteFunc(op.Parameters, body)
					severalBodies[method+" "+path] = true
				}
				switch {
				case !slices.ContainsFunc(op.Parameters, form):
				case method == "GET" || method == "HEAD" || method == "DELETE":
					for i, p := range op.Parameters {
						if form(p) {
							query := *resolve(p)
							query.In = "query"
							op.Parameters[i] = &query
						}
					}
				case len(op.Consumes) == 0 && len(d2.Consumes) == 0:
					op.Consumes = []string{formMedia}
					if slices.ContainsFunc(op.Parameters, func(p *openapi2.Parameter) bool { return resolve(p).Type.Is("file") }) {
						op.Consumes = []string{multipartMedia}
					}
				}
			}
		}
		if err == nil {
			doc, err = openapi2conv.ToV3(&d2)
		}
		if err != nil {
			return parsed{}, err
		}
		if len(doc.Servers) == 0 && d2.BasePath != "" {
			doc.AddServer(&openapi3.Server{URL: d2.BasePath})
		}
	} else {
		base, err := url.Parse(location)
		if err != nil {
			return parsed{}, err
		}
		loader.IsExternalRefsAllowed = false
		if doc, err = loader.LoadFromDataWithPath(src, base); err != nil {
			return parsed{}, err
		}
	}
	origin, base, host := "{origin}", "", ""
	if len(doc.Servers) > 0 {
		origin, base = splitServer(doc.Servers[0].URL)
		host = serverHost(doc.Servers[0].URL)
	}
	if prefix != "" {
		base = strings.TrimSuffix(prefix, "/")
	}
	var out parsed
	var diagnostics struct {
		Refs []string `json:"x-monitor-unresolved-refs"`
	}
	_ = json.Unmarshal(src, &diagnostics)
	for _, ref := range diagnostics.Refs {
		out.Warnings = append(out.Warnings, "unresolved request schema: "+ref)
	}
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
		for _, method := range sortedKeys(item.Operations()) {
			op := item.Operations()[method]
			route, query, fragment, err := requestPath(p)
			if err != nil {
				return parsed{}, err
			}
			inline := regexParam.FindAllStringSubmatch(route, -1)
			route = regexParam.ReplaceAllString(route, "{$1}")
			o := specOp{ID: op.OperationID, SourceID: op.OperationID, Summary: op.Summary + " " + op.Description, Method: method, Origin: origin, Path: patternPath(joinPath(base, route)), Base: base, Query: query, Tags: op.Tags, Body: "none"}
			if o.SourceID == "" {
				o.SourceID = method + " " + p
			}
			if severalBodies[method+" "+p] {
				o.Unsupported = "operation declares several body parameters"
			}
			servers := item.Servers
			if op.Servers != nil && len(*op.Servers) > 0 {
				servers = *op.Servers
			}
			if len(servers) > 0 {
				_, serverBase := splitServer(servers[0].URL)
				o.Base = serverBase
				o.Path = patternPath(joinPath(serverBase, route))
				if serverHost(servers[0].URL) != host {
					o.Origin, o.Server = serverOrigin(servers[0]), true
				}
			}
			o.PathPatterns = map[string]string{}
			for _, ref := range append(slices.Clone(item.Parameters), op.Parameters...) {
				if q := ref.Value; q != nil && q.In == "query" {
					for _, key := range queryKeys(q) {
						if slices.Contains(o.Params, key) {
							continue
						}
						o.Params = append(o.Params, key)
						if key == q.Name && resourceKey.MatchString(key) {
							o.Required = append(o.Required, param{q.Name, "query", "string", !q.Required})
						}
					}
					if value, ok := fragment[q.Name]; ok && q.Required {
						if o.Query == nil {
							o.Query = map[string]any{}
						}
						o.Query[q.Name] = value
					}
				}
				if q := ref.Value; q != nil && q.In == "header" && q.Required {
					if media := q.Content.Get(jsonMedia); media != nil {
						o.ArgHeader = http.CanonicalHeaderKey(q.Name)
						for _, p := range members(media.Schema, "header_json") {
							if !p.Optional {
								o.Required = append(o.Required, p)
							}
						}
					}
				}
				if q := ref.Value; q != nil && q.In == "path" && q.Schema != nil && q.Schema.Value != nil {
					if pattern := pathPattern(q.Schema.Value); pattern != "" {
						o.PathPatterns[q.Name] = pattern
					}
				}
			}
			for _, m := range inline {
				if _, err := regexp.Compile(m[2]); err == nil {
					o.PathPatterns[m[1]] = m[2]
				}
			}
			for _, s := range strings.Split(route, "/") {
				if multiParam.MatchString(s) {
					literals := pathParam.Split(s, -1)
					for i, literal := range literals {
						literals[i] = regexp.QuoteMeta(literal)
					}
					o.PathPatterns[strings.Trim(patternPath(s), "{}")] = strings.Join(literals, mergedParamPattern)
				}
			}
			if rb := op.RequestBody; rb != nil && rb.Value != nil {
				if len(rb.Value.Content) == 0 {
					o.Unsupported = "request body has no documented encoding"
					out.Ops = append(out.Ops, o)
					continue
				}
				if !rb.Value.Required && !needsFile(rb.Value.Content) {
					out.Ops = append(out.Ops, o)
				}
				schemas := map[string]*openapi3.SchemaRef{}
				variants := len(out.Ops)
				for _, media := range sortedKeys(rb.Value.Content) {
					variant := o
					variant.Body = "opaque"
					content := rb.Value.Content[media]
					switch kind := mediaBody(media); {
					case kind == "json" || media == "*/*" && content.Schema != nil && content.Schema.Value != nil && !content.Schema.Value.IsEmpty():
						variant = bodyVariant(o, "json", content.Schema)
					case kind == "form":
						variant = bodyVariant(o, "form", content.Schema)
					default:
						variant.Unsupported = "body encoding requires inspection: " + media
					}
					if _, seen := schemas[variant.Body]; !seen && variant.Unsupported == "" {
						schemas[variant.Body] = content.Schema
					}
					if !slices.ContainsFunc(out.Ops[variants:], func(v specOp) bool { return reflect.DeepEqual(v, variant) }) {
						out.Ops = append(out.Ops, variant)
					}
				}
				for _, body := range encodings {
					if _, declared := schemas[body]; declared {
						continue
					}
					for from, schema := range schemas {
						if from == "form" || bodyVariant(o, from, schema).BodyType == "object" {
							out.Ops = append(out.Ops, bodyVariant(o, body, schema))
						}
					}
				}
				continue
			}
			out.Ops = append(out.Ops, o)
		}
	}
	if origin == graphOrigin {
		for _, o := range slices.Clone(out.Ops) {
			if alias := odataAlias(o.Path); alias != o.Path {
				o.Path = alias
				out.Ops = append(out.Ops, o)
			}
		}
	}
	return out, nil
}

const mergedParamPattern = "[^,]+"

func bodyVariant(o specOp, body string, schema *openapi3.SchemaRef) specOp {
	o.Required = slices.Clone(o.Required)
	o.Body = body
	if body == "form" {
		o.Required = append(o.Required, members(schema, "form")...)
		return o
	}
	o.BodyType = "object"
	if schema != nil && schema.Value != nil {
		for _, typ := range []string{"array", "string", "boolean", "number", "integer", "null"} {
			if schema.Value.Type.Is(typ) {
				o.BodyType = typ
				if typ == "integer" {
					o.BodyType = "number"
				}
			}
		}
	}
	o.Required = append(o.Required, members(schema, "body")...)
	return o
}

// mediaBody classifies a media type as the connector inspects it, or returns "" for one it cannot.
func mediaBody(media string) string {
	typ, params, err := mime.ParseMediaType(media)
	switch {
	case err != nil || params["charset"] != "" && !strings.EqualFold(params["charset"], "utf-8"):
	case typ == jsonMedia || typ == textJSONMedia || strings.HasSuffix(typ, "+json"):
		return "json"
	case typ == formMedia:
		return "form"
	}
	return ""
}

var graphQualified = regexp.MustCompile(`^microsoft\.graph\.(?:[A-Za-z0-9]+\.)*`)

// odataAlias drops the empty parentheses of parameterless functions and the namespace of actions and functions, the form Microsoft Graph documents.
func odataAlias(path string) string {
	segs := strings.Split(path, "/")
	for i, s := range segs {
		segs[i] = graphQualified.ReplaceAllString(strings.TrimSuffix(s, "()"), "")
	}
	return strings.Join(segs, "/")
}

func queryKeys(q *openapi3.Parameter) []string {
	if q.Style == openapi3.SerializationDeepObject {
		if keys := deepKeys(q.Name, q.Schema, nil); len(keys) > 0 {
			return keys
		}
	}
	return []string{q.Name}
}

// deepKeys omits arrays and maps, which have no finite set of keys.
func deepKeys(prefix string, ref *openapi3.SchemaRef, seen []*openapi3.Schema) []string {
	if ref == nil || ref.Value == nil || slices.Contains(seen, ref.Value) {
		return nil
	}
	s := ref.Value
	seen = append(seen, s)
	alternatives := slices.Concat(s.AllOf, s.AnyOf, s.OneOf)
	var keys []string
	for _, alternative := range alternatives {
		keys = append(keys, deepKeys(prefix, alternative, seen)...)
	}
	switch {
	case len(s.Properties) > 0:
		for _, name := range sortedKeys(s.Properties) {
			keys = append(keys, deepKeys(prefix+"["+name+"]", s.Properties[name], seen)...)
		}
	case s.Type.Includes("object") || s.Type.Includes("array") || s.Items != nil || s.AdditionalProperties.Schema != nil:
	case s.Type != nil || len(alternatives) == 0:
		keys = append(keys, prefix)
	}
	return keys
}

func needsFile(content openapi3.Content) bool {
	for media, c := range content {
		s := c.Schema
		if !strings.HasPrefix(media, "multipart/") || s == nil || s.Value == nil || !slices.ContainsFunc(s.Value.Required, func(name string) bool {
			p := s.Value.Properties[name]
			return p != nil && p.Value != nil && (p.Value.Format == "binary" || p.Value.Items != nil && p.Value.Items.Value != nil && p.Value.Items.Value.Format == "binary")
		}) {
			return false
		}
	}
	return len(content) > 0
}

const (
	integerPattern = "[0-9]+"
	jsonMedia      = "application/json"
	textJSONMedia  = "text/json"
	formMedia      = "application/x-www-form-urlencoded"
	multipartMedia = "multipart/form-data"
	graphOrigin    = "https://graph.microsoft.com"
)

const (
	uploadTypeParam = "uploadType"
	uploadIDParam   = "upload_id"
	restCapture     = "path"
)

func pathPattern(s *openapi3.Schema) string {
	var values []string
	for _, v := range s.Enum {
		if text, ok := v.(string); ok {
			values = append(values, regexp.QuoteMeta(text))
		}
	}
	if len(values) > 0 && len(values) == len(s.Enum) {
		slices.Sort(values)
		return strings.Join(values, "|")
	}
	if re, err := syntax.Parse(s.Pattern, syntax.Perl); err == nil && re.Op == syntax.OpConcat && strings.HasPrefix(s.Pattern, "^") && strings.HasSuffix(s.Pattern, "$") &&
		re.Sub[0].Op == syntax.OpBeginText && re.Sub[len(re.Sub)-1].Op == syntax.OpEndText {
		return s.Pattern[1 : len(s.Pattern)-1]
	}
	if s.Type.Is("integer") {
		return integerPattern
	}
	return ""
}

func members(ref *openapi3.SchemaRef, from string) []param {
	if ref == nil || ref.Value == nil {
		return nil
	}
	var out []param
	for _, name := range sortedKeys(ref.Value.Properties) {
		p := ref.Value.Properties[name]
		if p == nil || p.Value == nil || !resourceKey.MatchString(name) {
			continue
		}
		optional := !slices.Contains(ref.Value.Required, name)
		switch t := p.Value.Type; {
		case from == "form":
			out = append(out, param{name, from, "string", optional})
		case t.Is("string"):
			out = append(out, param{name, from, "string", optional})
		case t.Is("integer"), t.Is("number"):
			out = append(out, param{name, from, "number", optional})
		case t.Is("array"):
			out = append(out, param{name, from, "array", optional})
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
	_, root := splitServer(doc.RootUrl)
	var global []string
	for name := range doc.Parameters {
		if !slices.Contains(credentialParams, name) {
			global = append(global, name)
		}
	}
	sort.Strings(global)
	out := parsed{Auth: &specAuth{Header: "Authorization", Prefix: "Bearer "}, Version: doc.Version}
	var walk func(methods map[string]discovery.RestMethod, resources map[string]discovery.RestResource)
	walk = func(methods map[string]discovery.RestMethod, resources map[string]discovery.RestResource) {
		for _, m := range sortedValues(methods) {
			o := specOp{ID: strings.TrimPrefix(m.Id, doc.Name+"."), Summary: m.Description, Method: m.HttpMethod, Origin: origin, Body: "none"}
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
			emit := func(o specOp, path string) {
				o.Path = patternPath(base + "/" + path)
				out.Ops = append(out.Ops, o)
				if m.UseMediaDownloadService {
					d := o
					d.ID, d.Path = o.ID+".download", patternPath(root+"/download/"+doc.ServicePath+path)
					out.Ops = append(out.Ops, d)
				}
				if m.MediaUpload != nil && m.MediaUpload.Protocols != nil && m.MediaUpload.Protocols.Simple != nil {
					params := slices.Clone(o.Params)
					if !slices.Contains(params, uploadTypeParam) {
						params = append(params, uploadTypeParam)
					}
					u := o
					u.ID, u.Body, u.Path, u.Params = o.ID+".upload", "any", patternPath(root+"/upload/"+doc.ServicePath+path), append(slices.Clone(params), uploadIDParam)
					out.Ops = append(out.Ops, u)
					if m.MediaUpload.Protocols.Resumable != nil && u.Method != http.MethodPut {
						u.ID, u.Method, u.Params, u.Query = u.ID+".session", http.MethodPut, params, map[string]any{uploadIDParam: true}
						out.Ops = append(out.Ops, u)
					}
				}
			}
			emit(o, cmp.Or(m.FlatPath, m.Path))
			if path, patterns := reservedPath(m); path != "" {
				o.ID, o.PathPatterns = o.ID+".nested", patterns
				emit(o, path)
			}
		}
		for _, r := range sortedValues(resources) {
			walk(r.Methods, r.Resources)
		}
	}
	walk(doc.Methods, doc.Resources)
	return out, nil
}

// reservedPath reaches the deeper paths a reserved expansion allows when its pattern ends in a wildcard: a wholly wildcard parameter becomes one capture, and otherwise a trailing capture follows the flat ones.
func reservedPath(m discovery.RestMethod) (string, map[string]string) {
	flat := strings.Split(m.FlatPath, "/")
	for _, name := range sortedKeys(m.Parameters) {
		_, after, ok := strings.Cut(m.Path, "{+"+name+"}")
		fixed, wildcard := strings.CutSuffix(strings.Trim(cmp.Or(m.Parameters[name].Pattern, "^.*$"), "^$"), ".*")
		if !ok || !wildcard || m.FlatPath == "" || strings.Contains(after, "{+") || fixed != "" && !strings.HasSuffix(fixed, "/") {
			continue
		}
		glued, _, _ := strings.Cut(after, "/")
		last := len(flat) - 1 - strings.Count(after, "/")
		literals := pathParam.Split(after, -1)
		for i, literal := range literals {
			literals[i] = regexp.QuoteMeta(literal)
		}
		rest := strings.Join(literals, segmentValue)
		if fixed == "" {
			return strings.Join(append(flat[:last:last], "{"+name+"*}"), "/"), map[string]string{name: segmentValue + "/" + restValue + rest}
		}
		return strings.Join(append(flat[:last:last], strings.TrimSuffix(flat[last], glued), "{"+restCapture+"*}"), "/"), map[string]string{restCapture: restValue + rest}
	}
	return "", nil
}

type introspectionType struct {
	Kind, Name string
	OfType     *introspectionType
}

func (t introspectionType) ast() *ast.Type {
	switch t.Kind {
	case "NON_NULL":
		inner := t.OfType.ast()
		inner.NonNull = true
		return inner
	case "LIST":
		return ast.ListType(t.OfType.ast(), nil)
	}
	return ast.NamedType(t.Name, nil)
}

// introspectedSchema builds the types and root fields parseGraphQL reads from an introspection result, with or without its data envelope.
func introspectedSchema(src []byte) (*ast.Schema, error) {
	type introspection struct {
		QueryType, MutationType *struct{ Name string }
		Types                   []struct {
			Kind              ast.DefinitionKind
			Name, Description string
			Fields            []struct {
				Name, Description string
				Args              []struct {
					Name string
					Type introspectionType
				}
				Type introspectionType
			}
		}
	}
	var result struct {
		Data struct {
			Schema *introspection `json:"__schema"`
		}
		Schema *introspection `json:"__schema"`
	}
	if err := json.Unmarshal(src, &result); err != nil {
		return nil, err
	}
	s := cmp.Or(result.Schema, result.Data.Schema)
	if s == nil {
		return nil, fmt.Errorf("GraphQL introspection result has no __schema")
	}
	schema := &ast.Schema{Types: map[string]*ast.Definition{}}
	for _, t := range s.Types {
		def := &ast.Definition{Kind: t.Kind, Name: t.Name, Description: t.Description}
		for _, f := range t.Fields {
			field := &ast.FieldDefinition{Name: f.Name, Description: f.Description, Type: f.Type.ast()}
			for _, a := range f.Args {
				field.Arguments = append(field.Arguments, &ast.ArgumentDefinition{Name: a.Name, Type: a.Type.ast()})
			}
			def.Fields = append(def.Fields, field)
		}
		schema.Types[t.Name] = def
	}
	if s.QueryType != nil {
		schema.Query = schema.Types[s.QueryType.Name]
	}
	if s.MutationType != nil {
		schema.Mutation = schema.Types[s.MutationType.Name]
	}
	return schema, nil
}

func parseGraphQL(src []byte, origin, path string) (parsed, error) {
	source := &ast.Source{Name: "schema.graphql", Input: string(src)}
	var schema *ast.Schema
	var err error
	if json.Valid(src) {
		schema, err = introspectedSchema(src)
	} else if schema, err = gqlparser.LoadSchema(source); err != nil && strings.Contains(err.Error(), "Cannot redeclare type") {
		schema, err = validator.LoadSchema(source)
	}
	if err != nil {
		return parsed{}, err
	}
	var out parsed
	for _, kind := range []string{"query", "mutation"} {
		root := schema.Query
		if kind == "mutation" {
			root = schema.Mutation
		}
		if root == nil {
			continue
		}
		for _, f := range root.Fields {
			if strings.HasPrefix(f.Name, "__") {
				continue
			}
			o := specOp{ID: f.Name, Summary: f.Description, Method: "POST", Origin: origin, Path: path, Body: "graphql", GraphQL: []string{kind, f.Name}, Tags: []string{kind}}
			resource := f.Type.Name()
			if def := schema.Types[resource]; def != nil && def.Kind == ast.Object {
				for _, suffix := range []string{"Connection", "Payload", "Response", "Result"} {
					resource = strings.TrimSuffix(resource, suffix)
				}
				resource = resourceWords(resource, true, false)
				if resource != "" && !slices.Contains(groupVerbs, resource) {
					o.Resource = resource
				}
			}
			for _, a := range f.Arguments {
				if a.Type.NonNull && resourceKey.MatchString(a.Name) {
					typ := "string"
					if a.Type.Elem != nil {
						typ = "array"
					} else {
						switch a.Type.NamedType {
						case "Int", "Float":
							typ = "number"
						case "Boolean":
							typ = "boolean"
						default:
							if def := schema.Types[a.Type.NamedType]; def != nil && def.Kind == ast.InputObject {
								typ = "object"
							}
						}
					}
					o.Required = append(o.Required, param{a.Name, "argument", typ, false})
				}
			}
			out.Ops = append(out.Ops, o)
		}
	}
	slices.SortFunc(out.Ops, func(a, b specOp) int { return strings.Compare(a.GraphQL[0]+a.ID, b.GraphQL[0]+b.ID) })
	return out, nil
}

const (
	awsPartition     = "aws"
	awsEndpoints     = "aws_endpoints"
	s3EndpointPrefix = "s3"
	s3OperationParam = "x-id"
	s3PathStyle      = "path_style"
	s3VirtualHosted  = "virtual_hosted"
)

var botocoreProtocols = []string{"json", "query", "ec2", "rest-json", "rest-xml"}

type botocoreModel struct {
	Metadata struct {
		Protocol, TargetPrefix, EndpointPrefix, ServiceFullName, SigningName string
		Protocols                                                            []string
	}
	Operations map[string]struct {
		Name          string
		HTTP          struct{ Method, RequestURI string } `json:"http"`
		Input         *struct{ Shape string }
		Documentation string
		Deprecated    bool
	}
	Shapes map[string]struct {
		Required []string
		Members  map[string]struct {
			Shape, Location, LocationName string
		}
		Type string
	}
	Partitions []botocorePartition
}

type botocoreEndpoint struct {
	Hostname, DNSSuffix string
	CredentialScope     struct{ Region string }
	Tags                []string
	Variants            []botocoreEndpoint
}

type botocorePartition struct {
	Partition, DNSSuffix string
	Defaults             botocoreEndpoint
	Regions              map[string]struct{}
	Services             map[string]struct {
		Defaults       botocoreEndpoint
		Endpoints      map[string]botocoreEndpoint
		IsRegionalized *bool
	}
}

func (p *botocorePartition) origins(prefix string) map[string][]string {
	service := p.Services[prefix]
	endpoints := map[string]botocoreEndpoint{}
	maps.Copy(endpoints, service.Endpoints)
	variants := slices.Concat(service.Defaults.Variants, p.Defaults.Variants)
	defaults := append([]botocoreEndpoint{service.Defaults, p.Defaults}, variants...)
	if service.IsRegionalized == nil || *service.IsRegionalized {
		var region botocoreEndpoint
		for _, v := range variants {
			region.Variants = append(region.Variants, botocoreEndpoint{Tags: v.Tags})
		}
		endpoints["{region}"] = region
	}
	var hosts []string
	for key, e := range endpoints {
		_, regional := p.Regions[key]
		for _, v := range append([]botocoreEndpoint{e}, e.Variants...) {
			if v.Hostname == "" && !regional && key != "{region}" {
				continue
			}
			for _, d := range defaults {
				if slices.Equal(v.Tags, d.Tags) {
					v.Hostname, v.DNSSuffix = cmp.Or(v.Hostname, d.Hostname), cmp.Or(v.DNSSuffix, d.DNSSuffix)
				}
			}
			host := strings.NewReplacer("{service}", prefix, "{region}", key, "{dnsSuffix}", cmp.Or(v.DNSSuffix, p.DNSSuffix)).Replace(v.Hostname)
			labels := strings.Split(host, ".")
			for i, label := range labels {
				if label == cmp.Or(e.CredentialScope.Region, key) {
					labels[i] = "{region}"
				}
			}
			if strings.HasSuffix(host, "."+p.DNSSuffix) {
				hosts = append(hosts, "https://"+strings.Join(labels, "."))
			}
		}
	}
	slices.Sort(hosts)
	hosts = slices.Compact(hosts)
	if prefix != s3EndpointPrefix {
		return map[string][]string{"origin": hosts}
	}
	buckets := make([]string, len(hosts))
	for i, host := range hosts {
		buckets[i] = strings.Replace(host, "://", "://{Bucket}.", 1)
	}
	return map[string][]string{s3PathStyle: hosts, "origin": buckets}
}

func parseBotocore(src []byte) (parsed, error) {
	var m botocoreModel
	if err := json.Unmarshal(src, &m); err != nil {
		return parsed{}, err
	}
	if m.Partitions != nil {
		i := slices.IndexFunc(m.Partitions, func(p botocorePartition) bool { return p.Partition == awsPartition })
		if i < 0 {
			return parsed{}, fmt.Errorf("botocore endpoints have no %s partition", awsPartition)
		}
		return parsed{Partition: &m.Partitions[i]}, nil
	}
	out := parsed{Auth: &specAuth{SigV4: cmp.Or(m.Metadata.SigningName, m.Metadata.EndpointPrefix)}, EndpointPrefix: m.Metadata.EndpointPrefix}
	protocol := m.Metadata.Protocol
	if i := slices.IndexFunc(m.Metadata.Protocols, func(p string) bool { return slices.Contains(botocoreProtocols, p) }); i >= 0 {
		protocol = m.Metadata.Protocols[i]
	}
	// S3 SDKs send x-id on operations whose method and URI another current operation shares.
	shared := map[string]int{}
	for _, op := range m.Operations {
		if !op.Deprecated {
			shared[op.HTTP.Method+" "+op.HTTP.RequestURI]++
		}
	}
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
		switch protocol {
		case "json":
			o.Method, o.Path, o.Body = "POST", "/", "any"
			o.Headers = map[string]any{"X-Amz-Target": m.Metadata.TargetPrefix + "." + name}
		case "query", "ec2":
			o.Method, o.Path, o.Body = "POST", "/", "form"
			o.Fields = map[string]any{"Action": name}
			for _, r := range shape.Required {
				if resourceKey.MatchString(r) && m.Shapes[shape.Members[r].Shape].Type == "string" {
					o.Required = append(o.Required, param{r, "form", "string", false})
				}
			}
		case "rest-json", "rest-xml":
			uri, query, _ := strings.Cut(op.HTTP.RequestURI, "?")
			o.Path, o.Body, o.Query = patternPath(uri), "any", map[string]any{}
			if op.HTTP.Method == "GET" || op.HTTP.Method == "HEAD" || op.HTTP.Method == "DELETE" {
				o.Body = "none"
			}
			if query != "" {
				for _, kv := range strings.Split(query, "&") {
					k, v, _ := strings.Cut(kv, "=")
					o.Query[k] = v
				}
			}
			for _, name := range sortedKeys(shape.Members) {
				member, required := shape.Members[name], slices.Contains(shape.Required, name)
				switch {
				case member.Location == "querystring" && required:
					o.Query[member.LocationName] = true
				case member.Location == "querystring":
					o.Params = append(o.Params, member.LocationName)
				case member.Location == "header" && required:
					if o.Headers == nil {
						o.Headers = map[string]any{}
					}
					o.Headers[http.CanonicalHeaderKey(member.LocationName)] = true
				}
			}
			if m.Metadata.EndpointPrefix == s3EndpointPrefix && shared[op.HTTP.Method+" "+op.HTTP.RequestURI] > 1 {
				o.Params = append(o.Params, s3OperationParam)
			}
		default:
			return parsed{}, fmt.Errorf("botocore protocol %s is not supported", protocol)
		}
		if m.Metadata.EndpointPrefix == s3EndpointPrefix {
			o.Origin = "{" + s3PathStyle + "}"
		}
		out.Ops = append(out.Ops, o)
		if key, ok := strings.CutPrefix(o.Path, "/{Bucket}"); ok && m.Metadata.EndpointPrefix == s3EndpointPrefix {
			o.ID, o.Origin, o.Path = name+"."+s3VirtualHosted, "{origin}", cmp.Or(key, "/")
			out.Ops = append(out.Ops, o)
		}
	}
	// An operation sharing its route with one that requires a header matches only requests without that header.
	route := func(o specOp) string {
		query, _ := json.Marshal(o.Query)
		return o.Method + " " + o.Origin + o.Path + string(query)
	}
	required := map[string][]string{}
	for _, o := range out.Ops {
		for header, value := range o.Headers {
			if value == true {
				required[route(o)] = append(required[route(o)], header)
			}
		}
	}
	for i, o := range out.Ops {
		for _, header := range required[route(o)] {
			if _, ok := o.Headers[header]; !ok {
				headers := map[string]any{header: nil}
				maps.Copy(headers, o.Headers)
				o.Headers, out.Ops[i].Headers = headers, headers
			}
		}
	}
	return out, nil
}

func parsePostman(src []byte, ref specRef) (parsed, error) {
	c, err := postman.ParseCollection(bytes.NewReader(src))
	if err != nil {
		return parsed{}, err
	}
	for _, name := range sortedKeys(ref.Variables) {
		c.Variables = append([]*postman.Variable{{Key: name, Value: ref.Variables[name]}}, c.Variables...)
	}
	captures := map[string]*regexp.Regexp{}
	for name, pattern := range ref.Captures {
		if captures[name], err = regexp.Compile(`\A(?:` + pattern + `)\z`); err != nil {
			return parsed{}, err
		}
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
			if len(u.Host) == 0 && len(u.Path) == 0 {
				u = rawURL(u.Raw, c.Variables)
			}
			var segs []string
			patterns := map[string]string{}
			for _, s := range u.Path {
				if strings.HasPrefix(s, ":") {
					s = "{" + s[1:] + "}"
				}
				s = postmanVar.ReplaceAllString(s, "{$1}")
				for _, name := range sortedKeys(captures) {
					if captures[name].MatchString(s) {
						s, patterns[name] = "{"+name+"}", ref.Captures[name]
					}
				}
				segs = append(segs, s)
			}
			origin := "{origin}"
			if host := strings.Join(u.Host, "."); host != "" && !strings.Contains(host, "{") {
				origin = "https://" + strings.ToLower(host)
			}
			o := specOp{ID: it.Name, Summary: it.Name, Method: string(it.Request.Method), Origin: origin, Path: patternPath("/" + strings.Join(segs, "/")), PathPatterns: patterns, Tags: tags, Body: "none"}
			for _, q := range u.Query {
				o.Params = append(o.Params, q.Key)
			}
			if b := it.Request.Body; b != nil && b.Mode != "" {
				o.Body = "any"
				if b.Mode == "raw" && (b.Options != nil && b.Options.Raw.Language == postman.JSON || slices.ContainsFunc(it.Request.Header, func(h *postman.Header) bool {
					return !h.Disabled && strings.EqualFold(h.Key, "Content-Type") && mediaBody(h.Value) == "json"
				})) {
					o.Body = "json"
					if strings.HasPrefix(strings.TrimSpace(b.Raw), "[") {
						o.BodyType = "array"
					}
				}
			}
			out.Ops = append(out.Ops, o)
		}
	}
	walk(c.Items, nil)
	names, qualified := map[string]int{}, map[string]int{}
	for _, o := range out.Ops {
		names[o.ID]++
	}
	for i, o := range out.Ops {
		if names[o.ID] > 1 {
			id := strings.Join(append(slices.Clone(o.Tags), o.ID), "/")
			if qualified[id]++; qualified[id] > 1 {
				id += fmt.Sprintf(" #%d", qualified[id])
			}
			out.Ops[i].ID = id
		}
	}
	return out, nil
}

// rawURL breaks down a URL written as a string, substituting a leading collection variable or dropping an undefined one.
func rawURL(raw string, variables []*postman.Variable) *postman.URL {
	if name, rest, ok := strings.Cut(strings.TrimPrefix(raw, "{{"), "}}"); ok && strings.HasPrefix(raw, "{{") {
		raw = rest
		if i := slices.IndexFunc(variables, func(v *postman.Variable) bool { return v.Key == strings.TrimSpace(name) }); i >= 0 {
			raw = variables[i].Value + rest
		}
	}
	u := &postman.URL{Raw: raw}
	path, query, _ := strings.Cut(raw, "?")
	if _, rest, ok := strings.Cut(path, "://"); ok {
		var host string
		host, path, _ = strings.Cut(rest, "/")
		u.Host = strings.Split(host, ".")
	}
	u.Path = strings.Split(strings.Trim(path, "/"), "/")
	values, _ := url.ParseQuery(query)
	for _, key := range sortedKeys(values) {
		u.Query = append(u.Query, &postman.QueryParam{Key: key})
	}
	return u
}
