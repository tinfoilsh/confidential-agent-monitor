package main

import (
	"cmp"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/go-openapi/jsonpointer"
	"sigs.k8s.io/yaml"
)

type documentStamp struct {
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
}

type documentationBundle struct {
	Documents  []documentStamp `json:"documents"`
	Operations []specOp        `json:"operations"`
}

func airtableDocument(src []byte) ([]byte, error) {
	const marker = "window.initData = "
	_, raw, ok := strings.Cut(string(src), marker)
	if !ok {
		return nil, fmt.Errorf("Airtable page has no public specification")
	}
	var state struct {
		OpenAPI json.RawMessage `json:"openApi"`
	}
	if err := json.NewDecoder(strings.NewReader(raw)).Decode(&state); err != nil {
		return nil, err
	}
	var spec map[string]any
	if err := json.Unmarshal(state.OpenAPI, &spec); err != nil {
		return nil, err
	}
	if spec["openapi"] == nil || spec["paths"] == nil {
		return nil, fmt.Errorf("Airtable document is not OpenAPI")
	}
	return json.Marshal(spec)
}

var slackMethodURL = regexp.MustCompile(`https://docs\.slack\.dev/reference/methods/([A-Za-z][A-Za-z0-9_.]+)/?`)
var slackArgument = regexp.MustCompile("(?m)^\\*\\*`([^`]+)`\\*\\*(?:`([^`]+)`)?(Required|Optional)")
var slackMethodAccess = regexp.MustCompile(`(?m)^([A-Z]+) https://slack\.com/api/([A-Za-z0-9_.]+)$`)

func parseSlackMethod(src []byte, location string) ([]specOp, error) {
	parts := strings.SplitN(string(src), "---", 3)
	if len(parts) != 3 {
		return nil, fmt.Errorf("%s has no method metadata", location)
	}
	var meta struct {
		Name    string `json:"method_name"`
		Method  string `json:"http_method"`
		Summary string `json:"summary"`
	}
	if err := yaml.Unmarshal([]byte(parts[1]), &meta); err != nil {
		return nil, err
	}
	if meta.Name == "" {
		return nil, fmt.Errorf("%s has no method metadata", location)
	}
	if access := slackMethodAccess.FindStringSubmatch(parts[2]); meta.Method == "" && access != nil && access[2] == meta.Name {
		meta.Method = access[1]
	}
	digest := sha256.Sum256(src)
	base := specOp{ID: meta.Name, SourceID: meta.Name, SourceURL: location, SourceHash: hex.EncodeToString(digest[:]), Summary: meta.Summary, Method: strings.ToUpper(meta.Method), Origin: "https://slack.com", Path: "/api/" + meta.Name, Body: "none"}
	if !httpMethods.MatchString(strings.ToLower(meta.Method)) {
		base.Method, base.Unsupported = "", "method documentation has no HTTP method"
		return []specOp{base}, nil
	}
	args, _, _ := strings.Cut(parts[2], "## Usage")
	_, args, _ = strings.Cut(args, "## Arguments")
	var encodings []string
	if base.Method == "GET" {
		encodings = []string{"none", "form"}
	} else {
		facts, _, _ := strings.Cut(parts[2], "## Arguments")
		if strings.Contains(facts, "application/json") {
			encodings = append(encodings, "json")
		}
		if strings.Contains(facts, "application/x-www-form-urlencoded") {
			encodings = append(encodings, "form")
		}
		if len(encodings) == 0 {
			encodings = []string{"opaque"}
		}
	}
	arguments := slackArgument.FindAllStringSubmatch(args, -1)
	var out []specOp
	for _, body := range encodings {
		o := base
		o.Body = body
		if body != "none" {
			o.Method = "POST"
		}
		if body == "opaque" {
			o.Unsupported = "method documentation has no inspectable request encoding"
		}
		for _, arg := range arguments {
			name, typ, optional := arg[1], cmp.Or(arg[2], "string"), arg[3] == "Optional"
			if name == "token" {
				continue
			}
			from := "body"
			if body == "none" {
				from = "query"
				o.Params = append(o.Params, name)
			}
			if body == "form" {
				from = "form"
			}
			if !resourceKey.MatchString(name) {
				continue
			}
			if from != "body" {
				typ = "string"
			}
			switch typ {
			case "string", "array", "number":
				o.Required = append(o.Required, param{name, from, typ, optional})
			}
		}
		out = append(out, o)
	}
	if !slices.ContainsFunc(arguments, func(arg []string) bool { return arg[1] != "token" && arg[3] == "Required" }) {
		o := base
		o.Method = "POST"
		out = append(out, o)
	}
	return out, nil
}

func slackDocument(index []byte, headers map[string]string) ([]byte, error) {
	urls := map[string]bool{}
	for _, match := range slackMethodURL.FindAllStringSubmatch(string(index), -1) {
		urls["https://docs.slack.dev/reference/methods/"+match[1]+".md"] = true
	}
	if len(urls) == 0 {
		return nil, fmt.Errorf("Slack sitemap contains no method pages")
	}
	locations := sortedKeys(urls)
	results := make([]documentationBundle, len(locations))
	errs := make([]error, len(locations))
	var wg sync.WaitGroup
	slots := make(chan struct{}, 8)
	for i, location := range locations {
		wg.Go(func() {
			slots <- struct{}{}
			defer func() { <-slots }()
			src, err := download(location, headers)
			if err == nil {
				var ops []specOp
				ops, err = parseSlackMethod(src, location)
				if err == nil {
					sum := sha256.Sum256(src)
					results[i] = documentationBundle{Documents: []documentStamp{{location, hex.EncodeToString(sum[:])}}, Operations: ops}
				}
			}
			errs[i] = err
		})
	}
	wg.Wait()
	var bundle documentationBundle
	for i, result := range results {
		if errs[i] != nil {
			return nil, fmt.Errorf("%s: %w", locations[i], errs[i])
		}
		bundle.Documents = append(bundle.Documents, result.Documents...)
		bundle.Operations = append(bundle.Operations, result.Operations...)
	}
	return json.Marshal(bundle)
}

func sourceBytes(ref specRef, url string) ([]byte, error) {
	src, err := download(url, ref.Headers)
	if err != nil {
		return nil, err
	}
	switch ref.Format {
	case "airtable":
		return airtableDocument(src)
	case "slack":
		return slackDocument(src, ref.Headers)
	}
	if ref.Pointer == "" {
		return src, nil
	}
	var doc any
	if err := json.Unmarshal(src, &doc); err != nil {
		return nil, err
	}
	pointer, err := jsonpointer.New(ref.Pointer)
	if err != nil {
		return nil, err
	}
	embedded, _, err := pointer.Get(doc)
	if err != nil {
		return nil, err
	}
	if text, ok := embedded.(string); ok {
		return []byte(text), nil
	}
	return json.Marshal(embedded)
}

func parseDocumentation(src []byte) (parsed, error) {
	var bundle documentationBundle
	if err := json.Unmarshal(src, &bundle); err != nil {
		return parsed{}, err
	}
	if len(bundle.Operations) == 0 {
		return parsed{}, fmt.Errorf("documentation bundle contains no operations")
	}
	return parsed{Ops: slices.Clone(bundle.Operations), Auth: &specAuth{Header: "Authorization", Prefix: "Bearer "}}, nil
}
