// Command presets drafts monitor presets from public API specs for the services in the n8n catalog.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
)

const (
	catalogPath = "../../../n8n-catalog.json"
	sourcesPath = "sources.json"
	lockPath    = "sources.lock.json"
	cacheDir    = ".cache"
	draftsDir   = "../../presets/drafts"
	shippedDir  = "../../presets"
)

// Generic credentials name no vendor, so a node with only these is not a service.
var genericCredentials = []string{
	"jwtAuth", "httpBasicAuth", "httpHeaderAuth", "httpQueryAuth", "httpDigestAuth", "httpCustomAuth", "httpBearerAuth",
	"httpMultipleHeadersAuth", "oAuth1Api", "oAuth2Api", "httpSslAuth",
}

// Credentials several services of one vendor share; they do not make two nodes one service.
var sharedCredentials = append([]string{"googleApi", "aws", "awsAssumeRole", "microsoftOAuth2Api", "microsoftEntraServicePrincipalApi"}, genericCredentials...)

type catalog struct {
	Nodes       []*node       `json:"nodes"`
	Credentials []*credential `json:"credentials"`
}

type node struct {
	Name        string   `json:"name"`
	DisplayName string   `json:"displayName"`
	Categories  []string `json:"categories"`
	Credentials []string `json:"credentials"`
	Origins     []string `json:"origins"`
	Endpoints   []string `json:"endpoints"`
	Resources   []struct {
		Resource   string `json:"resource"`
		Operations []struct {
			Value string `json:"value"`
		} `json:"operations"`
	} `json:"resources"`
}

type credential struct {
	Name        string `json:"name"`
	DisplayName string `json:"displayName"`
	Kind        string `json:"kind"`
	Fields      []struct {
		Name    string `json:"name"`
		Label   string `json:"label"`
		Secret  bool   `json:"secret"`
		Default any    `json:"default"`
	} `json:"fields"`
	Authenticate *struct {
		Properties struct {
			Headers map[string]any `json:"headers"`
			Qs      map[string]any `json:"qs"`
			Auth    map[string]any `json:"auth"`
			Body    map[string]any `json:"body"`
		} `json:"properties"`
	} `json:"authenticate"`
	OAuth map[string]any `json:"oauth"`
}

type service struct {
	Name        string        `json:"name"`
	Title       string        `json:"title"`
	Nodes       []*node       `json:"-"`
	Credentials []*credential `json:"-"`
	NodeNames   []string      `json:"nodes"`
	CredNames   []string      `json:"credentials"`
	Origins     []string      `json:"origins"`
}

var (
	camel     = regexp.MustCompile(`([a-z0-9])([A-Z])`)
	langchain = regexp.MustCompile(`^(embeddings|lmChat|vectorStore|chatHubVectorStore|memory|tool)([A-Z])`)
)

func snake(s string) string {
	return strings.ToLower(camel.ReplaceAllString(s, "${1}_${2}"))
}

func load[T any](path string) (T, error) {
	var v T
	src, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(src, &v)
	}
	return v, err
}

// services groups catalog nodes into one service per connected set of vendor credentials;
// a node with only shared credentials is its own service.
func services(c catalog) []*service {
	creds := map[string]*credential{}
	for _, cr := range c.Credentials {
		creds[cr.Name] = cr
	}
	parent := map[string]string{}
	var find func(string) string
	find = func(x string) string {
		if p, ok := parent[x]; ok && p != x {
			parent[x] = find(p)
			return parent[x]
		}
		parent[x] = x
		return x
	}
	for _, n := range c.Nodes {
		find(n.Name)
		for _, cr := range n.Credentials {
			if !slices.Contains(sharedCredentials, cr) {
				parent[find("cred:"+cr)] = find(n.Name)
			}
		}
	}
	components := map[string][]*node{}
	for _, n := range c.Nodes {
		if !slices.ContainsFunc(n.Credentials, func(cr string) bool { return !slices.Contains(genericCredentials, cr) }) {
			continue
		}
		components[find(n.Name)] = append(components[find(n.Name)], n)
	}
	// The base package's node names the service; LangChain vendor nodes and triggers of the same name join it.
	byName := map[string]*service{}
	for _, nodes := range components {
		slices.SortStableFunc(nodes, func(a, b *node) int {
			if c := strings.Compare(strings.SplitN(b.Name, ".", 2)[0], strings.SplitN(a.Name, ".", 2)[0]); c != 0 {
				return c
			}
			return len(b.Resources) - len(a.Resources)
		})
		short := strings.TrimSuffix(strings.TrimSuffix(strings.SplitN(nodes[0].Name, ".", 2)[1], "Tool"), "Trigger")
		short = langchain.ReplaceAllString(short, "$2")
		s := byName[snake(short)]
		if s == nil {
			s = &service{Name: snake(short), Title: strings.TrimSuffix(nodes[0].DisplayName, " Trigger")}
			byName[s.Name] = s
		}
		s.Nodes = append(s.Nodes, nodes...)
	}
	var out []*service
	for _, s := range byName {
		out = append(out, s)
		for _, n := range s.Nodes {
			for _, cr := range n.Credentials {
				if !slices.Contains(s.CredNames, cr) && creds[cr] != nil {
					s.CredNames = append(s.CredNames, cr)
					s.Credentials = append(s.Credentials, creds[cr])
				}
			}
			s.NodeNames = append(s.NodeNames, n.Name)
			for _, o := range n.Origins {
				if !slices.Contains(s.Origins, o) {
					s.Origins = append(s.Origins, o)
				}
			}
		}
	}
	slices.SortFunc(out, func(a, b *service) int { return strings.Compare(a.Name, b.Name) })
	return out
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: presets services|update|fetch|draft [service...]; update with no services resolves only those sources.json changed")
		os.Exit(2)
	}
	c, err := load[catalog](catalogPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	all := services(c)
	switch os.Args[1] {
	case "services":
		out, _ := json.MarshalIndent(all, "", "  ")
		fmt.Println(string(out))
	case "fetch", "update":
		var sources map[string]source
		var lock lockFile
		if sources, err = load[map[string]source](sourcesPath); err != nil {
			break
		}
		if lock, err = load[lockFile](lockPath); errors.Is(err, os.ErrNotExist) {
			lock, err = lockFile{}, nil
		}
		if err != nil {
			break
		}
		if os.Args[1] == "fetch" {
			err = fetch(sources, lock)
			break
		}
		if err = update(sources, lock, os.Args[2:]); err == nil {
			out, _ := json.MarshalIndent(lock, "", "  ")
			err = os.WriteFile(lockPath, append(out, '\n'), 0o644)
		}
	case "draft":
		err = draftAll(all, os.Args[2:])
	default:
		err = fmt.Errorf("unknown command %s", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
