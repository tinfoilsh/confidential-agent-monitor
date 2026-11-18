package main

import (
	"fmt"
	"path"
	"slices"
	"strings"
)

const module = "github.com/tinfoilsh/confidential-agent-monitor"

type role string

const (
	library     role = "library"
	protocol    role = "protocol"
	product     role = "product"
	application role = "application"
	tooling     role = "tooling"
)

type rule struct {
	Role role
	Deps []string
}

var packages = map[string]rule{
	"core":                          {library, []string{"core/connector", "core/facts", "core/transport/netx"}},
	"core/admission":                {library, nil},
	"core/approval":                 {library, nil},
	"core/certificates":             {library, []string{"core/facts"}},
	"core/connector":                {library, []string{"core/facts"}},
	"core/facts":                    {library, nil},
	"core/identity":                 {library, []string{"core/facts"}},
	"core/sealedlog":                {library, nil},
	"core/tomledit":                 {library, []string{"core/facts"}},
	"core/transport/netx":           {library, nil},
	"core/transport/noisetransport": {library, nil},
	"core/transport/sshtransport":   {library, []string{"core/transport/netx"}},
	"connector/browser":             {protocol, []string{"core/connector", "core/facts"}},
	"connector/email":               {protocol, []string{"core/connector", "core/facts", "core/transport/netx"}},
	"connector/mcp":                 {protocol, []string{"core/connector", "core/facts", "core/transport/netx"}},
	"connector/mqtt":                {protocol, []string{"core/connector", "core/facts"}},
	"connector/nats":                {protocol, []string{"core/connector", "core/facts"}},
	"connector/postgres":            {protocol, []string{"core/connector", "core/facts"}},
	"connector/redis":               {protocol, []string{"core/connector", "core/facts"}},
	"connector/session":             {protocol, []string{"core/connector", "core/facts"}},
	"connector/signer":              {protocol, []string{"core/connector", "core/facts"}},
	"connector/tcp":                 {protocol, []string{"core/connector", "core/facts", "core/transport/netx"}},
	"connector/tinfoil":             {product, []string{"connector/tinfoil/messages", "connector/slots", "connector/web", "connector/worker", "core/connector", "core/facts", "core/transport/netx"}},
	"connector/tinfoil/messages":    {product, nil},
	"connector/udp":                 {protocol, []string{"core/connector", "core/facts", "core/transport/netx"}},
	"connector/web":                 {protocol, []string{"core/connector", "core/facts", "core/transport/netx"}},
	"connector/catalog":             {library, nil},
	"connector/credential":          {library, nil},
	"connector/slots":               {library, []string{"core/connector", "core/facts"}},
	"connector/worker":              {library, []string{"core/connector", "core/facts", "core/transport/netx"}},
	"ui":                            {product, nil},
	"cmd/perimeter/format":          {product, []string{"core/sealedlog", "core/tomledit"}},
	"cmd/perimeter/config":          {product, []string{"cmd/perimeter/format", "core/facts", "core/tomledit", "connector/catalog"}},
	"cmd/perimeter/sandbox":         {product, []string{"core/connector", "core/facts", "core/transport/sshtransport", "connector/tinfoil"}},
	"cmd/perimeter/connections": {product, []string{
		"cmd/perimeter/config", "cmd/perimeter/format", "cmd/perimeter/sandbox",
		"core/connector", "core/facts", "core/transport/netx",
		"connector/email", "connector/mcp", "connector/mqtt", "connector/nats", "connector/postgres",
		"connector/redis", "connector/session", "connector/signer", "connector/slots", "connector/tcp",
		"connector/tinfoil", "connector/udp", "connector/web", "connector/worker",
	}},
	"cmd/perimeter": {application, []string{
		"cmd/perimeter/config", "cmd/perimeter/connections", "cmd/perimeter/format",
		"cmd/perimeter/sandbox", "ui",
		"core", "core/admission", "core/approval", "core/certificates", "core/connector",
		"core/facts", "core/identity", "core/sealedlog", "core/tomledit", "core/transport/netx",
		"core/transport/noisetransport", "core/transport/sshtransport",
		"connector/catalog", "connector/credential", "connector/worker",
	}},
	"cmd/other": {application, []string{
		"core", "core/admission", "core/certificates", "core/connector", "core/facts", "core/transport/sshtransport",
		"connector/postgres", "connector/tcp",
	}},
	"dev/checkcore": {tooling, nil},
	"dev/presets":   {tooling, nil},
	"dev/manual_tests": {tooling, []string{
		"connector/catalog", "connector/credential", "connector/slots", "connector/web",
		"core/certificates", "core/connector", "core/facts", "core/transport/netx",
	}},
	"cmd/slackreview": {application, []string{
		"core", "core/approval", "core/connector", "core/facts", "core/transport/sshtransport", "connector/postgres",
	}},
}

var modules = []string{
	".", "cmd/other", "cmd/perimeter", "cmd/slackreview", "core/tomledit",
	"connector/browser", "connector/credential", "connector/email", "connector/mcp",
	"connector/mqtt", "connector/nats", "connector/postgres", "connector/redis",
	"connector/session", "connector/slots", "connector/tinfoil", "connector/web",
	"dev/manual_tests", "dev/presets",
}

var cedarPackages = []string{
	"cmd/other", "core", "core/admission", "core/certificates", "core/connector", "core/facts", "connector/postgres", "connector/tcp",
	"core/transport/netx", "core/transport/sshtransport",
}

var productSDKs = []string{
	"github.com/tinfoilsh/tinfoil-go", "github.com/open-policy-agent/opa", "gocloud.dev",
}

func within(name, prefix string) bool { return name == prefix || strings.HasPrefix(name, prefix+"/") }

func localPackage(name string) (string, bool) {
	if name == module {
		return ".", true
	}
	return strings.TrimPrefix(name, module+"/"), within(name, module)
}

func (r rule) composes() bool { return r.Role == application || r.Role == tooling }
func (r rule) reusable() bool { return r.Role == library || r.Role == protocol }

func (r rule) packageName(name string) string {
	if r.composes() {
		return "main"
	}
	return path.Base(name)
}

func fence(name, dependency string, rules map[string]rule) string {
	r := rules[name]
	if target, local := localPackage(dependency); local {
		t, known := rules[target]
		if !known {
			return "unlisted repository package " + target
		}
		if r.reusable() && !t.reusable() {
			return "reusable package depends on product or composition " + target
		}
		if within(name, "core") && within(target, "connector") {
			return "core depends on connector " + target
		}
		if r.Role == protocol && t.Role == protocol && target != name {
			return "protocol depends on another protocol " + target
		}
	}
	if r.reusable() || name == "cmd/other" {
		for _, sdk := range productSDKs {
			if within(dependency, sdk) {
				return "product SDK dependency " + dependency
			}
		}
	}
	return ""
}

func checkImport(name, dependency string, rules map[string]rule) string {
	r, known := rules[name]
	if !known {
		return "package is outside the approved dependency graph"
	}
	if reason := fence(name, dependency, rules); reason != "" {
		return reason
	}
	if !r.composes() && (dependency == "flag" || dependency == "os/signal") {
		return "process configuration belongs to an application: " + dependency
	}
	if target, local := localPackage(dependency); local && !slices.Contains(r.Deps, target) {
		return "unapproved dependency " + target
	}
	return ""
}

func validateRules(rules map[string]rule) []string {
	var violations []string
	for name, r := range rules {
		seen := map[string]bool{}
		var visit func(string)
		visit = func(dependency string) {
			if dependency == name {
				violations = append(violations, "dependency policy contains a cycle at "+name)
			}
			if seen[dependency] {
				return
			}
			seen[dependency] = true
			if reason := fence(name, module+"/"+dependency, rules); reason != "" {
				violations = append(violations, fmt.Sprintf("dependency policy %s: %s", name, reason))
			}
			if name == "cmd/other" && !slices.Contains(cedarPackages, dependency) {
				violations = append(violations, "dependency policy cmd/other: forbidden transitive dependency "+dependency)
			}
			for _, next := range rules[dependency].Deps {
				visit(next)
			}
		}
		for _, dependency := range r.Deps {
			visit(dependency)
		}
	}
	return unique(violations)
}
