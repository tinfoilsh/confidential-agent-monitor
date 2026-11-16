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

// This is an intentional allowlist, never a snapshot regenerated from imports.
// A new edge must remove mechanical wiring without adding a lifecycle owner.
// Product state owns settings and decisions; core.Table owns installed setups;
// connector/worker owns child processes. Helpers do not mirror those owners.
var packages = map[string]rule{
	"core":                          {library, []string{"core/facts"}},
	"core/admission":                {library, nil},
	"core/approval":                 {library, nil},
	"core/attestation":              {library, nil},
	"core/certificates":             {library, nil},
	"core/facts":                    {library, nil},
	"core/identity":                 {library, []string{"core/facts"}},
	"core/sealedlog":                {library, nil},
	"core/transport/netx":           {library, nil},
	"core/transport/noisetransport": {library, nil},
	"core/transport/sshtransport":   {library, nil},
	"connector/browser":             {protocol, []string{"core/facts"}},
	"connector/email":               {protocol, []string{"core/facts"}},
	"connector/mcp":                 {protocol, []string{"core/facts"}},
	"connector/mqtt":                {protocol, []string{"core/facts"}},
	"connector/nats":                {protocol, []string{"core/facts"}},
	"connector/postgres":            {protocol, []string{"core/facts"}},
	"connector/redis":               {protocol, []string{"core/facts"}},
	"connector/session":             {protocol, []string{"core/facts"}},
	"connector/signer":              {protocol, []string{"core/facts"}},
	"connector/tcp":                 {protocol, []string{"core/facts"}},
	"connector/web":                 {protocol, []string{"core/facts"}},
	"connector/catalog":             {library, nil},
	"connector/credential":          {library, nil},
	"connector/slots":               {library, []string{"core/facts"}},
	// Worker shares byte transport only; its gate, grants and launcher stay supplied by the host.
	"connector/worker":       {library, []string{"core/facts", "core/transport/netx"}},
	"ui":                     {product, nil},
	"cmd/perimeter/format":   {product, []string{"core/facts"}},
	"cmd/perimeter/messages": {product, nil},
	"cmd/perimeter/rego":     {product, []string{"core/facts"}},
	"cmd/perimeter/config":   {product, []string{"cmd/perimeter/format", "cmd/perimeter/rego", "core/facts", "connector/catalog"}},
	"cmd/perimeter/sandbox":  {product, []string{"core/facts", "core/transport/sshtransport"}},
	// Only connections composes the protocols; it holds no settings, credentials or state.
	"cmd/perimeter/connections": {product, []string{
		"cmd/perimeter/config", "cmd/perimeter/format", "cmd/perimeter/messages", "cmd/perimeter/sandbox",
		"core", "core/attestation", "core/facts", "core/transport/netx",
		"connector/email", "connector/mcp", "connector/mqtt", "connector/nats", "connector/postgres",
		"connector/redis", "connector/session", "connector/signer", "connector/slots", "connector/tcp",
		"connector/web", "connector/worker",
	}},
	"cmd/perimeter": {application, []string{
		"cmd/perimeter/config", "cmd/perimeter/connections", "cmd/perimeter/format",
		"cmd/perimeter/rego", "cmd/perimeter/sandbox", "ui",
		"core", "core/admission", "core/approval", "core/certificates",
		"core/facts", "core/identity", "core/sealedlog", "core/transport/netx",
		"core/transport/noisetransport", "core/transport/sshtransport",
		"connector/catalog", "connector/credential", "connector/worker",
	}},
	"cmd/other": {application, []string{
		"core", "core/facts", "core/transport/netx", "core/transport/sshtransport", "connector/tcp",
	}},
	"dev/checkcore": {tooling, nil},
	"dev/presets":   {tooling, nil},
	"dev/manual_tests": {tooling, []string{
		"connector/catalog", "connector/credential", "connector/slots", "connector/web",
		"core/certificates", "core/facts", "core/transport/netx",
	}},
}

var modules = []string{
	".", "cmd/other", "cmd/perimeter",
	"connector/browser", "connector/credential", "connector/email", "connector/mcp",
	"connector/mqtt", "connector/nats", "connector/postgres", "connector/redis",
	"connector/session", "connector/slots", "connector/web",
	"dev/manual_tests", "dev/presets",
}

// Independent of the direct-edge allowlist: extending a shared helper must not
// silently expand this alternative composition's dependency closure.
var cedarPackages = []string{
	"cmd/other", "core", "core/facts", "connector/tcp", "core/transport/netx", "core/transport/sshtransport",
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

// These fences also apply to transitive dependencies and cannot be overridden by an edge entry.
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
	// Validate the entire permitted closure, even when an edge is used only in
	// a build-tagged file that go list cannot select on this machine.
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
