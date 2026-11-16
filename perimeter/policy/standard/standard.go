// Package standard supplies Perimeter's shipped policy and vocabulary.
package standard

import (
	_ "embed"

	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/policy"
)

//go:embed lib.rego
var source string

// Vocabulary returns independent default tables for one host.
func Vocabulary() facts.Vocabulary {
	// obligations is shared by preset validation, request descriptions, policy, and UI.
	effects := map[string]facts.Obligations{
		"read":     {},
		"session":  {},
		"write":    {Change: true, Trust: true},
		"generate": {Change: true, Trust: true},
		"delete":   {Change: true, Trust: true},
		"admin":    {Change: true, Trust: true},
		"execute":  {Change: true, Trust: true},
		"send":     {Change: true, Trust: true, Discloses: true},
		"share":    {Change: true, Trust: true, Discloses: true},
		"publish":  {Change: true, Trust: true, Ask: true, Discloses: true},
		"pay":      {Change: true, Trust: true, Ask: true},
	}

	return facts.Vocabulary{Audiences: []string{"me", "team", "anyone"}, Trusts: []string{"untrusted", "trusted"}, Effects: effects, Initial: facts.Label{Trust: "trusted", Audience: "anyone"}}
}

func Library() policy.Library {
	return policy.Library{
		Modules:  map[string]string{"perimeter/lib.rego": source},
		Queries:  map[string]string{"decision": "data.perimeter.decision", "admin": "data.perimeter.admin_deny", "capable": "data.perimeter.capable"},
		Reserved: []string{"perimeter", "lattices", "levels"}, BasePackage: "data.perimeter.base",
	}
}
