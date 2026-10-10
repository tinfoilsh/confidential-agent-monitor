package sentinel

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/open-policy-agent/opa/v1/rego"
)

const denyQuery = "data.sentinel.deny"

type Policy struct{ query rego.PreparedEvalQuery }

// NewPolicy compiles the modules given as rego options, such as rego.Load or rego.Module.
func NewPolicy(ctx context.Context, modules ...func(*rego.Rego)) (*Policy, error) {
	query, err := rego.New(append(modules, rego.Query(denyQuery))...).PrepareForEval(ctx)
	if err != nil {
		return nil, err
	}
	policy := &Policy{query}
	if _, err := policy.Deny(ctx, map[string]any{}); err != nil {
		return nil, err
	}
	return policy, nil
}

// Deny returns the message of every deny rule that fires for the input.
func (p *Policy) Deny(ctx context.Context, input map[string]any) ([]string, error) {
	rs, err := p.query.Eval(ctx, rego.EvalInput(input))
	if err != nil {
		return nil, err
	}
	if len(rs) == 0 {
		return nil, fmt.Errorf("%s is undefined; policies must be in package sentinel", denyQuery)
	}
	set, ok := rs[0].Expressions[0].Value.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be a set", denyQuery)
	}
	var msgs []string
	for _, v := range set {
		msgs = append(msgs, fmt.Sprint(v))
	}
	return msgs, nil
}

// Gate screens the calls to server's tools, with input {"server", "tool", "arguments"}.
func (p *Policy) Gate(server string) Gate {
	return func(ctx context.Context, tool *mcp.Tool, raw json.RawMessage) error {
		var args any
		if len(raw) > 0 {
			if err := json.Unmarshal(raw, &args); err != nil {
				return err
			}
		}
		denied, err := p.Deny(ctx, map[string]any{"server": server, "tool": tool.Name, "arguments": args})
		if err != nil || len(denied) == 0 {
			return err
		}
		return errors.New(strings.Join(denied, "; "))
	}
}
