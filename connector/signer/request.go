package signer

import (
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/facts"
)

type Request struct {
	Agent     string `json:"agent"`
	Key       string `json:"key,omitempty"`
	Purpose   string `json:"purpose,omitempty"`
	Namespace string `json:"namespace,omitempty"`
	User      string `json:"user,omitempty"`
	Hash      string `json:"hash,omitempty"`
	Op        string `json:"op,omitempty"`
}

// Signing requests remain unknown until the owner supplies operation semantics.
func (r *Request) Describe(c connector.Context) (facts.Facts, connector.Approval, error) {
	return facts.Facts{Details: map[string]any{"sign": r}}, connector.Approval{}, nil
}
