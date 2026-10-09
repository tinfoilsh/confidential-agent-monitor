package signer

import (
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/facts"
)

type Request facts.Sign

// Signing requests remain unknown until the owner supplies operation semantics.
func (r *Request) Describe(c connector.Context) (facts.Facts, error) {
	return facts.Facts{Details: facts.Details{Sign: (*facts.Sign)(r)}}, nil
}
