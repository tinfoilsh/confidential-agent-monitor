package signer

import (
	"github.com/tinfoilsh/monitor/facts"
)

type Request SignFacts

// Signing requests remain unknown until the owner supplies operation semantics.
func (r *Request) Describe() (facts.Facts, error) {
	return facts.Facts{Details: Details{Sign: (*SignFacts)(r)}}, nil
}
