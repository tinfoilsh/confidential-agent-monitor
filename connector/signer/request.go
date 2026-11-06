package signer

import (
	"github.com/tinfoilsh/monitor/facts"
)

// Signing requests remain unknown until the owner supplies operation semantics.
func (r *SignFacts) Describe() facts.Facts {
	return facts.Facts{Details: Details{Sign: r}}
}
