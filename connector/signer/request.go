package signer

import (
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

func (r *SignFacts) Describe() facts.Observation {
	return facts.Observation{Details: Details{Sign: r}}
}
