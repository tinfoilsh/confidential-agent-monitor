package authz

import "github.com/tinfoilsh/confidential-agent-monitor/core/facts"

// Requirement IDs bind approval waivers; messages explain them without granting authority.
type Requirement struct {
	ID      string `json:"id"`
	Message string `json:"message"`
}

type Decision struct {
	Deny         []string      `json:"deny"`
	Requirements []Requirement `json:"requirements"`
	Sends        string        `json:"sends"`
	Next         facts.Label   `json:"next"`
}
