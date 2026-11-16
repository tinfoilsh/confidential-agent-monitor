package web

import (
	"fmt"

	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

// Catalog validates policy vocabulary and projects HTTP operation metadata during parsing.
// A nil preset has no listing; a present empty preset retains its empty listing.
func (p *Preset) Catalog(v facts.Vocabulary) (map[string]facts.OperationSummary, error) {
	if p == nil {
		return nil, nil
	}
	out := map[string]facts.OperationSummary{}
	for id, op := range p.Operations {
		if !v.ValidEffects(op.Effects) || !v.ValidSends(op.Sends) {
			return nil, fmt.Errorf("invalid effects or audience for operation %s", id)
		}
		out[id] = facts.OperationSummary{Action: op.Action, Effects: op.Effects}
	}
	return out, nil
}
