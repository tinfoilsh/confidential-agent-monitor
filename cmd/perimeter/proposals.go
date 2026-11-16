package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/config"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/format"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

const (
	maxProposalChanges = 256
	maxPolicyProposals = 32
)

type proposalInput struct {
	Source  string          `json:"source,omitempty"`
	Changes []format.Change `json:"changes,omitempty"`
	Reason  string          `json:"reason"`
	Delete  [][]string      `json:"delete,omitempty"`
}

type proposalReceipt struct {
	ID         string `json:"id"`
	State      string `json:"state"`
	Connection string `json:"connection"`
}

func receipt(r *record) proposalReceipt {
	return proposalReceipt{ID: r.ID, State: r.State, Connection: r.subject().Connection}
}

func (s *state) proposal(st *settings, source string, p facts.Principal, target, reason string, changes []format.Change) (string, json.RawMessage, error) {
	current, ok := s.identities.Lookup(p.Key)
	if !ok || !current.Same(p) {
		return "", nil, errNoAgent
	}
	if _, err := config.ProposalChanges(p, changes, st.capable(current, capabilityPropose)); err != nil {
		return "", nil, err
	}
	candidate, _, _, err := st.Edit(source, changes)
	if err == nil && candidate == source {
		err = errors.New("proposal does not change policy")
	}
	if err != nil {
		return "", nil, err
	}
	raw, err := json.Marshal(requestFacts{Version: config.FactsVersion, Principal: p, Connection: target,
		Service: "policy-proposal", Title: reason, Parameters: map[string]any{},
		Details: map[string]any{"policy": policyDiff{SourceDiff: sourceDiff(source, candidate)}}})
	return candidate, raw, err
}

func (s *state) proposePolicy(ctx context.Context, fingerprint string, input proposalInput) ([]proposalReceipt, error) {
	reason := strings.TrimSpace(input.Reason)
	if reason == "" || len(reason) > maxReason {
		return nil, fmt.Errorf("proposal needs a reason of 1-%d bytes", maxReason)
	}
	if (input.Source != "" || input.Delete != nil) == (input.Changes != nil) {
		return nil, errors.New("proposal requires exactly one of a TOML fragment or structured changes")
	}
	changes := input.Changes
	if changes == nil {
		var err error
		if changes, err = format.FragmentTOML(input.Source); err != nil {
			return nil, err
		}
		for _, path := range input.Delete {
			changes = append(changes, format.Change{Path: path, Delete: true})
		}
	}
	if len(changes) == 0 || len(changes) > maxProposalChanges {
		return nil, fmt.Errorf("proposal must contain 1-%d changes", maxProposalChanges)
	}
	if policyFile != "" {
		return nil, errPolicyFile
	}
	return stable(s, func(base format.Document, before *settings) ([]proposalReceipt, error) {
		p, known := s.identities.Lookup(fingerprint)
		if !known {
			return nil, errNoAgent
		}
		groups, err := config.ProposalChanges(p, changes, before.capable(p, capabilityPropose))
		if err != nil {
			return nil, err
		}
		var proposals []*record
		for _, target := range slices.Sorted(maps.Keys(groups)) {
			candidate, raw, err := s.proposal(before, base.Policy, p, target, reason, groups[target])
			if err == nil {
				_, err = s.prepareSettings(ctx, candidate, everyConnection, nil, before.tls, before.hostKey)
			}
			if err != nil {
				return nil, fmt.Errorf("service %s: %w", target, err)
			}
			proposals = append(proposals, &record{Changes: groups[target], Facts: raw,
				Decision: config.Decision{Requirements: []config.Requirement{{ID: "policy", Message: reason}}}})
		}

		var receipts []proposalReceipt
		var tooMany error
		s.locked(func(h held) {
			var replaced []*record
			pending := len(proposals)
			for r := range h.records.All() {
				if r.State != statePending || r.Changes == nil {
					continue
				}
				f := r.subject()
				if _, again := groups[f.Connection]; again && f.Principal.Same(p) {
					replaced = append(replaced, r)
				} else {
					pending++
				}
			}
			if pending > maxPolicyProposals {
				tooMany = errors.New("too many pending policy proposals")
				return
			}
			for _, r := range replaced {
				h.outdateRecord(r)
			}
			receipts = make([]proposalReceipt, 0, len(proposals))
			for _, proposal := range proposals {
				h.addRecord(proposal).State = statePending
				h.announce(proposal)
				receipts = append(receipts, receipt(proposal))
			}
		})
		return receipts, tooMany
	})
}
