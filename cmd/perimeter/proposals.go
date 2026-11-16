package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"
	"strings"

	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/config"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/format"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"golang.org/x/crypto/ssh"
)

// Policy proposals and enrollment.

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
	return proposalReceipt{ID: r.ID, State: r.State, Connection: summarize(r).Facts.Connection}
}

// proposal renders p's changes to one connection against source for review under st. It
// fails when they no longer apply, change nothing, or p may not propose them.
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

// proposePolicy publishes one pending record per connection, or none if any fails.
// The owner answers it like a request; approval writes its changes.
func (s *state) proposePolicy(ctx context.Context, key string, input proposalInput) ([]proposalReceipt, error) {
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
		p, known := s.identities.Lookup(key)
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
				_, err = s.prepareSettings(ctx, candidate, everyConnection, nil, nil, before.tls, before.hostKey)
			}
			if err != nil {
				return nil, fmt.Errorf("service %s: %w", target, err)
			}
			proposals = append(proposals, &record{Changes: groups[target], Facts: raw,
				Decision: Decision{Requirements: []config.Requirement{{ID: "policy", Message: reason}}}})
		}

		var receipts []proposalReceipt
		s.locked(func() {
			// A principal has one pending proposal per connection; a new one replaces it.
			var replaced []*record
			pending := len(proposals)
			for r := range s.records.All() {
				if r.State != statePending || r.Changes == nil {
					continue
				}
				f := summarize(r).Facts
				if _, again := groups[f.Connection]; again && f.Principal.Same(p) {
					replaced = append(replaced, r)
				} else {
					pending++
				}
			}
			if pending > maxPolicyProposals {
				err = errors.New("too many pending policy proposals")
				return
			}
			for _, r := range replaced {
				s.outdateRecord(r)
			}
			receipts = make([]proposalReceipt, 0, len(proposals))
			for _, proposal := range proposals {
				s.addRecord(proposal).State = statePending
				s.announce(proposal)
				receipts = append(receipts, receipt(proposal))
			}
		})
		return receipts, err
	})
}

type identityEnrollment struct {
	Key      string `json:"key"`
	Operator bool   `json:"routes"`
	Restore  bool   `json:"restore"`
	// Attributes are the enrollment's other keys.
	Attributes map[string]json.RawMessage `json:",embed"`
}

// enrollmentChanges adds new identities; a revoked key or route access returns only when restored.
// The caller holds s.mu.
func (s *state) enrollmentChanges(input map[string]identityEnrollment) ([]format.Change, error) {
	var changes []format.Change
	st := s.settings.Load()
	for name, id := range input {
		fingerprint, err := config.KeyFingerprint(id.Key)
		if err != nil {
			return nil, err
		}
		attributes := map[string]any{}
		for key, raw := range id.Attributes {
			if identityAttributes[key] == nil {
				return nil, fmt.Errorf("an enrollment has no field %s", key)
			}
			if attributes[key], err = facts.JSON[any](raw); err != nil {
				return nil, err
			}
		}
		maps.DeleteFunc(attributes, func(_ string, value any) bool { return value == nil })
		if principal, ok := st.Config.Principal(fingerprint); ok {
			existing := st.Identities[principal.Name]
			if id.Operator && !existing.Operator {
				if !id.Restore {
					return nil, errors.New("device route access was revoked")
				}
				changes = append(changes, format.Change{Path: []string{"identities", principal.Name, "routes"}, Value: true})
			}
			for key, value := range attributes {
				if before, _ := facts.JSON[any](existing.Attributes[key]); !reflect.DeepEqual(value, before) {
					changes = append(changes, format.Change{Path: []string{"identities", principal.Name, key}, Value: value})
				}
			}
			continue
		}
		if s.doc.Enrolled[fingerprint] && !id.Restore {
			return nil, errors.New("identity was revoked; restore access explicitly in the Perimeter")
		}
		if _, exists := st.Config.Identities[name]; exists {
			return nil, errors.New("identity name belongs to another key")
		}
		value := map[string]any{"key": id.Key, "routes": id.Operator}
		maps.Copy(value, attributes)
		changes = append(changes, format.Change{Path: []string{"identities", name}, Value: value})
	}
	return changes, nil
}

// restoreDevice lets owner unlock restore its device; ordinary enrollment still honors revocation.
// Authentication and unlocking precede this independent settings write.
func (s *state) restoreDevice(ctx context.Context, public string) error {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(public))
	if err != nil {
		return fmt.Errorf("device public key: %w", err)
	}
	public = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	digest := sha256.Sum256([]byte(public))
	return s.enroll(ctx, map[string]identityEnrollment{fmt.Sprintf("device-%x", digest[:8]): {Key: public, Operator: true, Restore: true}})
}

func (s *state) enroll(ctx context.Context, identities map[string]identityEnrollment) error {
	return s.writeSettings(ctx, settingsWrite{derive: func() ([]format.Change, error) { return s.enrollmentChanges(identities) }})
}
