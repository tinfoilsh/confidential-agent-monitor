package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"

	"github.com/pmezard/go-difflib/difflib"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/config"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/connections"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/format"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/rego"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/credential"
	"github.com/tinfoilsh/confidential-agent-monitor/core"
	"golang.org/x/crypto/ssh"
)

// Settings snapshots: prepared outside s.mu, committed under it, and delivered to connectors
// after it. Stored maps and snapshots are immutable once published.

// settings is an immutable snapshot of the saved settings, published as a whole.
// Mutable connector availability and stream authority belong to the table and admissions.
type settings struct {
	*config.Config
	policy      *rego.Program
	catalog     map[string]config.CatalogEntry
	catalogID   string
	tls         *tls.Config
	hostKey     ssh.Signer
	publicScope map[string][]string
	connections map[string]*installed
}

// installed is a connection's parsed setup with the credentials bound to it at commit, and the
// public placeholders agents send in their place.
type installed struct {
	*connections.Setup
	secrets      map[string]*credential.Value
	placeholders map[string]string
}

type connectionPlan struct {
	config.ConnectionSpec
	*installed
}

// settingsPlan contains parsed settings, never candidate runtime instances.
type settingsPlan struct {
	next        *settings
	source      string
	credentials format.Secrets
	renamed     map[string]string
	updates     []connectionPlan
	remove      []string
}

// settingsWrite replaces the policy source, or edits it with changes, and stages
// credentials, nil clearing one. check runs under s.mu before validation and again
// before persistence. A saved approval is answered atomically with the durable change.
// derive supplies changes under s.writes and s.mu, before the first check.
type settingsWrite struct {
	source      *string
	changes     []format.Change
	derive      func() ([]format.Change, error)
	credentials format.Secrets
	check       func() error
	saved       *savedAnswer
}

func (w settingsWrite) checked() error {
	if w.check == nil {
		return nil
	}
	return w.check()
}

var (
	errPolicyConflict = httpError{errors.New("policy changed; reload it and review a new diff before applying"), http.StatusConflict}
	errPolicyFile     = refused("the policy is loaded from a file; change it there")
)

func everyConnection(string) bool { return true }

// prepareSettings validates source and parses the connector setups to rebuild
// under s.writes, without s.mu. It creates no runtime instances. Credential refreshes
// can still commit while validation runs.
func (s *state) prepareSettings(ctx context.Context, source string, rebuild func(connection string) bool, renamed map[string]string, credentials format.Secrets, tlsConfig *tls.Config, hostKey ssh.Signer) (*settingsPlan, error) {
	cfg, err := config.Load(source, presets)
	if err != nil {
		return nil, err
	}
	for name, id := range cfg.Identities {
		for key, value := range id.Attributes {
			validate := identityAttributes[key]
			if validate == nil {
				return nil, fmt.Errorf("identity %s has no field %s", name, key)
			}
			if err := validate(value); err != nil {
				return nil, fmt.Errorf("identity %s %s: %w", name, key, err)
			}
		}
	}
	program, err := config.PreparePolicy(ctx, cfg, basePolicy)
	if err != nil {
		return nil, err
	}
	next := &settings{Config: cfg, policy: program, tls: tlsConfig, hostKey: hostKey, publicScope: map[string][]string{}, connections: map[string]*installed{}}
	operations := map[string]map[string]config.OperationSummary{}
	plan := &settingsPlan{next: next, source: source, credentials: credentials, renamed: renamed}
	var current map[string]*installed
	if st := s.settings.Load(); st != nil {
		current = st.connections
	}
	status := s.table.Connections()
	for _, name := range slices.Sorted(maps.Keys(next.Connections)) {
		spec, err := next.Spec(name)
		if err != nil {
			return nil, err
		}
		next.publicScope[spec.Name] = spec.PublicScope
		if !connections.Registered(spec.Protocol, development) {
			return nil, fmt.Errorf("service %s has unknown kind %s", spec.Name, spec.Protocol)
		}
		c, exists := current[spec.Name]
		if exists && c.Protocol != spec.Protocol {
			plan.remove = append(plan.remove, spec.Name)
		}
		if exists && c.Protocol == spec.Protocol && !rebuild(spec.Name) && len(credentials[spec.Name]) == 0 {
			next.connections[spec.Name] = c
			operations[next.Connections[spec.Name].Preset] = c.Operations
			if status[spec.Name].State != core.Ready {
				plan.updates = append(plan.updates, connectionPlan{spec, c})
			}
			continue
		}
		p, err := connections.Parse(spec)
		if err != nil {
			return nil, fmt.Errorf("service %s: %w", spec.Name, err)
		}
		operations[next.Connections[spec.Name].Preset] = p.Operations
		handles := map[string]*credential.Value{}
		for _, name := range p.SecretNames {
			handles[name] = nil
		}
		for name, raw := range credentials[spec.Name] {
			if _, uses := handles[name]; raw != nil && !uses {
				return nil, fmt.Errorf("service %s does not use credential %s", spec.Name, name)
			}
		}
		c = &installed{Setup: p, secrets: handles, placeholders: map[string]string{}}
		next.connections[spec.Name] = c
		plan.updates = append(plan.updates, connectionPlan{spec, c})
	}
	if next.catalog, next.catalogID, err = config.CatalogEntries(cfg, presetDefaults, operations); err != nil {
		return nil, err
	}
	for name := range credentials {
		if _, present := next.Connections[name]; !present {
			return nil, fmt.Errorf("service %s does not exist", name)
		}
	}
	for name := range current {
		if _, present := next.Connections[name]; !present {
			plan.remove = append(plan.remove, name)
		}
	}
	return plan, nil
}

// commitSettings runs under s.writes and s.mu: rebase the planned changes, persist them,
// publish the settings and revoke lost authority. Changed connectors remain
// unavailable until installation. A saved approval is answered after persistence
// and before general settings invalidation.
func (s *state) commitSettings(ctx context.Context, plan *settingsPlan, saved *savedAnswer) (err error) {
	current := s.doc
	next := current
	next.Policy = plan.source
	next.Credentials = next.Credentials.Clone()
	for to, from := range plan.renamed {
		if values, ok := current.Credentials[from]; ok {
			next.Credentials[to] = maps.Clone(values)
		}
	}
	for connection, values := range plan.credentials {
		for name, raw := range values {
			next.Credentials.Set(format.SecretID{Connection: connection, Name: name}, raw)
		}
	}
	maps.DeleteFunc(next.Credentials, func(connection string, _ map[string]json.RawMessage) bool {
		_, ok := plan.next.Connections[connection]
		return !ok
	})
	// Bind new handles to the latest durable record exactly once, before commit.
	// This is pure credential validation; it takes no Value lock or network call.
	client := plan.next.client()
	for _, update := range plan.updates {
		for name, value := range update.secrets {
			if value != nil {
				continue
			}
			id := format.SecretID{Connection: update.Name, Name: name}
			var v *credential.Value
			if v, err = bindCredential(next.Credentials.Get(id), client, func(ctx context.Context, before, after json.RawMessage) error {
				return s.replaceValue(ctx, id, v, before, after)
			}); err != nil {
				return fmt.Errorf("credential %s/%s: %w", update.Name, name, err)
			}
			update.secrets[name], update.placeholders[name] = v, placeholder(next.Keys, id)
		}
	}
	next.Enrolled = maps.Clone(next.Enrolled)
	if next.Enrolled == nil {
		next.Enrolled = map[string]bool{}
	}
	for key := range plan.next.Principals {
		next.Enrolled[key] = true
	}
	next.Revision++
	// Persist before publishing authority.
	if err := s.commit(ctx, next); err != nil {
		return err
	}
	if saved != nil {
		s.saved(saved.record, saved.answer)
	}
	for _, name := range plan.remove {
		s.table.Remove(name)
	}
	for _, update := range plan.updates {
		s.table.Stage(update.Name, update.Claim, update.PerMessage, s.opener(plan.next, update.installed))
	}
	previous := s.settings.Swap(plan.next)
	if previous != nil {
		for key := range previous.Principals {
			if _, kept := plan.next.Principals[key]; !kept {
				s.identities.Unregister(key)
			}
		}
	}
	for key := range plan.next.Principals {
		p, _ := plan.next.Config.Principal(key)
		s.identities.Register(key, p, true)
	}
	for r := range s.records.All() {
		if r.State != statePending || r.Changes == nil {
			continue
		}
		f := summarize(r).Facts
		if _, raw, err := s.proposal(plan.next, plan.source, f.Principal, f.Connection, r.Requirements[0].Message, r.Changes); err == nil {
			r.Facts = raw
		} else {
			s.outdateRecord(r)
		}
	}
	s.recheckAll()
	return nil
}

// reviewed checks, under s.mu, that an owner write naming a revision was made against current settings.
func (s *state) reviewed(revision *uint64) func() error {
	return func() error {
		if revision != nil && *revision != s.doc.Revision {
			return errPolicyConflict
		}
		return nil
	}
}

// policyDiff compares the owner source and its expanded settings.
type policyDiff struct {
	SourceDiff    string `json:"source_diff"`
	EffectiveDiff string `json:"effective_diff"`
}

func sourceDiff(a, b string) string {
	text, _ := difflib.GetUnifiedDiffString(difflib.UnifiedDiff{A: difflib.SplitLines(a), B: difflib.SplitLines(b), FromFile: "active/policy.toml", ToFile: "proposed/policy.toml", Context: 3})
	return text
}

func (s *state) previewPolicy(ctx context.Context, base format.Document, before *settings, source string) (*policyDiff, error) {
	source, _, _, err := before.Edit(source, nil)
	if err != nil {
		return nil, err
	}
	plan, err := s.prepareSettings(ctx, source, everyConnection, nil, nil, before.tls, before.hostKey)
	if err != nil {
		return nil, err
	}
	beforeText, err := before.Config.Effective()
	if err != nil {
		return nil, err
	}
	afterText, err := plan.next.Config.Effective()
	if err != nil {
		return nil, err
	}
	return &policyDiff{SourceDiff: sourceDiff(base.Policy, source), EffectiveDiff: sourceDiff(beforeText, afterText)}, nil
}
