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

type installed struct {
	*connections.Setup
	secrets      map[string]*credential.Value
	placeholders map[string]string
}

type settingsPlan struct {
	next        *settings
	source      string
	credentials format.Secrets
	renamed     map[string]string
	updates     []string
	remove      []string
}

type settingsWrite struct {
	source      *string
	changes     []format.Change
	derive      func(held) ([]format.Change, error)
	credentials format.Secrets
	check       func(held) error
	saved       *savedAnswer
}

func (w settingsWrite) checked(h held) error {
	if w.check == nil {
		return nil
	}
	return w.check(h)
}

var (
	errPolicyConflict = httpError{errors.New("policy changed; reload it and review a new diff before applying"), http.StatusConflict}
	errPolicyFile     = httpError{errors.New("the policy is loaded from a file; change it there"), http.StatusForbidden}
)

func everyConnection(string) bool { return true }

func (s *state) prepareSettings(ctx context.Context, source string, rebuild func(connection string) bool, credentials format.Secrets, tlsConfig *tls.Config, hostKey ssh.Signer) (*settingsPlan, error) {
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
	plan := &settingsPlan{next: next, source: source, credentials: credentials}
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
		next.publicScope[name] = spec.PublicScope
		if !connections.Registered(spec.Protocol, development) {
			return nil, fmt.Errorf("service %s has unknown kind %s", name, spec.Protocol)
		}
		c, exists := current[name]
		if exists && c.Protocol != spec.Protocol {
			plan.remove = append(plan.remove, name)
		}
		if exists && c.Protocol == spec.Protocol && !rebuild(name) && len(credentials[name]) == 0 {
			next.connections[name] = c
			operations[next.Connections[name].Preset] = c.Operations
			if status[name].State != core.Ready {
				plan.updates = append(plan.updates, name)
			}
			continue
		}
		p, err := connections.Parse(spec)
		if err != nil {
			return nil, fmt.Errorf("service %s: %w", name, err)
		}
		operations[next.Connections[name].Preset] = p.Operations
		handles := map[string]*credential.Value{}
		for _, secret := range p.SecretNames {
			handles[secret] = nil
		}
		for secret, raw := range credentials[name] {
			if _, uses := handles[secret]; raw != nil && !uses {
				return nil, fmt.Errorf("service %s does not use credential %s", name, secret)
			}
		}
		next.connections[name] = &installed{Setup: p, secrets: handles, placeholders: map[string]string{}}
		plan.updates = append(plan.updates, name)
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

func (s held) commitSettings(ctx context.Context, plan *settingsPlan, saved *savedAnswer) (err error) {
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
	client := plan.next.client()
	for _, connection := range plan.updates {
		c := plan.next.connections[connection]
		for name, value := range c.secrets {
			if value != nil {
				continue
			}
			id := format.SecretID{Connection: connection, Name: name}
			var v *credential.Value
			if v, err = bindCredential(next.Credentials.Get(id), client, func(ctx context.Context, before, after json.RawMessage) error {
				return s.replaceValue(ctx, id, v, before, after)
			}); err != nil {
				return fmt.Errorf("credential %s/%s: %w", connection, name, err)
			}
			c.secrets[name], c.placeholders[name] = v, placeholder(next.Keys, id)
		}
	}
	next.Enrolled = maps.Clone(next.Enrolled)
	if next.Enrolled == nil {
		next.Enrolled = map[string]bool{}
	}
	for fingerprint := range plan.next.Principals {
		next.Enrolled[fingerprint] = true
	}
	next.Revision++
	if err := s.commit(ctx, next); err != nil {
		return err
	}

	// An answered proposal must leave pending before the loop below would outdate it.
	if saved != nil {
		s.saved(saved.record, saved.answer)
	}
	for _, name := range plan.remove {
		s.table.Remove(name)
	}
	for _, name := range plan.updates {
		c := plan.next.connections[name]
		s.table.Stage(name, c.Claim, c.PerMessage, s.opener(plan.next, c))
	}
	previous := s.settings.Swap(plan.next)
	if previous != nil {
		for fingerprint := range previous.Principals {
			if _, kept := plan.next.Principals[fingerprint]; !kept {
				s.identities.Unregister(fingerprint)
			}
		}
	}
	for fingerprint := range plan.next.Principals {
		p, _ := plan.next.Config.Principal(fingerprint)
		s.identities.Register(fingerprint, p, true)
	}
	for r := range s.records.All() {
		if r.State != statePending || r.Changes == nil {
			continue
		}
		f := r.subject()
		if _, raw, err := s.proposal(plan.next, plan.source, f.Principal, f.Connection, r.Requirements[0].Message, r.Changes); err == nil {
			r.Facts = raw
		} else {
			s.outdateRecord(r)
		}
	}
	s.recheckAll()
	return nil
}

func reviewed(revision *uint64) func(held) error {
	return func(h held) error {
		if revision != nil && *revision != h.doc.Revision {
			return errPolicyConflict
		}
		return nil
	}
}

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
	plan, err := s.prepareSettings(ctx, source, everyConnection, nil, before.tls, before.hostKey)
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
