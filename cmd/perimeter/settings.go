package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/pmezard/go-difflib/difflib"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/config"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/connections"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/format"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/credential"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/worker"
	"github.com/tinfoilsh/confidential-agent-monitor/core"
	"github.com/tinfoilsh/confidential-agent-monitor/core/certificates"
	"github.com/tinfoilsh/confidential-agent-monitor/core/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/core/tomledit"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/netx"
	"golang.org/x/crypto/ssh"
)

type settings struct {
	*config.Config
	lib         library
	policy      *config.Program
	catalog     map[string]config.CatalogEntry
	catalogID   string
	authority   *certificates.Authority
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
	catalogs    map[string]format.Catalog
	updates     []string
	remove      []string
}

type settingsWrite struct {
	source      *string
	changes     []tomledit.Change
	derive      func(held) ([]tomledit.Change, error)
	credentials format.Secrets
	check       func(held) error
	saved       *savedAnswer
	lib         library
	catalogs    map[string]format.Catalog
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

var errCredentialChanged = errors.New("credential changed; start again")

const credentialTimeout = 30 * time.Second

func everyConnection(string) bool { return true }

func (s *state) writeSettings(ctx context.Context, w settingsWrite) error {
	s.writes.Lock()
	defer s.writes.Unlock()
	h := held{s}

	s.mu.Lock()
	source, current := s.doc.Policy, s.settings.Load()
	var err error
	if w.derive != nil {
		w.changes, err = w.derive(h)
	}
	if err == nil && policyFile != "" && (w.source != nil || len(w.changes) != 0) {
		err = errPolicyFile
	}
	if err == nil {
		err = w.checked(h)
	}
	s.mu.Unlock()
	if err != nil {
		return err
	}

	before := source
	if w.source != nil {
		source = *w.source
	}
	lib := current.lib
	if w.lib != nil {
		lib = w.lib
	}
	source, rebuild, renamed, err := current.Edit(source, w.changes, lib)
	if err != nil {
		return err
	}
	plan, err := s.prepareSettings(ctx, lib, source, rebuild, w.credentials, current.authority, current.hostKey)
	if err != nil {
		return err
	}
	plan.renamed, plan.catalogs = renamed, w.catalogs

	s.mu.Lock()
	if err = w.checked(h); err == nil {
		err = h.commitSettings(ctx, plan, w.saved)
	}
	if source != before || len(w.credentials) != 0 {
		h.recordAdmin(ctx, "Change settings", map[string]any{"policy": policyDiff{SourceDiff: sourceDiff(before, source)}, "credentials": slices.Sorted(maps.Keys(w.credentials))}, err)
	}
	s.mu.Unlock()
	if err == nil {
		s.table.Start()
	}
	return err
}

func (s *state) prepareSettings(ctx context.Context, lib library, source string, rebuild func(connection string) bool, credentials format.Secrets, authority *certificates.Authority, hostKey ssh.Signer) (*settingsPlan, error) {
	cfg, err := config.Load(source, lib)
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

	next := &settings{Config: cfg, lib: lib, policy: program, authority: authority, hostKey: hostKey, publicScope: map[string][]string{}, connections: map[string]*installed{}}
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

	if next.catalog, next.catalogID, err = config.CatalogEntries(cfg, operations); err != nil {
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
	if plan.catalogs != nil {
		next.Catalogs = plan.catalogs
	}
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
			if v, err = credential.Parse(next.Credentials.Get(id), credential.Options{Files: secretFiles, Client: client, Timeout: credentialTimeout, Save: func(ctx context.Context, before, after json.RawMessage) error {
				return s.replaceValue(ctx, id, v, before, after)
			}}); err != nil {
				return fmt.Errorf("credential %s/%s: %w", connection, name, err)
			}
			c.secrets[name], c.placeholders[name] = v, connections.Placeholder(next.Keys, id)
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
		s.table.Stage(name, c.Network, c.Claim, s.opener(plan.next, c))
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
	source, _, _, err := before.Edit(source, nil, before.lib)
	if err != nil {
		return nil, err
	}
	plan, err := s.prepareSettings(ctx, before.lib, source, everyConnection, nil, before.authority, before.hostKey)
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

func guardedDialer(allowed []netip.Prefix, network string) *net.Dialer {
	return &net.Dialer{Timeout: connections.DialTimeout, Control: netx.Guard(allowed, network)}
}

func (st *settings) client() *http.Client {
	return &http.Client{Transport: connections.Identified{RoundTripper: netx.Transport(guardedDialer(st.AllowNetworks, "tcp").DialContext)}, CheckRedirect: netx.RefuseRedirects}
}

func (s *state) opener(st *settings, c *installed) core.Open {
	grants := worker.Grants{Dial: s.routes.RouteDial(c.Hosts, s.identities.Keys, guardedDialer(st.AllowNetworks, c.Network).DialContext), Secrets: map[string]worker.Secret{},
		Certificate: func(name string) (*tls.Certificate, error) {
			return st.authority.Issue(name, leafLifetime, leafBackdate)
		}}
	if c.HostKey {
		grants.HostKey = st.hostKey
	}
	for name, value := range c.secrets {
		grants.Secrets[name] = worker.Secret{Configured: value.Configured(), OAuth: value.OAuth(), Placeholder: c.placeholders[name], Value: value.Value}
	}
	if workers == nil {
		return func(ctx context.Context) (connector.Instance, error) { return c.Open(ctx, grants.Host()) }
	}
	return func(ctx context.Context) (connector.Instance, error) {
		data, err := json.Marshal(c.ConnectionSpec)
		if err != nil {
			return connector.Instance{}, err
		}
		p, err := worker.Launch(ctx, workers.Start, data, grants, workerLimits)
		if err != nil {
			return connector.Instance{}, err
		}
		return p.Instance(), nil
	}
}

func (s held) unchanged(id format.SecretID, value *credential.Value, before json.RawMessage) bool {
	c := s.settings.Load().connections[id.Connection]
	return c != nil && c.secrets[id.Name] == value && bytes.Equal(s.doc.Credentials.Get(id), before)
}

func (s *state) replaceValue(ctx context.Context, id format.SecretID, value *credential.Value, before, after json.RawMessage) error {
	err := errCredentialChanged
	s.locked(func(h held) {
		if h.unchanged(id, value, before) {
			next := h.doc
			next.Credentials = next.Credentials.Clone()
			next.Credentials.Set(id, bytes.Clone(after))
			err = h.commit(ctx, next)
		}
	})
	return err
}

func (s *state) signInCredential(connection, name string) (json.RawMessage, func(context.Context, json.RawMessage) error, error) {
	id := format.SecretID{Connection: connection, Name: name}
	var value *credential.Value
	var before json.RawMessage
	s.locked(func(h held) {
		if c := s.settings.Load().connections[connection]; c != nil {
			value = c.secrets[name]
		}
		before = bytes.Clone(h.doc.Credentials.Get(id))
	})
	if value == nil {
		return nil, nil, errors.New("credential does not exist")
	}
	return before, func(ctx context.Context, raw json.RawMessage) error {
		return s.writeSettings(ctx, settingsWrite{credentials: format.Secrets{connection: {name: raw}}, check: func(h held) error {
			if !h.unchanged(id, value, before) {
				return errCredentialChanged
			}
			return nil
		}})
	}, nil
}

func (s *state) restoreDevice(ctx context.Context, public string) error {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(public))
	if err != nil {
		return fmt.Errorf("device public key: %w", err)
	}
	public = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	digest := sha256.Sum256([]byte(public))
	return s.enroll(ctx, map[string]config.Enrollment{fmt.Sprintf("device-%x", digest[:8]): {Key: public, Routes: true, Restore: true}})
}

func (s *state) enroll(ctx context.Context, identities map[string]config.Enrollment) error {
	return s.writeSettings(ctx, settingsWrite{derive: func(h held) ([]tomledit.Change, error) {
		return h.settings.Load().Enroll(identities, h.doc.Enrolled, identityAttributes)
	}})
}
