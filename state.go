package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"slices"
	"sync"
	"sync/atomic"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/tinfoilsh/monitor/connector"
	"gocloud.dev/blob"
	"gocloud.dev/gcerrors"
	"golang.org/x/crypto/ssh"
)

const ownerKeyBytes = 32

var errOwner = errors.New("invalid owner secret")

// sealed is the document encrypted in storage. The monitor owns it under mu.
type sealed struct {
	Generation uint64             `json:"generation"`
	Keys       keyMaterial        `json:"keys"`
	Labels     map[string]label   `json:"labels"`
	Mailboxes  map[string]mailbox `json:"mailboxes,omitempty"`
	Config     json.RawMessage    `json:"config"`
}

type state struct {
	cfg             *config
	connections     map[string]*connection
	principals      map[string]principal
	decision        rego.PreparedEvalQuery
	messageDecision rego.PreparedEvalQuery
	connector.Env
}

type monitor struct {
	live        atomic.Pointer[state]
	mu          sync.Mutex
	doc         sealed
	labelsDirty bool // A failed write must not let a later request skip label persistence.
	owner       []byte
	store       *blob.Bucket
	object      string
	listen      string
	running     map[string]*connection
	// flow serializes policy decisions; mu protects all document reads and writes.
	flow    sync.Mutex
	streams map[string]map[*connector.Stream]struct{}
	records records
	// Only with a file:// bucket: corpus receives every request to a preset's account, and identities may profile.
	dev    bool
	corpus *json.Encoder
	// signIns holds the finish of each started sign-in, keyed by its state.
	signIns map[string]func(context.Context, string) (*state, error)
}

type principal struct {
	Key      string            `json:"key"`
	Name     string            `json:"name"`
	Accounts map[string]access `json:"-"`
	Rules    []rule            `json:"-"`
	Messages *messageAccess    `json:"-"`
	Profile  bool              `json:"-"`
}

func (p principal) reaches(account string) bool {
	level := p.Accounts[account].Level
	return level != "" && level != "off"
}

func newAEAD(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCMWithRandomNonce(block)
}

// The first unlock of an empty store makes its secret the owner's.
func (m *monitor) unlock(ctx context.Context, key []byte, minimum uint64) (*state, error) {
	if s := m.live.Load(); s != nil {
		if subtle.ConstantTimeCompare(key, m.owner) != 1 {
			return nil, errOwner
		}
		return s, nil
	}
	aead, err := newAEAD(key)
	if err != nil {
		return nil, err
	}
	sl := sealed{Config: json.RawMessage("{}")}
	raw, err := m.store.ReadAll(ctx, m.object)
	if gcerrors.Code(err) != gcerrors.NotFound || minimum != 0 {
		if err != nil {
			return nil, err
		}
		plain, err := aead.Open(nil, nil, raw, nil)
		if err != nil {
			return nil, errOwner
		}
		if err := json.Unmarshal(plain, &sl); err != nil {
			return nil, err
		}
	}
	if sl.Generation < minimum {
		return nil, fmt.Errorf("stored generation %d is older than %d", sl.Generation, minimum)
	}
	var migrated bool
	if sl.Config, migrated, err = migratePresets(sl.Config); err != nil {
		return nil, err
	}
	fresh := sl.Keys == keyMaterial{}
	var env connector.Env
	if env.TLS, err = loadCA(&sl.Keys); err != nil {
		return nil, err
	}
	if env.HostKey, err = loadHostKey(&sl.Keys); err != nil {
		return nil, err
	}
	if fresh || migrated {
		sl.Generation++
	}
	if sl.Labels == nil {
		sl.Labels = map[string]label{}
	}
	s, err := m.build(ctx, sl, env, nil)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", m.listen)
	if err == nil && (fresh || migrated) {
		if err = m.persist(ctx, sl, key); err != nil {
			ln.Close()
		}
	}
	if err != nil {
		return nil, err
	}
	m.owner = key
	m.doc = sl
	m.apply(s)
	m.live.Store(s)
	go m.serveSSH(ln)
	return s, nil
}

func (m *monitor) patch(ctx context.Context, patch []byte) (*state, error) {
	patch = bytes.TrimSpace(patch)
	if len(patch) == 0 || patch[0] != '{' {
		return nil, errors.New("configuration patch must be an object")
	}
	config, err := jsonpatch.MergePatch(m.doc.Config, patch)
	if err != nil {
		return nil, err
	}
	if config, _, err = migratePresets(config); err != nil {
		return nil, err
	}
	old := m.live.Load()
	next := m.doc
	next.Config = config
	next.Generation++
	s, err := m.build(ctx, next, old.Env, old)
	if err != nil {
		return nil, err
	}
	next.Labels = maps.Clone(m.doc.Labels)
	maps.DeleteFunc(next.Labels, func(key string, _ label) bool { _, ok := s.principals[key]; return !ok })
	next.Mailboxes = maps.Clone(m.doc.Mailboxes)
	maps.DeleteFunc(next.Mailboxes, func(_ string, box mailbox) bool { return !s.keepsMailbox(box) })
	if err := m.commitLocked(ctx, next); err != nil {
		return nil, err
	}
	for key := range m.streams {
		if _, exists := s.principals[key]; !exists || s.cfg.Lattices != old.cfg.Lattices {
			m.retireStreamsLocked(key, nil)
		}
	}
	m.apply(s)
	m.live.Store(s)
	return s, nil
}

func configValue(raw json.RawMessage, path []string) json.RawMessage {
	for _, key := range path {
		var object map[string]json.RawMessage
		if json.Unmarshal(raw, &object) != nil {
			return nil
		}
		raw = object[key]
	}
	return raw
}

// valuePatch addresses a value through the same merge-patch API as other edits.
func valuePatch(path []string, value json.RawMessage) []byte {
	var patch any = value
	for _, key := range slices.Backward(path) {
		patch = map[string]any{key: patch}
	}
	raw, _ := json.Marshal(patch)
	return raw
}

func (c *connection) path() []string {
	return []string{"accounts", c.account, "connections", c.key, c.protocol}
}

func (m *monitor) currentValue(c *connection, path []string, before json.RawMessage) bool {
	current := configValue(m.doc.Config, path)
	return m.running[c.name] == c && (bytes.Equal(current, before) || jsonpatch.Equal(current, before))
}

// Provider writes preserve the connector and publish only after persistence.
func (m *monitor) replaceValue(ctx context.Context, c *connection, path []string, before, after json.RawMessage) error {
	if !m.currentValue(c, path, before) {
		return errors.New("credential changed; start again")
	}
	next := m.doc
	var err error
	if next.Config, err = jsonpatch.MergePatch(next.Config, valuePatch(path, after)); err != nil {
		return err
	}
	next.Generation++
	return m.commitLocked(ctx, next)
}

// persist writes a document without publishing it or touching runtime resources.
func (m *monitor) persist(ctx context.Context, sl sealed, key []byte) error {
	plain, _ := json.Marshal(sl)
	aead, err := newAEAD(key)
	if err != nil {
		return err
	}
	return m.store.WriteAll(ctx, m.object, aead.Seal(nil, nil, plain, nil), nil)
}

// commitLocked requires mu. Queue changes are published only after persistence;
// label changes already applied by setLabelLocked remain restrictive on failure.
func (m *monitor) commitLocked(ctx context.Context, next sealed) error {
	if err := m.persist(ctx, next, m.owner); err != nil {
		return err
	}
	m.doc = next
	m.labelsDirty = false
	return nil
}

// build validates without starting anything or mutating live credentials.
func (m *monitor) build(ctx context.Context, sl sealed, env connector.Env, old *state) (*state, error) {
	cfg, definitions, err := parse(sl.Config)
	if err != nil {
		return nil, err
	}
	s := &state{cfg: cfg, connections: definitions, principals: map[string]principal{}, Env: env}
	s.Dialer = connector.NewDialer(cfg.AllowNetworks)
	client := s.Client()
	for name, definition := range definitions {
		if old != nil && old.connections[name] != nil && slices.Equal(old.cfg.AllowNetworks, cfg.AllowNetworks) &&
			old.connections[name].account == definition.account && old.connections[name].protocol == definition.protocol &&
			jsonpatch.Equal(configValue(m.doc.Config, definition.path()), definition.config) {
			s.connections[name] = old.connections[name]
		} else {
			for _, field := range definition.connector.Fields() {
				if field.Value == nil {
					continue
				}
				path := append(definition.path(), field.Path...)
				field.Value.Client = client
				field.Value.Save = func(ctx context.Context, before, after json.RawMessage) error {
					m.mu.Lock()
					defer m.mu.Unlock()
					return m.replaceValue(ctx, definition, path, before, after)
				}
			}
		}
	}
	for name, id := range cfg.Identities {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(id.Key))
		if err != nil {
			return nil, fmt.Errorf("identity %s: %w", name, err)
		}
		fingerprint := ssh.FingerprintSHA256(key)
		if _, exists := s.principals[fingerprint]; exists {
			return nil, fmt.Errorf("identity %s shares another identity's public key", name)
		}
		if id.Profile && !m.dev {
			return nil, fmt.Errorf("identity %s: profiling needs a file:// bucket", name)
		}
		s.principals[fingerprint] = principal{Key: fingerprint, Name: name, Accounts: id.Accounts, Rules: id.Rules, Messages: id.Messages, Profile: id.Profile}
	}
	if s.decision, s.messageDecision, err = preparePolicies(ctx, cfg); err != nil {
		return nil, err
	}
	return s, nil
}
