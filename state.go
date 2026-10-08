package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"maps"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/facts"
	"gocloud.dev/blob"
	"gocloud.dev/gcerrors"
	"golang.org/x/crypto/ssh"
)

type label = facts.Label

var cleanLabel = label{Trust: "trusted", Audience: "anyone"}

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
	cfg         *config
	connections map[string]*connection
	principals  map[string]principal
	decision    policyQuery
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
	// flow orders authorization commits; mu protects all document reads and writes.
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
		p, exists := s.principals[key]
		sameAccess := maps.EqualFunc(old.principals[key].Accounts, p.Accounts, func(a, b access) bool {
			return a.Level == b.Level && maps.Equal(a.Actions, b.Actions)
		})
		// Raw sessions cannot recheck permissions for each byte after admission.
		if !exists || !sameAccess || s.cfg.Lattices != old.cfg.Lattices {
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
	if s.decision, err = preparePolicy(ctx, cfg); err != nil {
		return nil, err
	}
	return s, nil
}

// Parsing fills settings; apply allocates runtime resources after persistence.
type connection struct {
	name, protocol, account, key string
	config                       json.RawMessage
	publicConfig                 json.RawMessage
	connector                    connector.Connector
	ctx                          context.Context
	cancel                       context.CancelFunc
	ready, done                  chan struct{}
	incoming                     *connector.Listener
	err                          error // Published by closing done.
}

// apply never waits for upstreams. Replacements wait for their predecessors,
// including when a connection is removed and immediately re-added.
func (m *monitor) apply(s *state) {
	if m.running == nil {
		m.running = map[string]*connection{}
	}
	for name, c := range m.running {
		if s.connections[name] != c {
			c.cancel()
			select {
			case <-c.done:
				delete(m.running, name)
			default:
			}
		}
	}
	for name, c := range s.connections {
		previous := m.running[name]
		if previous == c {
			continue
		}
		c.ctx, c.cancel = context.WithCancel(context.Background())
		c.ready, c.done = make(chan struct{}), make(chan struct{})
		c.incoming = connector.NewListener()
		m.running[name] = c
		go func() {
			defer close(c.done)
			defer c.cancel()
			if previous != nil {
				<-previous.done
			}
			if c.ctx.Err() != nil {
				return
			}
			stop := context.AfterFunc(c.ctx, func() { c.incoming.Close() })
			defer stop()
			defer c.incoming.Close()
			c.err = connector.Run(c.connector, c.ctx, &s.Env, c.incoming, func() { close(c.ready) })
			if c.err != nil && c.ctx.Err() == nil {
				log.Printf("connector %s: %v", c.name, c.err)
			}
		}()
	}
}

func (c *connection) status() any {
	select {
	case <-c.done:
		if c.err != nil {
			return map[string]string{"state": "error", "error": c.err.Error()}
		}
		return map[string]string{"state": "stopped"}
	default:
	}
	select {
	case <-c.ready:
		if r, ok := c.connector.(connector.Reporter); ok {
			return r.Status()
		}
		return map[string]string{"state": "ready"}
	default:
		return map[string]string{"state": "connecting"}
	}
}

func connectionName(account, key string) string {
	if key != "" {
		return account + "-" + key
	}
	return account
}

func redactedConnection(c *connection) json.RawMessage {
	if c.publicConfig != nil {
		return c.publicConfig
	}
	raw := c.config
	for _, field := range c.connector.Fields() {
		if field.Redact {
			raw, _ = jsonpatch.MergePatch(raw, valuePatch(field.Path, json.RawMessage("null")))
		}
	}
	return raw
}

func (m *monitor) label(fingerprint string) label {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.labelLocked(fingerprint)
}

// labelLocked requires mu.
func (m *monitor) labelLocked(fingerprint string) label {
	if l, ok := m.doc.Labels[fingerprint]; ok {
		return l
	}
	return cleanLabel
}

// setLabelLocked requires flow and mu. Keep the new label in memory even if
// persistence fails. The stream observing the data may finish its own request.
func (m *monitor) setLabelLocked(fingerprint string, l label, source *connector.Stream) {
	old := m.labelLocked(fingerprint)
	changed := old.Trust != l.Trust || old.Audience != l.Audience
	if !changed && maps.Equal(old.Because, l.Because) {
		return
	}
	if m.doc.Labels == nil {
		m.doc.Labels = map[string]label{}
	}
	l.Because = maps.Clone(l.Because)
	m.doc.Labels[fingerprint] = l
	m.doc.Generation++
	m.labelsDirty = true
	lattices := m.live.Load().cfg.Lattices
	if lattices.Integrity && old.Trust != l.Trust || lattices.Confidentiality && old.Audience != l.Audience {
		m.retireStreamsLocked(fingerprint, source)
	}
}

// relabel requires flow. Retry a failed label write before admitting more data,
// including when this request would leave the in-memory label unchanged.
func (m *monitor) relabel(ctx context.Context, fingerprint string, l label, source *connector.Stream) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.setLabelLocked(fingerprint, l, source)
	if !m.labelsDirty {
		return nil
	}
	return m.commitLocked(ctx, m.doc)
}

const (
	caLifetime   = 10 * 365 * 24 * time.Hour
	leafLifetime = 24 * time.Hour
	leafBackdate = time.Hour
)

type keyMaterial struct {
	HostKey string `json:"host_key"`
	CACert  string `json:"ca_cert"`
	CAKey   string `json:"ca_key"`
}

type authority struct {
	ca     tls.Certificate
	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

func loadCA(k *keyMaterial) (*tls.Config, error) {
	if k.CACert == "" {
		if err := createCA(k); err != nil {
			return nil, err
		}
	}
	ca, err := tls.X509KeyPair([]byte(k.CACert), []byte(k.CAKey))
	if err != nil {
		return nil, err
	}
	a := &authority{ca: ca, leaves: map[string]*tls.Certificate{}}
	return &tls.Config{GetCertificate: a.certificate}, nil
}

func createCA(k *keyMaterial) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	template := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "monitor dev CA"},
		NotBefore:             now,
		NotAfter:              now.Add(caLifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	k.CAKey = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	k.CACert = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return nil
}

// Without SNI, the leaf is minted for the channel's target.
func (a *authority) certificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := hello.ServerName
	if c, ok := hello.Conn.(*connector.Stream); ok && name == "" {
		name = c.Host
	}
	if name == "" {
		return nil, errors.New("a selected connection needs TLS server name indication")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if leaf := a.leaves[name]; leaf != nil && time.Now().Before(leaf.Leaf.NotAfter) {
		return leaf, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		Subject:     pkix.Name{CommonName: name},
		NotBefore:   now.Add(-leafBackdate),
		NotAfter:    now.Add(leafLifetime),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(name); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.ca.Leaf, &key.PublicKey, a.ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	leaf := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}
	a.leaves[name] = leaf
	return leaf, nil
}

func loadHostKey(k *keyMaterial) (ssh.Signer, error) {
	if k.HostKey == "" {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		block, err := ssh.MarshalPrivateKey(private, "")
		if err != nil {
			return nil, err
		}
		k.HostKey = string(pem.EncodeToMemory(block))
	}
	return ssh.ParsePrivateKey([]byte(k.HostKey))
}
