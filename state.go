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
	"iter"
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

var cleanLabel = facts.Label{Trust: "trusted", Audience: "anyone"}

const ownerKeyBytes = 32

var errOwner = errors.New("invalid owner secret")

// sealed is the document encrypted in storage. The monitor owns it under mu.
type sealed struct {
	Generation uint64                 `json:"generation"`
	Keys       keyMaterial            `json:"keys"`
	Labels     map[string]facts.Label `json:"labels"`
	Policy     *policyDocument        `json:"policy,omitempty"`
	Secrets    secretStore            `json:"secrets,omitempty"`
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
	revision    uint64 // Changes only when policy or credentials change.
	// mu owns authorization transactions, including documents, records and streams.
	streams map[string]map[*connector.Stream]struct{}
	records []*record
	// Only with a file:// bucket: corpus receives every request to a preset's account, and identities may profile.
	dev    bool
	corpus *json.Encoder
	// signIns holds the finish of each started sign-in, keyed by its state.
	signIns map[string]pendingSignIn
}

type principal struct {
	Key  string
	Name string
	identity
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
func (m *monitor) unlock(ctx context.Context, key []byte, minimum uint64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if s := m.live.Load(); s != nil {
		if subtle.ConstantTimeCompare(key, m.owner) != 1 {
			return errOwner
		}
		return nil
	}
	aead, err := newAEAD(key)
	if err != nil {
		return err
	}
	sl := sealed{Policy: &policyDocument{Source: "[monitor]\nversion = 1\n\n[lattices]\nconfidentiality = true\nintegrity = false\n"}}
	raw, err := m.store.ReadAll(ctx, m.object)
	if gcerrors.Code(err) != gcerrors.NotFound || minimum != 0 {
		if err != nil {
			return err
		}
		plain, err := aead.Open(nil, nil, raw, nil)
		if err != nil {
			return errOwner
		}
		sl = sealed{}
		if err := facts.DecodeNumbers(plain, &sl); err != nil {
			return err
		}
	}
	if sl.Generation < minimum {
		return fmt.Errorf("stored generation %d is older than %d", sl.Generation, minimum)
	}
	fresh := sl.Keys == keyMaterial{}
	var env connector.Env
	if env.TLS, err = loadCA(&sl.Keys); err != nil {
		return err
	}
	if env.HostKey, err = loadHostKey(&sl.Keys); err != nil {
		return err
	}
	if sl.Labels == nil {
		sl.Labels = map[string]facts.Label{}
	}
	if sl.Policy == nil {
		return errors.New("stored document has no policy source")
	}
	if sl.Secrets == nil {
		sl.Secrets = secretStore{}
	}
	if sl.Policy.Bases == nil {
		sl.Policy.Bases = map[string]json.RawMessage{}
	}
	if fresh {
		sl.Generation++
	}
	s, err := m.build(ctx, sl, env, nil, nil)
	if err != nil {
		return err
	}
	sl.Secrets.prune(s.connections)
	ln, err := net.Listen("tcp", m.listen)
	if err == nil && fresh {
		if err = m.persist(ctx, sl, key); err != nil {
			ln.Close()
		}
	}
	if err != nil {
		return err
	}
	m.owner = key
	m.doc = sl
	m.signIns = map[string]pendingSignIn{}
	m.streams = map[string]map[*connector.Stream]struct{}{}
	m.running = map[string]*connection{}
	m.reconcile(s)
	m.live.Store(s)
	m.revision++
	go m.serveSSH(ln)
	return nil
}

// activate publishes exactly the state that was prepared outside the lock.
func (m *transaction) activate(ctx context.Context, candidate *policyCandidate) error {
	if candidate.base.revision != m.revision {
		return errPolicyConflict
	}
	old, s := m.live.Load(), candidate.state
	next := m.doc
	policy := *candidate.doc.Policy
	next.Policy = &policy
	next.Policy.Proposals = slices.Clone(m.doc.Policy.Proposals)
	if candidate.proposal != "" {
		p, i, err := m.doc.Policy.findProposal(candidate.proposal)
		if err != nil {
			return err
		}
		if p.State != proposalPending || p.BaseSource != m.doc.Policy.Source {
			return errPolicyConflict
		}
		principal, ok := old.principals[p.Key]
		if !ok || principal.Name != p.Agent {
			return errors.New("the proposing identity was revoked or replaced")
		}
		next.Policy.Proposals[i].State = proposalApproved
	}
	next.Secrets = candidate.doc.Secrets.clone()
	next.Secrets.prune(s.connections)
	next.Generation++
	next.Labels = maps.Clone(m.doc.Labels)
	maps.DeleteFunc(next.Labels, func(key string, _ facts.Label) bool { _, ok := s.principals[key]; return !ok })
	if err := m.commit(ctx, next); err != nil {
		return err
	}
	for key := range m.streams {
		p, exists := s.principals[key]
		sameAccess := maps.EqualFunc(old.principals[key].Accounts, p.Accounts, func(a, b access) bool {
			return a.Level == b.Level && maps.Equal(a.Actions, b.Actions)
		})
		if !exists || !sameAccess || s.cfg.Lattices != old.cfg.Lattices {
			m.retireStreams(key, nil)
		}
	}
	(*monitor)(m).reconcile(s)
	m.live.Store(s)
	m.revision++
	return nil
}

func (c *connection) path() []string {
	return []string{"accounts", c.account, "connections", c.key, c.protocol}
}

func sameCredential(a, b json.RawMessage) bool {
	if len(a) == 0 || len(b) == 0 {
		return len(a) == len(b)
	}
	return jsonpatch.Equal(a, b)
}

// Provider writes preserve the connector and publish only after persistence.
func (m *transaction) replaceValue(ctx context.Context, c *connection, id secretID, before, after json.RawMessage) error {
	if m.live.Load().connections[c.name] != c || !sameCredential(m.doc.Secrets.get(id), before) {
		return errors.New("credential changed; start again")
	}
	next := m.doc
	next.Secrets = next.Secrets.clone()
	next.Secrets.set(id, bytes.Clone(after))
	next.Generation++
	if err := m.commit(ctx, next); err != nil {
		return err
	}
	m.revision++
	return nil
}

// persist writes a document without publishing it or touching runtime resources.
func (m *monitor) persist(ctx context.Context, sl sealed, key []byte) error {
	plain, err := json.Marshal(sl)
	if err != nil {
		return err
	}
	aead, err := newAEAD(key)
	if err != nil {
		return err
	}
	return m.store.WriteAll(ctx, m.object, aead.Seal(nil, nil, plain, nil), nil)
}

// Queue changes are published only after persistence;
// label changes already applied by setLabel remain restrictive on failure.
func (m *transaction) commit(ctx context.Context, next sealed) error {
	if err := (*monitor)(m).persist(ctx, next, m.owner); err != nil {
		return err
	}
	m.doc = next
	m.labelsDirty = false
	return nil
}

// build validates without starting anything or mutating live credentials.
func (m *monitor) build(ctx context.Context, sl sealed, env connector.Env, old *state, updated map[secretID]bool) (*state, error) {
	cfg, definitions, err := compileSource(sl.Policy, sl.Secrets)
	if err != nil {
		return nil, err
	}
	s := &state{cfg: cfg, connections: definitions, principals: map[string]principal{}, Env: env}
	s.Dialer = connector.NewDialer(cfg.AllowNetworks)
	client := s.Client()
	for name, definition := range definitions {
		if old != nil && slices.Equal(old.cfg.AllowNetworks, cfg.AllowNetworks) {
			previous := old.connections[name]
			if previous != nil && previous.account == definition.account && previous.protocol == definition.protocol && jsonpatch.Equal(previous.config, definition.config) {
				same := true
				for id := range updated {
					if id[0] == definition.account && id[1] == definition.key {
						same = false
						break
					}
				}
				if same {
					s.connections[name] = previous
					continue
				}
			}
		}
		for name, value := range definition.Secrets {
			id := secretID{definition.account, definition.key, name}
			value.Client = client
			value.Save = func(ctx context.Context, before, after json.RawMessage) error {
				return m.transact(func(tx *transaction) error { return tx.replaceValue(ctx, definition, id, before, after) })
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
		s.principals[fingerprint] = principal{Key: fingerprint, Name: name, identity: id}
	}
	if s.decision, err = preparePolicy(ctx, cfg); err != nil {
		return nil, err
	}
	return s, nil
}

func connectionName(account, key string) string {
	if key != "" {
		return account + "-" + key
	}
	return account
}

func (m *transaction) currentLabel(fingerprint string) facts.Label {
	if l, ok := m.doc.Labels[fingerprint]; ok {
		return l
	}
	return cleanLabel
}

// Keep the new label in memory even if
// persistence fails. The stream observing the data may finish its own request.
func (m *transaction) setLabel(fingerprint string, l facts.Label, source *connector.Stream) {
	old := m.currentLabel(fingerprint)
	changed := old.Trust != l.Trust || old.Audience != l.Audience
	if !changed && maps.Equal(old.Because, l.Because) {
		return
	}
	m.doc.Labels = maps.Clone(m.doc.Labels)
	l.Because = maps.Clone(l.Because)
	m.doc.Labels[fingerprint] = l
	m.doc.Generation++
	m.labelsDirty = true
	lattices := m.live.Load().cfg.Lattices
	if lattices.Integrity && old.Trust != l.Trust || lattices.Confidentiality && old.Audience != l.Audience {
		m.retireStreams(fingerprint, source)
	}
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

type secretID [3]string
type secretStore map[string]map[string]map[string]json.RawMessage

func (s secretStore) get(id secretID) json.RawMessage { return s[id[0]][id[1]][id[2]] }
func (s secretStore) set(id secretID, raw json.RawMessage) {
	if raw == nil {
		delete(s[id[0]][id[1]], id[2])
		return
	}
	if s[id[0]] == nil {
		s[id[0]] = map[string]map[string]json.RawMessage{}
	}
	if s[id[0]][id[1]] == nil {
		s[id[0]][id[1]] = map[string]json.RawMessage{}
	}
	s[id[0]][id[1]][id[2]] = raw
}
func (s secretStore) all() iter.Seq2[secretID, json.RawMessage] {
	return func(yield func(secretID, json.RawMessage) bool) {
		for account, connections := range s {
			for connection, values := range connections {
				for name, raw := range values {
					if !yield(secretID{account, connection, name}, raw) {
						return
					}
				}
			}
		}
	}
}
func (s secretStore) clone() secretStore {
	out := secretStore{}
	for id, raw := range s.all() {
		out.set(id, raw)
	}
	return out
}

func (s secretStore) prune(connections map[string]*connection) {
	for id := range s.all() {
		c := connections[connectionName(id[0], id[1])]
		if c == nil || c.account != id[0] || c.key != id[1] || c.Secrets == nil {
			s.set(id, nil)
		}
	}
}
