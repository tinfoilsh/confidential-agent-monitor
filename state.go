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
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"iter"
	"log"
	"maps"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/connector/mcp"
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
	Policy     string                 `json:"policy"`
	Secrets    secretStore            `json:"secrets,omitempty"`
}

type state struct {
	cfg         *config
	connections map[string]*connection
	principals  map[string]principal
	query       rego.PreparedEvalQuery
	program     string
	connector.Env
}

type monitor struct {
	live    atomic.Pointer[state]
	mu      sync.Mutex
	doc     sealed
	owner   []byte
	store   *blob.Bucket
	running map[string]*connection

	// A measured public digest prevents another caller claiming an empty store.
	ownerKeyHash []byte
	sshHostKey   ssh.Signer

	// routesMu keeps SSH admission and routing independent of mu's policy commits.
	// sessions records whether each connection's key had an identity when admitted.
	routesMu sync.Mutex
	routes   map[string]*routeSession
	sessions map[*ssh.ServerConn]bool

	// mu owns authorization transactions, including documents, records and streams.
	streams map[*connector.Stream]string
	records []*record
	// Only with a file:// bucket: identities may profile.
	dev bool
	// signIns holds the finish of each started sign-in, keyed by its state.
	signIns sync.Map
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
	if len(m.ownerKeyHash) != 0 {
		digest := sha256.Sum256(key)
		if subtle.ConstantTimeCompare(digest[:], m.ownerKeyHash) != 1 {
			return errOwner
		}
	}
	if m.live.Load() != nil {
		if subtle.ConstantTimeCompare(key, m.owner) != 1 {
			return errOwner
		}
		if m.doc.Generation < minimum {
			return fmt.Errorf("live generation %d is older than %d", m.doc.Generation, minimum)
		}
		return nil
	}
	aead, err := newAEAD(key)
	if err != nil {
		return err
	}
	sl := sealed{Labels: map[string]facts.Label{}}
	raw, err := m.store.ReadAll(ctx, stateObject)
	missing := gcerrors.Code(err) == gcerrors.NotFound
	// S3 hides missing objects behind AccessDenied when ListBucket is scoped
	// by prefix. Confirm absence with an authorized prefix listing. A denied
	// listing or an existing unreadable object must never reset the state.
	if gcerrors.Code(err) == gcerrors.PermissionDenied && minimum == 0 {
		items := m.store.List(&blob.ListOptions{Prefix: stateObject})
		for {
			item, listErr := items.Next(ctx)
			if errors.Is(listErr, io.EOF) {
				missing = true
				break
			}
			if listErr != nil {
				return errors.Join(err, listErr)
			}
			if item.Key == stateObject {
				break
			}
		}
	}
	if !missing || minimum != 0 {
		if err != nil {
			return err
		}
		plain, err := aead.Open(nil, nil, raw, nil)
		if err != nil {
			return errOwner
		}
		// Unknown stored fields are ignored.
		sl = sealed{}
		if err := json.Unmarshal(plain, &sl); err != nil {
			return err
		}
	}
	if sl.Generation < minimum {
		return fmt.Errorf("stored generation %d is older than %d", sl.Generation, minimum)
	}
	var env connector.Env
	if env.TLS, err = loadCA(&sl.Keys); err != nil {
		return err
	}
	env.HostKey = m.sshHostKey
	if env.HostKey == nil {
		if env.HostKey, err = loadHostKey(&sl.Keys); err != nil {
			return err
		}
	}
	s, err := m.build(ctx, sl, env, nil)
	if err != nil {
		return err
	}
	m.owner, m.streams, m.running = key, map[*connector.Stream]string{}, map[string]*connection{}
	return m.activate(ctx, sl, s)
}

// activate persists a candidate prepared under the same lock, then publishes it.
func (m *monitor) activate(ctx context.Context, next sealed, s *state) error {
	old := m.live.Load()
	next.Labels = maps.Clone(next.Labels)
	maps.DeleteFunc(next.Labels, func(key string, _ facts.Label) bool { _, ok := s.principals[key]; return !ok })
	if err := m.commit(ctx, next); err != nil {
		return err
	}
	for stream, key := range m.streams {
		p, exists := s.principals[key]
		sameAccess := maps.EqualFunc(old.principals[key].Accounts, p.Accounts, func(a, b access) bool {
			return a.Level == b.Level && maps.Equal(a.Actions, b.Actions)
		})
		if !exists || old.principals[key].Routes != p.Routes || !sameAccess || s.cfg.Lattices != old.cfg.Lattices {
			stream.Close()
		}
	}
	m.reconcile(s)
	m.live.Store(s)
	return nil
}

// Provider writes preserve the connector and publish only after persistence.
func (m *monitor) replaceValue(ctx context.Context, c *connection, id secretID, before, after json.RawMessage) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.live.Load().connections[c.name] != c || !bytes.Equal(m.doc.Secrets.get(id), before) {
		return errors.New("credential changed; start again")
	}
	next := m.doc
	next.Secrets = next.Secrets.clone()
	next.Secrets.set(id, bytes.Clone(after))
	return m.commit(ctx, next)
}

// Queue changes are published only after persistence.
func (m *monitor) commit(ctx context.Context, next sealed) error {
	next.Generation++
	plain, err := json.Marshal(next)
	if err != nil {
		return err
	}
	aead, err := newAEAD(m.owner)
	if err != nil {
		return err
	}
	if err := m.store.WriteAll(ctx, stateObject, aead.Seal(nil, nil, plain, nil), nil); err != nil {
		return err
	}
	m.doc = next
	return nil
}

// build validates without starting anything or mutating live credentials.
func (m *monitor) build(ctx context.Context, sl sealed, env connector.Env, old *state) (*state, error) {
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
			if previous != nil && previous.account == definition.account && previous.protocol == definition.protocol && bytes.Equal(previous.config, definition.config) &&
				maps.EqualFunc(m.doc.Secrets[definition.account][definition.key], sl.Secrets[definition.account][definition.key], slices.Equal[json.RawMessage]) {
				s.connections[name] = previous
				continue
			}
		}
		for name, value := range definition.Secrets {
			id := secretID{definition.account, definition.key, name}
			value.Client = client
			value.Save = func(ctx context.Context, before, after json.RawMessage) error {
				return m.replaceValue(ctx, definition, id, before, after)
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
	if s.query, s.program, err = preparePolicy(ctx, cfg); err != nil {
		return nil, err
	}
	return s, nil
}

// prepareCandidate validates source without publishing anything.
func (m *monitor) prepareCandidate(ctx context.Context, source string, secrets secretStore) (sealed, *state, error) {
	next := m.doc
	next.Policy = source
	next.Secrets = secrets
	if secrets == nil {
		next.Secrets = m.doc.Secrets.clone()
	}
	st, err := m.build(ctx, next, m.live.Load().Env, m.live.Load())
	return next, st, err
}

func (m *monitor) editPolicy(ctx context.Context, changes []sourceChange) error {
	if len(changes) == 0 {
		return nil
	}
	secrets := m.doc.Secrets.clone()
	var edits []sourceChange
	for _, change := range changes {
		if len(change.Path) == 0 {
			return errors.New("an edit requires a source path")
		}
		if change.Delete && change.Value != nil {
			return errors.New("a deletion cannot have a value")
		}
		// Credentials live in the sealed store; removing a connection drops its own.
		if isCredentialPath(change.Path) {
			var raw json.RawMessage
			if change.Value != nil {
				raw, _ = json.Marshal(change.Value)
			}
			secrets.set(credentialID(change.Path), raw)
			continue
		}
		if !change.Delete {
			var err error
			if change.Value, err = tomlValue(change.Value); err != nil {
				return err
			}
		}
		// Replacing a table key by key gives it [header] sections instead of one inline line.
		if table, ok := change.Value.(map[string]any); ok && len(table) > 0 && table["$json"] == nil {
			edits = append(edits, sourceChange{Path: change.Path, Delete: true})
			edits = append(edits, fragmentChanges(table, change.Path)...)
			continue
		}
		edits = append(edits, change)
	}
	source, err := editSource(m.doc.Policy, edits)
	if err != nil {
		return err
	}
	// Compilation drops credentials without a connection, so compare against what this edit wrote.
	next, st, err := m.prepareCandidate(ctx, source, secrets.clone())
	if err != nil {
		return err
	}
	for id, raw := range secrets.all() {
		if next.Secrets.get(id) == nil && !bytes.Equal(raw, m.doc.Secrets.get(id)) {
			return fmt.Errorf("credential %v has no connection", id)
		}
	}
	return m.activate(ctx, next, st)
}

func connectionName(account, key string) string {
	if key != "" {
		return account + "-" + key
	}
	return account
}

func (m *monitor) currentLabel(fingerprint string) facts.Label {
	if l, ok := m.doc.Labels[fingerprint]; ok {
		return l
	}
	return cleanLabel
}

// observe persists a changed label before the request runs.
// The stream observing the data may finish its own request.
func (m *monitor) observe(ctx context.Context, fingerprint string, l facts.Label, source *connector.Stream) error {
	if old := m.currentLabel(fingerprint); old.Trust == l.Trust && old.Audience == l.Audience {
		return nil
	}
	next := m.doc
	next.Labels = maps.Clone(m.doc.Labels)
	next.Labels[fingerprint] = l
	if err := m.commit(ctx, next); err != nil {
		return err
	}
	// Closing the client side prevents further input under an old label, including on raw SSH and CLI streams.
	for s, key := range m.streams {
		if key == fingerprint && s != source {
			s.Close()
		}
	}
	return nil
}

// Compilation fills settings; reconciliation starts runtime resources after persistence.
type connection struct {
	Secrets                      map[string]*credential.Value
	name, protocol, account, key string
	config                       json.RawMessage
	connector                    connector.Server
	ctx                          context.Context
	cancel                       context.CancelFunc
	ready, done                  chan struct{}
	incoming                     chan *connector.Stream
	err                          error // Published by closing done.
}

// reconcile never waits for upstreams. Replacements wait for their predecessors,
// including when a connection is removed and immediately re-added.
func (m *monitor) reconcile(s *state) {
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
		c.ready, c.done, c.incoming = make(chan struct{}), make(chan struct{}), make(chan *connector.Stream)
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
			serve := func() {
				var streams sync.WaitGroup
				defer streams.Wait()
				close(c.ready)
				for {
					select {
					case stream := <-c.incoming:
						streams.Go(func() { defer stream.Close(); c.connector.Serve(stream, &s.Env) })
					case <-c.ctx.Done():
						return
					}
				}
			}
			if runner, ok := c.connector.(connector.Runner); ok {
				c.err = runner.Run(c.ctx, &s.Env, serve)
			} else {
				serve()
			}
			if c.err != nil && c.ctx.Err() == nil {
				log.Printf("connector %s: %v", c.name, c.err)
			}
		}()
	}
}

type connectionStatus struct {
	State   string `json:"state"`
	Error   string `json:"error,omitempty"`
	Details any    `json:"details,omitempty"`
}

func (c *connection) status() connectionStatus {
	select {
	case <-c.done:
		if c.err != nil {
			return connectionStatus{State: "error", Error: c.err.Error()}
		}
		return connectionStatus{State: "stopped"}
	default:
	}
	select {
	case <-c.ready:
		result := connectionStatus{State: "ready"}
		if reporter, ok := c.connector.(*mcp.Server); ok {
			result.Details = reporter.Status()
		}
		return result
	default:
		return connectionStatus{State: "connecting"}
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
	return &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) { return leaf(ca, hello) }}, nil
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
func leaf(ca tls.Certificate, hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := hello.ServerName
	if c, ok := hello.Conn.(*connector.Stream); ok && name == "" {
		name = c.Host
	}
	if name == "" {
		return nil, errors.New("a selected connection needs TLS server name indication")
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
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Leaf, &key.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
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

func isCredentialPath(path []string) bool {
	return len(path) == 7 && path[0] == "accounts" && path[2] == "connections" && path[5] == "secrets"
}
func credentialID(path []string) secretID { return secretID{path[1], path[3], path[6]} }

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
