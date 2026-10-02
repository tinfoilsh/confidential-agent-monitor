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
	"log"
	"maps"
	"net"
	"sync"
	"sync/atomic"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
	"gocloud.dev/blob"
	"gocloud.dev/gcerrors"
	"golang.org/x/crypto/ssh"
)

const ownerKeyBytes = 32

var errOwner = errors.New("invalid owner secret")

// sealed is the plaintext of the encrypted object; only Config is the owner's to edit.
type sealed struct {
	Generation uint64                    `json:"generation"`
	Keys       keyMaterial               `json:"keys"`
	Secrets    map[string]map[string]any `json:"secrets"`
	Labels     map[string]label          `json:"labels"`
	Config     json.RawMessage           `json:"config"`
}

type state struct {
	sealed
	cfg         *config
	connections map[string]*connection
	principals  map[string]principal
	decision    rego.PreparedEvalQuery
	credentials map[string]credential.Store
	connector.Env
}

type monitor struct {
	live    atomic.Pointer[state]
	mu      sync.Mutex
	owner   []byte
	store   *blob.Bucket
	object  string
	listen  string
	running map[string]*connection
	// flow orders label reads and writes; labels change only while holding both it and mu.
	flow    sync.Mutex
	labels  map[string]label
	records records
	// signIns holds the finish of each started sign-in, keyed by its state.
	signIns sync.Map
}

type principal struct {
	Key      string            `json:"key"`
	Name     string            `json:"name"`
	Accounts map[string]access `json:"-"`
	Rules    []rule            `json:"-"`
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
	fresh := sl.Keys == keyMaterial{}
	var env connector.Env
	if env.TLS, err = loadCA(&sl.Keys); err != nil {
		return nil, err
	}
	if env.HostKey, err = loadHostKey(&sl.Keys); err != nil {
		return nil, err
	}
	if fresh {
		sl.Generation++
	}
	if m.labels = sl.Labels; m.labels == nil {
		m.labels = map[string]label{}
	}
	s, err := m.build(ctx, sl, env, nil)
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", m.listen)
	if err == nil && fresh {
		if err = m.persist(ctx, s, key); err != nil {
			ln.Close()
		}
	}
	if err != nil {
		return nil, err
	}
	m.owner = key
	m.live.Store(s)
	m.apply(s)
	go m.serveSSH(ln)
	return s, nil
}

func (m *monitor) patch(ctx context.Context, patch []byte) (*state, error) {
	old := m.live.Load()
	next := old.sealed
	var doc map[string]json.RawMessage
	if err := json.Unmarshal(patch, &doc); err != nil {
		return nil, err
	}
	secretsPatch, ok := doc["secrets"]
	if !ok {
		secretsPatch = json.RawMessage("{}")
	}
	delete(doc, "secrets")
	patch, err := json.Marshal(doc)
	if err != nil {
		return nil, err
	}
	if next.Config, err = jsonpatch.MergePatch(old.Config, patch); err != nil {
		return nil, err
	}
	secrets := []byte("{}")
	if old.Secrets != nil {
		if secrets, err = json.Marshal(old.Secrets); err != nil {
			return nil, err
		}
	}
	if secrets, err = jsonpatch.MergePatch(secrets, secretsPatch); err != nil {
		return nil, err
	}
	next.Secrets = nil
	if err := json.Unmarshal(secrets, &next.Secrets); err != nil {
		return nil, err
	}
	next.Generation++
	s, err := m.build(ctx, next, old.Env, old)
	if err != nil {
		return nil, err
	}
	if err := m.persist(ctx, s, m.owner); err != nil {
		return nil, err
	}
	m.live.Store(s)
	m.apply(s)
	return s, nil
}

func (m *monitor) rotate(key credentialKey, source credential.Source, old, new string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.live.Load()
	if s.credentials[key.account][key.name] != source {
		return nil
	}
	secret, _ := s.Secrets[key.account][key.name].(map[string]any)
	oauth, _ := secret["oauth"].(map[string]any)
	if oauth["refresh_token"] != old {
		return nil
	}
	// Rotation only saves the source's runtime state. It does not rebuild config.
	next := *s
	next.Generation++
	next.Secrets = maps.Clone(s.Secrets)
	next.Secrets[key.account] = maps.Clone(s.Secrets[key.account])
	secret = maps.Clone(secret)
	oauth = maps.Clone(oauth)
	oauth["refresh_token"] = new
	secret["oauth"] = oauth
	next.Secrets[key.account][key.name] = secret
	if err := m.persist(context.Background(), &next, m.owner); err != nil {
		log.Printf("rotate: %v", err)
		return err
	}
	m.live.Store(&next)
	return nil
}

// persist keeps only the labels of keys that some identity holds.
func (m *monitor) persist(ctx context.Context, s *state, key []byte) error {
	sl := s.sealed
	sl.Labels = maps.Clone(m.labels)
	maps.DeleteFunc(sl.Labels, func(fingerprint string, _ label) bool { _, ok := s.principals[fingerprint]; return !ok })
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

// build validates without starting anything or mutating live credentials.
func (m *monitor) build(ctx context.Context, sl sealed, env connector.Env, old *state) (*state, error) {
	cfg, connections, err := parse(sl.Config, sl.Secrets)
	if err != nil {
		return nil, err
	}
	credentials := map[string]credential.Store{}
	changed := map[credentialKey]bool{}
	for _, conn := range connections {
		account := conn.account
		for _, name := range conn.credentialRefs {
			if credentials[account] == nil {
				credentials[account] = credential.Store{}
			}
			if credentials[account][name] != nil {
				continue
			}
			raw, err := json.Marshal(sl.Secrets[account][name])
			if err != nil {
				return nil, err
			}
			if old != nil {
				previous, err := json.Marshal(old.Secrets[account][name])
				if err != nil {
					return nil, err
				}
				if source := old.credentials[account][name]; source != nil && bytes.Equal(previous, raw) {
					credentials[account][name] = source
					continue
				}
			}
			key := credentialKey{account, name}
			changed[key] = true
			var c credential.Credential
			if err := json.Unmarshal(raw, &c); err != nil {
				return nil, fmt.Errorf("credential %s/%s: %w", account, name, err)
			}
			if c.Name != nil {
				return nil, fmt.Errorf("credential %s/%s must be a string or an oauth grant", account, name)
			}
			if source, ok := c.Source.(*credential.OAuth); ok {
				source.Rotated = func(before, after string) error { return m.rotate(key, source, before, after) }
			}
			credentials[account][name] = c.Source
		}
	}
	maps.DeleteFunc(sl.Secrets, func(acct string, _ map[string]any) bool { _, ok := cfg.Accounts[acct]; return !ok })
	s := &state{sealed: sl, cfg: cfg, connections: connections, principals: map[string]principal{}, credentials: credentials, Env: env}
	s.Dialer = connector.NewDialer(cfg.AllowNetworks)
	for name, id := range cfg.Identities {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(id.Key))
		if err != nil {
			return nil, fmt.Errorf("identity %s: %w", name, err)
		}
		fingerprint := ssh.FingerprintSHA256(key)
		s.principals[fingerprint] = principal{Key: fingerprint, Name: name, Accounts: id.Accounts, Rules: id.Rules}
	}
	if s.decision, err = prepareDecision(ctx, cfg); err != nil {
		return nil, err
	}
	if old != nil {
		for name, c := range connections {
			if previous := old.connections[name]; previous != nil && previous.account == c.account && previous.spec == c.spec && !c.usesChangedCredential(changed) {
				c.cancel()
				connections[name] = previous
			}
		}
	}
	return s, nil
}
