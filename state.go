package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/tinfoilsh/mcp-sentinel"
	"github.com/tinfoilsh/monitor/connector"
	"gocloud.dev/blob"
	"gocloud.dev/gcerrors"
	"golang.org/x/crypto/ssh"
)

const (
	ownerKeyBytes     = 32
	maxDocumentBytes  = 16 << 20
	defaultPolicyName = "monitor.rego"
	defaultPolicy     = "package sentinel\n\ndeny contains reason if { false; reason := \"\" }"
)

var errOwner = errors.New("invalid owner secret")

// sealed is the plaintext of the encrypted object; only Config is the owner's to edit.
type sealed struct {
	Generation uint64          `json:"generation"`
	Keys       keyMaterial     `json:"keys"`
	Config     json.RawMessage `json:"config"`
}

type state struct {
	sealed
	connections map[string]*connection
	mcp         map[string]*mcpServer
	principals  map[string]principal
	pins        map[string]*sentinel.Snapshot
	policy      *sentinel.Policy
	connector.Env
}

type monitor struct {
	live    atomic.Pointer[state]
	mu      sync.Mutex
	owner   []byte
	store   *blob.Bucket
	object  string
	listen  string
	gateway *connector.Listener
}

// MarshalJSON is the owner's view, which never includes private keys.
func (s *state) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Generation uint64          `json:"generation"`
		Config     json.RawMessage `json:"config"`
		HostKey    string          `json:"host_key"`
		CA         string          `json:"ca"`
	}{s.Generation, s.Config, string(ssh.MarshalAuthorizedKey(s.HostKey.PublicKey())), s.Keys.CACert})
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
	s, err := m.build(ctx, sl, env)
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
		retire(s)
		return nil, err
	}
	m.owner = key
	m.live.Store(s)
	m.startMCP()
	go m.serveSSH(ln)
	return s, nil
}

func (m *monitor) patch(ctx context.Context, patch []byte) (*state, error) {
	old := m.live.Load()
	next := old.sealed
	var err error
	if next.Config, err = jsonpatch.MergePatch(old.Config, patch); err != nil {
		return nil, err
	}
	next.Generation++
	s, err := m.build(ctx, next, old.Env)
	if err != nil {
		return nil, err
	}
	if err := m.persist(ctx, s, m.owner); err != nil {
		retire(s)
		return nil, err
	}
	m.live.Store(s)
	retire(old)
	return s, nil
}

func (m *monitor) persist(ctx context.Context, s *state, key []byte) error {
	plain, err := json.Marshal(s.sealed)
	if err != nil {
		return err
	}
	aead, err := newAEAD(key)
	if err != nil {
		return err
	}
	return m.store.WriteAll(ctx, m.object, aead.Seal(nil, nil, plain, nil), nil)
}

// build starts every connector anew; the caller retires whichever state it does not publish.
func (m *monitor) build(ctx context.Context, sl sealed, env connector.Env) (*state, error) {
	cfg, connections, servers, err := parse(sl.Config)
	if err != nil {
		return nil, err
	}
	s := &state{sealed: sl, connections: connections, mcp: servers, principals: map[string]principal{}, pins: cfg.Pins, Env: env}
	s.Dialer = connector.NewDialer(cfg.AllowNetworks)
	for name, id := range cfg.Identities {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(id.Key))
		if err != nil {
			return nil, fmt.Errorf("identity %s: %w", name, err)
		}
		fingerprint := ssh.FingerprintSHA256(key)
		s.principals[fingerprint] = principal{Key: fingerprint, Name: name, Connections: id.Connections}
	}
	if cfg.Data == nil {
		cfg.Data = map[string]any{}
	}
	policies := []func(*rego.Rego){rego.Module(defaultPolicyName, defaultPolicy), rego.Store(inmem.NewFromObject(cfg.Data))}
	for name, src := range cfg.Policies {
		policies = append(policies, rego.Module(name, src))
	}
	if s.policy, err = sentinel.NewPolicy(ctx, policies...); err != nil {
		return nil, err
	}
	s.connections[gatewayName] = &connection{name: gatewayName, protocol: protocolMCP, connector: m.gateway}
	for _, c := range s.connections {
		if r, ok := c.connector.(connector.Starter); ok {
			r.Start(&s.Env)
		}
	}
	var wg sync.WaitGroup
	for name, srv := range s.mcp {
		wg.Go(func() {
			if err := m.connectMCP(s, name, srv); err != nil {
				log.Printf("%s: %v", name, err)
			}
		})
	}
	wg.Wait()
	return s, nil
}

func retire(s *state) {
	for _, c := range s.connections {
		if r, ok := c.connector.(connector.Stopper); ok {
			go r.Stop()
		}
	}
	for _, srv := range s.mcp {
		srv.close()
	}
}

func (m *monitor) handler() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("POST /unlock", m.owned(false, func(r *http.Request, key []byte) (any, error) {
		var req struct {
			Generation uint64 `json:"generation"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, err
		}
		return m.unlock(r.Context(), key, req.Generation)
	}))
	mux.Handle("GET /{$}", m.owned(true, func(*http.Request, []byte) (any, error) { return m.live.Load(), nil }))
	mux.Handle("PATCH /{$}", m.owned(true, func(r *http.Request, _ []byte) (any, error) {
		patch, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		return m.patch(r.Context(), patch)
	}))
	mux.Handle("GET /mcp/{name}/review", m.owned(true, func(r *http.Request, _ []byte) (any, error) {
		return m.review(r.Context(), r.PathValue("name"))
	}))
	return mux
}

// owned serializes owner requests; before unlock, decrypting the state is what proves the secret.
func (m *monitor) owned(unlocked bool, fn func(*http.Request, []byte) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		r.Body = http.MaxBytesReader(w, r.Body, maxDocumentBytes)
		var v any
		key, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if err == nil && len(key) == ownerKeyBytes && (!unlocked || subtle.ConstantTimeCompare(key, m.owner) == 1) {
			v, err = fn(r, key)
		} else {
			err = errOwner
		}
		switch {
		case errors.Is(err, errOwner):
			http.Error(w, err.Error(), http.StatusUnauthorized)
		case err != nil:
			http.Error(w, err.Error(), http.StatusBadRequest)
		default:
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(v)
		}
	}
}
