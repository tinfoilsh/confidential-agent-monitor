package main

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"slices"
	"strings"
	"sync"
	"sync/atomic"

	jsonpatch "github.com/evanphx/json-patch/v5"
	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/connector/web"
	"gocloud.dev/blob"
	"gocloud.dev/gcerrors"
	"golang.org/x/crypto/ssh"
)

const (
	ownerKeyBytes    = 32
	maxDocumentBytes = 16 << 20
)

var errOwner = errors.New("invalid owner secret")

//go:embed app
var app embed.FS

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
	// infra is what connectors are started from; states that share it share them.
	infra string
	connector.Env
}

type monitor struct {
	live   atomic.Pointer[state]
	mu     sync.Mutex
	owner  []byte
	store  *blob.Bucket
	object string
	listen string
	// flow orders label reads and writes; labels change only while holding both it and mu.
	flow    sync.Mutex
	labels  map[string]label
	records records
	// signIns holds the finish of each started sign-in, keyed by its state.
	signIns sync.Map
}

// ownerView never includes private keys or secret values.
type ownerView struct {
	Generation uint64                       `json:"generation"`
	Config     json.RawMessage              `json:"config"`
	HostKey    string                       `json:"host_key"`
	CA         string                       `json:"ca"`
	Secrets    map[string][]string          `json:"secrets"`
	Status     map[string]any               `json:"status"`
	Labels     map[string]label             `json:"labels"`
	Setup      map[string]map[string]string `json:"setup"`
	Templates  any                          `json:"templates"`
}

func (m *monitor) view(s *state, err error) (any, error) {
	if err != nil {
		return nil, err
	}
	templates, err := catalog()
	if err != nil {
		return nil, err
	}
	v := ownerView{s.Generation, s.Config, string(ssh.MarshalAuthorizedKey(s.HostKey.PublicKey())), s.Keys.CACert,
		map[string][]string{}, map[string]any{}, map[string]label{}, map[string]map[string]string{}, templates}
	for acct, secrets := range s.Secrets {
		v.Secrets[acct] = slices.Sorted(maps.Keys(secrets))
	}
	for _, c := range s.connections {
		if r, ok := c.connector.(connector.Reporter); ok {
			v.Status[c.name] = r.Status()
		}
	}
	for _, p := range s.principals {
		v.Labels[p.Name] = m.label(p.Key)
		v.Setup[p.Name] = map[string]string{}
		for _, c := range s.connections {
			if r, ok := c.connector.(*web.HTTP); ok && p.reaches(c.account) {
				for secret := range r.Secrets {
					v.Setup[p.Name][secret] = web.Placeholder(c.name, secret)
				}
			}
		}
	}
	return v, nil
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
		s.retire(nil)
		return nil, err
	}
	m.owner = key
	m.live.Store(s)
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
		s.retire(old)
		return nil, err
	}
	m.live.Store(s)
	old.retire(s)
	return s, nil
}

func (m *monitor) rotate(old, new string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	secrets := map[string]map[string]any{}
	for acct, ss := range m.live.Load().Secrets {
		for key, v := range ss {
			secret, _ := v.(map[string]any)
			if o, _ := secret["oauth"].(map[string]any); o["refresh_token"] == old {
				if secrets[acct] == nil {
					secrets[acct] = map[string]any{}
				}
				secrets[acct][key] = map[string]any{"oauth": map[string]any{"refresh_token": new}}
			}
		}
	}
	patch, err := json.Marshal(map[string]any{"secrets": secrets})
	if err == nil {
		_, err = m.patch(context.Background(), patch)
	}
	if err != nil {
		log.Printf("rotate: %v", err)
	}
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

// build starts connectors anew unless old shares their infra; the caller retires whichever state it does not publish.
func (m *monitor) build(ctx context.Context, sl sealed, env connector.Env, old *state) (*state, error) {
	cfg, connections, err := parse(sl.Config, sl.Secrets)
	if err != nil {
		return nil, err
	}
	maps.DeleteFunc(sl.Secrets, func(acct string, _ map[string]any) bool { _, ok := cfg.Accounts[acct]; return !ok })
	s := &state{sealed: sl, cfg: cfg, connections: connections, principals: map[string]principal{}, Env: env}
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
	conns := map[string]any{}
	for acct, a := range cfg.Accounts {
		conns[acct] = a.Connections
	}
	infra, err := json.Marshal([]any{conns, cfg.AllowNetworks, sl.Secrets})
	if err != nil {
		return nil, err
	}
	if s.infra = string(infra); old != nil && old.infra == s.infra {
		s.connections = old.connections
		return s, nil
	}
	var wg sync.WaitGroup
	for _, c := range s.connections {
		if r, ok := c.connector.(connector.Starter); ok {
			wg.Go(func() { r.Start(&s.Env) })
		}
	}
	wg.Wait()
	return s, nil
}

func (s *state) retire(next *state) {
	if next != nil && next.infra == s.infra {
		return
	}
	for _, c := range s.connections {
		if r, ok := c.connector.(connector.Stopper); ok {
			go r.Stop()
		}
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
		return m.view(m.unlock(r.Context(), key, req.Generation))
	}))
	mux.Handle("GET /{$}", m.owned(true, func(*http.Request, []byte) (any, error) { return m.view(m.live.Load(), nil) }))
	mux.Handle("PATCH /{$}", m.owned(true, func(r *http.Request, _ []byte) (any, error) {
		patch, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		return m.view(m.patch(r.Context(), patch))
	}))
	mux.Handle("POST /secrets/{account}/{key}/sign-in", m.owned(true, func(r *http.Request, _ []byte) (any, error) {
		var req struct {
			Redirect string `json:"redirect"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, err
		}
		s, acct, key := m.live.Load(), r.PathValue("account"), r.PathValue("key")
		sign, err := credential.NewSignIn(r.Context(), &http.Client{Transport: &http.Transport{DialContext: s.Dialer.DialContext}}, s.Secrets[acct][key], req.Redirect)
		if err != nil {
			return nil, err
		}
		m.signIns.Store(sign.State, func(ctx context.Context, code string) (*state, error) {
			secret, err := sign.Exchange(ctx, code)
			if err != nil {
				return nil, err
			}
			patch, err := json.Marshal(map[string]any{"secrets": map[string]any{acct: map[string]any{key: secret}}})
			if err != nil {
				return nil, err
			}
			return m.patch(ctx, patch)
		})
		return map[string]string{"url": sign.URL}, nil
	}))
	mux.Handle("POST /sign-in/{state}", m.owned(true, func(r *http.Request, _ []byte) (any, error) {
		var req struct {
			Code string `json:"code"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			return nil, err
		}
		finish, ok := m.signIns.LoadAndDelete(r.PathValue("state"))
		if !ok {
			return nil, errors.New("no sign-in is waiting for this state")
		}
		return m.view(finish.(func(context.Context, string) (*state, error))(r.Context(), req.Code))
	}))
	m.requests(mux)
	mux.Handle("GET /app/", http.FileServerFS(app))
	return mux
}

// owned serializes owner requests; before unlock, decrypting the state is what proves the secret.
func (m *monitor) owned(unlocked bool, fn func(*http.Request, []byte) (any, error)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		if unlocked && m.live.Load() == nil {
			http.Error(w, "the monitor is locked", http.StatusLocked)
			return
		}
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
