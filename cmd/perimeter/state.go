package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/format"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/sandbox"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/credential"
	"github.com/tinfoilsh/confidential-agent-monitor/core"
	"github.com/tinfoilsh/confidential-agent-monitor/core/admission"
	"github.com/tinfoilsh/confidential-agent-monitor/core/approval"
	"github.com/tinfoilsh/confidential-agent-monitor/core/certificates"
	"github.com/tinfoilsh/confidential-agent-monitor/core/identity"
	"github.com/tinfoilsh/confidential-agent-monitor/core/sealedlog"
	"gocloud.dev/blob"
	"golang.org/x/crypto/ssh"
)

const (
	caName               = "perimeter dev CA"
	caLifetime           = 10 * 365 * 24 * time.Hour
	leafLifetime         = 24 * time.Hour
	leafBackdate         = time.Hour
	connectorOpenTimeout = time.Minute
	signInClient         = "Perimeter"
)

var signInLimits = credential.SignInLimits{Timeout: 30 * time.Second, Lifetime: 10 * time.Minute, MaxDeviceExpiry: 24 * time.Hour, MaxDeviceInterval: 3600,
	MaxResponseBytes: 1 << 20, MaxClientIDBytes: 512}

var auditLimits = sealedlog.Limits{FlushInterval: time.Minute, WriteTimeout: 30 * time.Second, SegmentBytes: 8 << 20, MaxBacklog: 64 << 20, PageRecords: 200}

var errOwner error = httpError{errors.New("invalid owner secret"), http.StatusUnauthorized}

// When both locks are needed, writes is taken before mu.
type state struct {
	bucket     *blob.Bucket
	life       context.Context
	flushing   sync.WaitGroup
	mu         sync.Mutex
	writes     sync.Mutex
	doc        format.Document
	storageKey []byte
	hostID     string
	sealer     sealedlog.Sealer
	audit      *sealedlog.Log
	settings   atomic.Pointer[settings]
	table      *core.Table
	routes     sandbox.Forwarder
	relays     *http.Transport
	identities identity.Registry
	admissions admission.Set[*admitted]
	records    *approval.Records[*record]
	signIns    *credential.SignIns
}

type held struct{ *state }

func newState(life context.Context, bucket *blob.Bucket) *state {
	s := &state{bucket: bucket, life: life, signIns: credential.NewSignIns(signInLimits, signInClient)}
	s.relays = s.routes.Transport()
	s.admissions.L = &s.mu
	s.records = approval.NewRecords(&s.mu, maxRecords, func(r *record) bool { return r.State == statePending })
	s.table = core.New(s.reaches, s.admit, selectTarget, connectorOpenTimeout)
	return s
}

func (s *state) generation() (uint64, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.doc.Generation, s.settings.Load() != nil
}

func (s *state) snapshot() (format.Document, *settings) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.doc, s.settings.Load()
}

func (s *state) locked(fn func(held)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn(held{s})
}

func stable[T any](s *state, fn func(format.Document, *settings) (T, error)) (T, error) {
	s.writes.Lock()
	defer s.writes.Unlock()
	return fn(s.snapshot())
}

func (s held) commit(ctx context.Context, next format.Document) error {
	next.Generation++
	if err := format.Save(ctx, s.bucket, s.sealer, next); err != nil {
		return err
	}
	s.doc = next
	return nil
}

func (s held) matchesStorageKey(key []byte) bool {
	return subtle.ConstantTimeCompare(key, s.storageKey) == 1
}

func (s *state) unlock(ctx context.Context, key []byte, minimum uint64) (bool, error) {
	s.writes.Lock()
	defer s.writes.Unlock()
	if !passphraseKeys && len(key) != sealedlog.KeyBytes {
		return false, errOwner
	}
	h := held{s}

	s.mu.Lock()
	unlocked := s.settings.Load() != nil
	var err error
	if unlocked && !h.matchesStorageKey(key) {
		err = errOwner
	} else if unlocked && s.doc.Generation < minimum {
		err = fmt.Errorf("live generation %d is older than %d", s.doc.Generation, minimum)
	}
	s.mu.Unlock()
	if unlocked || err != nil {
		return false, err
	}

	doc, sealer, initialized, err := format.Load(ctx, s.bucket, key, minimum)
	if errors.Is(err, sealedlog.ErrKey) {
		err = errOwner
	}
	if err != nil {
		return false, err
	}
	authority, err := ensureTLS(&doc.Keys)
	if err != nil {
		return false, err
	}
	hostID, err := credential.Thumbprint(authority.Leaf.PublicKey)
	if err != nil {
		return false, err
	}
	signer := sshHostKey
	if signer == nil {
		if signer, err = ensureHostKey(&doc.Keys); err != nil {
			return false, err
		}
	}
	source := doc.Policy
	if policyFile != "" {
		file, err := os.ReadFile(policyFile)
		if err != nil {
			return false, err
		}
		source = string(file)
	}
	lib, err := s.loadLibrary(ctx, sealer, doc.Catalogs)
	if err != nil {
		return false, err
	}
	plan, err := s.prepareSettings(ctx, lib, source, everyConnection, nil, authority, signer)
	if err != nil {
		return false, err
	}

	s.mu.Lock()
	interrupted := doc.Pending
	doc.Pending = nil
	s.doc, s.hostID = doc, hostID
	s.storageKey, s.sealer = bytes.Clone(key), sealer
	s.audit = sealedlog.New(format.Storage(s.bucket), auditPrefix, auditLimits, sealer.Seal, sealer.Open,
		func(err error) { log.Printf("audit: %v", err) })
	err = h.commitSettings(ctx, plan, nil)
	if err != nil {
		s.doc, s.hostID = format.Document{}, ""
		s.storageKey, s.sealer, s.audit = nil, sealedlog.Sealer{}, nil
	} else {
		s.flushing.Go(func() { s.audit.Run(s.life) })
		h.recordAdmin(ctx, "Unlock", nil, nil)
		for _, raw := range interrupted {
			r, err := decodeRecord(raw)
			if err != nil {
				log.Printf("interrupted record: %v", err)
				continue
			}
			h.records.Add(r)
			h.settleRecord(r, errRestarted)
		}
	}
	s.mu.Unlock()
	if err != nil {
		return false, err
	}
	s.table.Start()
	return initialized, nil
}

func (s *state) close() {
	s.writes.Lock()
	defer s.writes.Unlock()
	s.table.Close()
	s.flushing.Wait()
}

func (s *state) acceptsStorageKey(key []byte) bool {
	if len(key) < sealedlog.MinKeyBytes || len(key) > sealedlog.MaxKeyBytes {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settings.Load() == nil || held{s}.matchesStorageKey(key)
}

func ensureTLS(keys *format.Keys) (*certificates.Authority, error) {
	if keys.CACert == "" {
		created, err := certificates.NewAuthority(caName, caLifetime)
		if err != nil {
			return nil, err
		}
		keys.CACert, keys.CAKey = created.PEM()
	}
	return certificates.LoadAuthority(keys.CACert, keys.CAKey)
}

func ensureHostKey(keys *format.Keys) (ssh.Signer, error) {
	if keys.HostKey == "" {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		block, err := ssh.MarshalPrivateKey(private, "")
		if err != nil {
			return nil, err
		}
		keys.HostKey = string(pem.EncodeToMemory(block))
	}
	return ssh.ParsePrivateKey([]byte(keys.HostKey))
}

func (s *state) hostKey() ssh.Signer {
	if st := s.settings.Load(); st != nil {
		return st.hostKey
	}
	return sshHostKey
}