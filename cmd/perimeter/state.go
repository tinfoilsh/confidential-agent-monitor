package main

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwk"
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
	"gocloud.dev/gcerrors"
	"golang.org/x/crypto/ssh"
)

const (
	documentObject = "monitor.enc"
	caName         = "perimeter dev CA"
	caLifetime     = 10 * 365 * 24 * time.Hour
	leafLifetime   = 24 * time.Hour
	leafBackdate   = time.Hour
)

var auditLimits = sealedlog.Limits{FlushInterval: time.Minute, WriteTimeout: 30 * time.Second, SegmentBytes: 8 << 20, MaxBacklog: 64 << 20, PageRecords: 200}

var errOwner error = httpError{format.ErrKey, http.StatusUnauthorized}

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
	sealer     format.Sealer
	audit      *sealedlog.Log
	settings   atomic.Pointer[settings]
	table      *core.Table
	routes     sandbox.Forwarder
	identities identity.Registry
	admissions admission.Set[*admitted]
	records    *approval.Records[*record]
	signIns    *credential.SignIns
}

type held struct{ *state }

func newState(life context.Context, bucket *blob.Bucket) *state {
	s := &state{bucket: bucket, life: life, signIns: credential.NewSignIns(signInLimits)}
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
	source, rebuild, renamed, err := current.Edit(source, w.changes)
	if err != nil {
		return err
	}
	plan, err := s.prepareSettings(ctx, source, rebuild, w.credentials, current.tls, current.hostKey)
	if err != nil {
		return err
	}
	plan.renamed = renamed

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

func (s held) commit(ctx context.Context, next format.Document) error {
	next.Generation++
	plain, err := format.EncodeDocument(next)
	if err != nil {
		return err
	}
	if err := s.bucket.WriteAll(ctx, documentObject, s.sealer.SealState(plain), nil); err != nil {
		return err
	}
	s.doc = next
	return nil
}

func (s *state) load(ctx context.Context, key []byte, minimum uint64) (format.Document, format.Sealer, bool, error) {
	var doc format.Document
	if len(key) < format.MinKeyBytes || len(key) > format.MaxKeyBytes {
		return doc, format.Sealer{}, false, errOwner
	}
	raw, err := s.bucket.ReadAll(ctx, documentObject)
	missing := false
	if err != nil {
		if missing, err = documentMissing(ctx, s.bucket, err); err != nil {
			return doc, format.Sealer{}, false, err
		}
	}
	if missing && minimum != 0 {
		return doc, format.Sealer{}, false, fmt.Errorf("the Perimeter has no saved state, but generation %d was saved", minimum)
	}
	var sealer format.Sealer
	if missing {
		sealer, err = format.NewSealer(key)
		doc = format.Document{Version: format.StateVersion, Labels: map[string]format.Label{}}
	} else {
		var plain []byte
		if sealer, plain, err = format.OpenState(key, raw); err == nil {
			doc, err = format.DecodeDocument(plain, v1Presets())
		}
	}
	if errors.Is(err, format.ErrKey) {
		err = errOwner
	}
	if err == nil && doc.Generation < minimum {
		err = fmt.Errorf("stored generation %d is older than %d", doc.Generation, minimum)
	}
	return doc, sealer, missing, err
}

func v1Presets() map[string]bool {
	declared := map[string]bool{}
	for name, p := range presets {
		declared[name] = p.Catalog.Connection != nil
	}
	return declared
}

func documentMissing(ctx context.Context, bucket *blob.Bucket, err error) (bool, error) {
	switch gcerrors.Code(err) {
	case gcerrors.NotFound:
		return true, nil
	case gcerrors.PermissionDenied:
		items := bucket.List(&blob.ListOptions{Prefix: documentObject})
		for {
			item, listErr := items.Next(ctx)
			if errors.Is(listErr, io.EOF) {
				return true, nil
			}
			if listErr != nil {
				return false, errors.Join(err, listErr)
			}
			if item.Key == documentObject {
				return false, err
			}
		}
	}
	return false, err
}

func documentExists(ctx context.Context, bucket *blob.Bucket) (bool, error) {
	_, err := bucket.Attributes(ctx, documentObject)
	if err == nil {
		return true, nil
	}
	missing, err := documentMissing(ctx, bucket, err)
	return !missing, err
}

func (s held) matchesStorageKey(key []byte) bool {
	return subtle.ConstantTimeCompare(key, s.storageKey) == 1
}

func (s *state) unlock(ctx context.Context, key []byte, minimum uint64) (bool, error) {
	s.writes.Lock()
	defer s.writes.Unlock()
	if !passphraseKeys && len(key) != format.KeyBytes {
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

	doc, sealer, initialized, err := s.load(ctx, key, minimum)
	if err != nil {
		return false, err
	}
	tlsConfig, err := ensureTLS(&doc.Keys)
	if err != nil {
		return false, err
	}
	hostID, err := caThumbprint(doc.Keys.CACert)
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
	plan, err := s.prepareSettings(ctx, source, everyConnection, nil, tlsConfig, signer)
	if err != nil {
		return false, err
	}

	s.mu.Lock()
	s.doc, s.hostID = doc, hostID
	s.storageKey, s.sealer = bytes.Clone(key), sealer
	s.audit = sealedlog.New(sealedlog.Storage{Write: s.bucketWrite, Read: s.bucket.ReadAll, List: s.bucketList}, auditPrefix, auditLimits, sealer.Seal, sealer.Open,
		func(err error) { log.Printf("audit: %v", err) })
	err = h.commitSettings(ctx, plan, nil)
	if err != nil {
		s.doc, s.hostID = format.Document{}, ""
		s.storageKey, s.sealer, s.audit = nil, format.Sealer{}, nil
	} else {
		s.flushing.Go(func() { s.audit.Run(s.life) })
		h.recordAdmin(ctx, "Unlock", nil, nil)
	}
	s.mu.Unlock()
	if err != nil {
		return false, err
	}
	s.table.Start()
	return initialized, nil
}

func (s *state) bucketWrite(ctx context.Context, key string, data []byte) error {
	return s.bucket.WriteAll(ctx, key, data, nil)
}

func (s *state) bucketList(ctx context.Context, prefix, delimiter string) ([]string, error) {
	keys := []string{}
	items := s.bucket.List(&blob.ListOptions{Prefix: prefix, Delimiter: delimiter})
	for {
		item, err := items.Next(ctx)
		if errors.Is(err, io.EOF) {
			return keys, nil
		}
		if err != nil {
			return nil, err
		}
		keys = append(keys, item.Key)
	}
}

func (s *state) close() {
	s.writes.Lock()
	defer s.writes.Unlock()
	s.table.Close()
	s.flushing.Wait()
}

func (s *state) acceptsStorageKey(key []byte) bool {
	if len(key) < format.MinKeyBytes || len(key) > format.MaxKeyBytes {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settings.Load() == nil || held{s}.matchesStorageKey(key)
}

func ensureTLS(keys *format.Keys) (*tls.Config, error) {
	if keys.CACert == "" {
		created, err := certificates.NewAuthority(caName, caLifetime)
		if err != nil {
			return nil, err
		}
		keys.CACert, keys.CAKey = created.PEM()
	}
	authority, err := certificates.LoadAuthority(keys.CACert, keys.CAKey)
	if err != nil {
		return nil, err
	}
	return &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		return authority.Issue(hello.ServerName, leafLifetime, leafBackdate)
	}}, nil
}

func caThumbprint(caCert string) (string, error) {
	block, _ := pem.Decode([]byte(caCert))
	if block == nil {
		return "", errors.New("Perimeter has no host certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}
	key, err := jwk.Import(certificate.PublicKey)
	if err != nil {
		return "", err
	}
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", err
	}
	return "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" + base64.RawURLEncoding.EncodeToString(thumbprint), nil
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
