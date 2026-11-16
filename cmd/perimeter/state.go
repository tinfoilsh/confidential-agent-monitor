package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
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

// State: the encrypted document, its settings, records and admissions.

const (
	stateObject = "monitor.enc"
	caName      = "perimeter dev CA"
	caLifetime  = 10 * 365 * 24 * time.Hour
	// Connection leaves are minted per handshake.
	leafLifetime = 24 * time.Hour
	leafBackdate = time.Hour
)

// Settled records are batched into immutable segments named by upload time, so
// storage credentials never need delete or overwrite access to the log.
var auditLimits = sealedlog.Limits{FlushInterval: time.Minute, WriteTimeout: 30 * time.Second, SegmentBytes: 8 << 20, MaxBacklog: 64 << 20, PageRecords: 200}

var errOwner error = httpError{format.ErrKey, http.StatusUnauthorized}

// state is the running Perimeter. mu guards the document, records and admissions, and
// approval waits release it; writes serializes settings preparation, commit, delivery and
// final teardown. When both are needed, take writes before mu. The table's lock is taken
// inside either. Everything unlock creates is nil while locked. Only this file takes mu or
// writes; the others go through locked, stable and writeSettings.
type state struct {
	bucket     *blob.Bucket
	life       context.Context // ends the audit log's flushing
	flushing   sync.WaitGroup
	mu         sync.Mutex
	writes     sync.Mutex
	doc        format.Document
	owner      []byte
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

// locked runs fn under s.mu.
func (s *state) locked(fn func()) {
	s.mu.Lock()
	defer s.mu.Unlock()
	fn()
}

// stable runs fn with the document and settings no settings write replaces before it returns.
func stable[T any](s *state, fn func(format.Document, *settings) (T, error)) (T, error) {
	s.writes.Lock()
	defer s.writes.Unlock()
	return fn(s.snapshot())
}

// writeSettings is the single ordered settings path. It holds s.writes throughout, and s.mu
// around its checks and its commit.
func (s *state) writeSettings(ctx context.Context, w settingsWrite) error {
	s.writes.Lock()
	defer s.writes.Unlock()
	s.mu.Lock()
	source, current := s.doc.Policy, s.settings.Load()
	var err error
	if w.derive != nil {
		w.changes, err = w.derive()
	}
	if err == nil && policyFile != "" && (w.source != nil || len(w.changes) != 0) {
		err = errPolicyFile
	}
	if err == nil {
		err = w.checked()
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
	plan, err := s.prepareSettings(ctx, source, rebuild, renamed, w.credentials, current.tls, current.hostKey)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if err = w.checked(); err == nil {
		err = s.commitSettings(ctx, plan, w.saved)
	}
	if source != before || len(w.credentials) != 0 {
		s.recordAdmin(ctx, "Change settings", map[string]any{"policy": policyDiff{SourceDiff: sourceDiff(before, source)}, "credentials": slices.Sorted(maps.Keys(w.credentials))}, err)
	}
	s.mu.Unlock()
	if err == nil {
		s.table.Start()
	}
	return err
}

// commit changes the document only after the encrypted write succeeds.
func (s *state) commit(ctx context.Context, next format.Document) error {
	next.Generation++
	plain, err := format.EncodeDocument(next)
	if err != nil {
		return err
	}
	if err := s.bucket.WriteAll(ctx, stateObject, s.sealer.SealState(plain), nil); err != nil {
		return err
	}
	s.doc = next
	return nil
}

// load reads the stored document with key, or starts one if storage confirms there is none and
// no generation was saved. It changes nothing and rejects rollback below minimum.
func (s *state) load(ctx context.Context, key []byte, minimum uint64) (format.Document, format.Sealer, bool, error) {
	var doc format.Document
	if len(key) < format.MinKeyBytes || len(key) > format.MaxKeyBytes {
		return doc, format.Sealer{}, false, errOwner
	}
	raw, err := s.bucket.ReadAll(ctx, stateObject)
	missing := false
	if err != nil {
		if missing, err = stateMissing(ctx, s.bucket, err); err != nil {
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

// v1Presets tells the version 1 upgrade which presets declare a connection.
func v1Presets() map[string]bool {
	declared := map[string]bool{}
	for name, p := range presets {
		declared[name] = p.Catalog.Connection != nil
	}
	return declared
}

// stateMissing confirms that a failed read means no state exists. S3 hides missing
// objects behind AccessDenied when ListBucket is scoped by prefix, so absence is
// confirmed with an authorized prefix listing. A denied listing or an existing
// unreadable object must never reset the state.
func stateMissing(ctx context.Context, bucket *blob.Bucket, err error) (bool, error) {
	switch gcerrors.Code(err) {
	case gcerrors.NotFound:
		return true, nil
	case gcerrors.PermissionDenied:
		items := bucket.List(&blob.ListOptions{Prefix: stateObject})
		for {
			item, listErr := items.Next(ctx)
			if errors.Is(listErr, io.EOF) {
				return true, nil
			}
			if listErr != nil {
				return false, errors.Join(err, listErr)
			}
			if item.Key == stateObject {
				return false, err
			}
		}
	}
	return false, err
}

// stateExists reports whether state is stored; a failed probe is never absence.
func stateExists(ctx context.Context, bucket *blob.Bucket) (bool, error) {
	_, err := bucket.Attributes(ctx, stateObject)
	if err == nil {
		return true, nil
	}
	missing, err := stateMissing(ctx, bucket, err)
	return !missing, err
}

func (s *state) isOwnerKey(key []byte) bool { return subtle.ConstantTimeCompare(key, s.owner) == 1 }

// unlock reports whether it created the Perimeter's state.
func (s *state) unlock(ctx context.Context, key []byte, minimum uint64) (bool, error) {
	s.writes.Lock()
	defer s.writes.Unlock()
	s.mu.Lock()
	if !passphraseKeys && len(key) != format.KeyBytes {
		s.mu.Unlock()
		return false, errOwner
	}
	if s.settings.Load() != nil {
		defer s.mu.Unlock()
		if !s.isOwnerKey(key) {
			return false, errOwner
		}
		if generation := s.doc.Generation; generation < minimum {
			return false, fmt.Errorf("live generation %d is older than %d", generation, minimum)
		}
		return false, nil
	}
	s.mu.Unlock()
	doc, sealer, created, err := s.load(ctx, key, minimum)
	if err != nil {
		return false, err
	}
	tlsConfig, err := connectionTLS(&doc.Keys)
	if err != nil {
		return false, err
	}
	signer := sshHostKey
	if signer == nil {
		if signer, err = storedHostKey(&doc.Keys); err != nil {
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
	plan, err := s.prepareSettings(ctx, source, everyConnection, nil, nil, tlsConfig, signer)
	if err != nil {
		return false, err
	}
	s.mu.Lock()
	s.doc = doc
	s.owner, s.sealer = bytes.Clone(key), sealer
	s.audit = sealedlog.New(sealedlog.Storage{Write: s.bucketWrite, Read: s.bucket.ReadAll, List: s.bucketList}, auditPrefix, auditLimits, sealer.Seal, sealer.Open,
		func(err error) { log.Printf("audit: %v", err) })
	err = s.commitSettings(ctx, plan, nil)
	if err != nil {
		s.doc = format.Document{}
		s.owner, s.sealer, s.audit = nil, format.Sealer{}, nil
	} else {
		s.flushing.Go(func() { s.audit.Run(s.life) })
		s.recordAdmin(ctx, "Unlock", nil, nil)
	}
	s.mu.Unlock()
	if err != nil {
		return false, err
	}
	s.table.Start()
	return created, nil
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

// close stops connectors and waits for the audit log's final flush once life has ended.
func (s *state) close() {
	s.writes.Lock()
	defer s.writes.Unlock()
	s.table.Close()
	s.flushing.Wait()
}

// isOwner reports whether key is a well-formed storage key and, once unlocked, the owner's.
// While locked any well-formed key passes; only unlock can check a key then.
func (s *state) isOwner(key []byte) bool {
	if len(key) < format.MinKeyBytes || len(key) > format.MaxKeyBytes {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.settings.Load() == nil || s.isOwnerKey(key)
}

// connectionTLS mints connection leaves from the stored CA, creating it if keys have none.
func connectionTLS(keys *format.Keys) (*tls.Config, error) {
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

// storedHostKey is the stored SSH host key, created if keys have none.
func storedHostKey(keys *format.Keys) (ssh.Signer, error) {
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
