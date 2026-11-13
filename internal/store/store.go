// Package store keeps the Monitor's encrypted state document and append-only audit log.
package store

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"

	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/internal/store/migrations"
	"gocloud.dev/blob"
	"gocloud.dev/gcerrors"
	"golang.org/x/crypto/argon2"
)

const (
	stateObject  = "monitor.enc"
	stateVersion = migrations.Version // JSON format version, independent of encryption and Generation.
)

var ErrOwner = errors.New("invalid owner secret")

// Document is the state encrypted in storage.
// Labels are shared by all streams authenticated with the same SSH fingerprint.
type Document struct {
	Version     int                    `json:"version"`
	Generation  uint64                 `json:"generation"`
	Revision    uint64                 `json:"revision"` // Counts settings writes; owner writes name the one they reviewed.
	Keys        Keys                   `json:"keys"`
	Labels      map[string]facts.Label `json:"labels"`
	Policy      string                 `json:"policy"`
	Credentials Secrets                `json:"credentials,omitempty"`
	Enrolled    map[string]bool        `json:"enrolled,omitempty"`
}

// decodeState reads earlier versions through their migration before accepting a document.
func decodeState(plain []byte) (Document, error) {
	plain, err := migrations.Upgrade(plain)
	if err != nil {
		return Document{}, fmt.Errorf("stored state: %w", err)
	}
	var sl Document
	if err := json.Unmarshal(plain, &sl); err != nil {
		return Document{}, fmt.Errorf("stored state: %w", err)
	}
	if sl.Version != stateVersion {
		return Document{}, fmt.Errorf("unsupported stored state version %d (latest supported: %d)", sl.Version, stateVersion)
	}
	return sl, nil
}

// Store owns the last committed document and its encryption state.
// The monitor's authorization lock serializes loads and commits with runtime changes.
type Store struct {
	Bucket *blob.Bucket
	Doc    Document
	owner  []byte
	Sealer
	header []byte
}

type Sealer struct{ aead cipher.AEAD }

// Load returns a candidate without changing the current store or writing storage, and
// whether it is new. Only confirmed absence with no saved minimum starts new state.
func (s Store) Load(ctx context.Context, key []byte, minimum uint64) (Store, bool, error) {
	if len(key) < MinOwnerKeyBytes || len(key) > MaxOwnerKeyBytes {
		return s, false, ErrOwner
	}
	sl := Document{Version: stateVersion, Labels: map[string]facts.Label{}}
	raw, err := s.Bucket.ReadAll(ctx, stateObject)
	missing := false
	if err != nil {
		if missing, err = s.missing(ctx, err); err != nil {
			return s, false, err
		}
	}
	if missing && minimum != 0 {
		return s, false, fmt.Errorf("the Perimeter has no saved state, but generation %d was saved", minimum)
	}
	storageKey, header, keyErr := stateEncryptionKey(key, raw, missing)
	if keyErr != nil {
		return s, false, keyErr
	}
	block, keyErr := aes.NewCipher(storageKey)
	clear(storageKey)
	if keyErr != nil {
		return s, false, keyErr
	}
	aead, keyErr := cipher.NewGCMWithRandomNonce(block)
	if keyErr != nil {
		return s, false, keyErr
	}
	if !missing {
		plain, err := aead.Open(nil, nil, raw[len(header):], header)
		if err != nil {
			return s, false, ErrOwner
		}
		sl, err = decodeState(plain)
		if err != nil {
			return s, false, err
		}
	}
	// Reject stored state rollback.
	if sl.Generation < minimum {
		return s, false, fmt.Errorf("stored generation %d is older than %d", sl.Generation, minimum)
	}
	s.Doc, s.owner, s.Sealer, s.header = sl, bytes.Clone(key), Sealer{aead}, header
	return s, missing, nil
}

// Exists reports whether state is stored; a failed probe is never absence.
func (s Store) Exists(ctx context.Context) (bool, error) {
	_, err := s.Bucket.Attributes(ctx, stateObject)
	if err == nil {
		return true, nil
	}
	missing, err := s.missing(ctx, err)
	return !missing, err
}

// missing confirms that a failed read means no state exists. S3 hides missing
// objects behind AccessDenied when ListBucket is scoped by prefix, so absence is
// confirmed with an authorized prefix listing. A denied listing or an existing
// unreadable object must never reset the state.
func (s Store) missing(ctx context.Context, err error) (bool, error) {
	switch gcerrors.Code(err) {
	case gcerrors.NotFound:
		return true, nil
	case gcerrors.PermissionDenied:
		items := s.Bucket.List(&blob.ListOptions{Prefix: stateObject})
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

func (s Store) IsOwner(key []byte) bool { return subtle.ConstantTimeCompare(key, s.owner) == 1 }

// Seal encrypts an object stored beside the document; its name is the associated data.
func (s Sealer) Seal(name string, plain []byte) []byte {
	return s.aead.Seal(nil, nil, plain, []byte(name))
}

func (s Sealer) Open(name string, sealed []byte) ([]byte, error) {
	return s.aead.Open(nil, nil, sealed, []byte(name))
}

// Commit changes the document only after the encrypted write succeeds.
func (s *Store) Commit(ctx context.Context, next Document) error {
	next.Version = stateVersion
	next.Generation++
	plain, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err := s.Bucket.WriteAll(ctx, stateObject, s.aead.Seal(bytes.Clone(s.header), nil, plain, s.header), nil); err != nil {
		return err
	}
	s.Doc = next
	return nil
}

type SecretID struct{ Connection, Name string }

// Secrets maps each connection to its named credential records.
type Secrets map[string]map[string]json.RawMessage

func (s Secrets) Get(id SecretID) json.RawMessage { return s[id.Connection][id.Name] }

// Set removes a connection with its last value.
func (s Secrets) Set(id SecretID, raw json.RawMessage) {
	if raw != nil {
		if s[id.Connection] == nil {
			s[id.Connection] = map[string]json.RawMessage{}
		}
		s[id.Connection][id.Name] = raw
		return
	}
	delete(s[id.Connection], id.Name)
	if len(s[id.Connection]) == 0 {
		delete(s, id.Connection)
	}
}

// Clone isolates edits at every map level; credential records are immutable bytes.
func (s Secrets) Clone() Secrets {
	out := Secrets{}
	for connection, values := range s {
		out[connection] = maps.Clone(values)
	}
	return out
}

const (
	MinOwnerKeyBytes = 16
	MaxOwnerKeyBytes = 4096
	OwnerKeyBytes    = 32
)

// Local development passphrases use a versioned state format with a random salt.
var stateMagic = []byte("TINFOIL-MONITOR-STATE\x00\x01")

func stateEncryptionKey(secret, raw []byte, create bool) (key, header []byte, err error) {
	if create && len(secret) != OwnerKeyBytes {
		header = make([]byte, len(stateMagic)+32)
		copy(header, stateMagic)
		if _, err := rand.Read(header[len(stateMagic):]); err != nil {
			return nil, nil, err
		}
	} else if !create && bytes.HasPrefix(raw, stateMagic) {
		if len(raw) < len(stateMagic)+32+12+16 {
			return nil, nil, ErrOwner
		}
		header = bytes.Clone(raw[:len(stateMagic)+32])
	} else {
		// Existing state retains its original format and AES key. Reading it
		// must not silently rekey it or make rollback to the old release fail.
		if len(secret) != OwnerKeyBytes {
			return nil, nil, ErrOwner
		}
		return bytes.Clone(secret), nil, nil
	}
	return argon2.IDKey(secret, header[len(stateMagic):], 3, 256<<10, 4, 32), header, nil
}
