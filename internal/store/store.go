// Package store keeps the Monitor's encrypted state document and seals the objects stored beside it.
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
	"gocloud.dev/blob"
	"gocloud.dev/gcerrors"
	"golang.org/x/crypto/argon2"
)

const (
	stateObject  = "monitor.enc"
	stateVersion = 1 // JSON format version, independent of encryption and Generation.
)

var ErrOwner = errors.New("invalid owner secret")
var ErrMissingState = errors.New("the Monitor has no saved state; initialize it to create one")

// Document is the state encrypted in storage.
// Labels are shared by all streams authenticated with the same SSH fingerprint.
type Document struct {
	Version    int                    `json:"version"`
	Generation uint64                 `json:"generation"`
	Keys       Keys                   `json:"keys"`
	Labels     map[string]facts.Label `json:"labels"`
	Policy     string                 `json:"policy"`
	Secrets    Secrets                `json:"secrets,omitempty"`
	Enrolled   map[string]bool        `json:"enrolled,omitempty"`
}

// decodeState reads documents written before versioning as version 1, which names
// their layout. A new version needs its migration here before it is accepted.
func decodeState(plain []byte) (Document, error) {
	var sl Document
	if err := json.Unmarshal(plain, &sl); err != nil {
		return Document{}, fmt.Errorf("stored state: %w", err)
	}
	if sl.Version == 0 {
		sl.Version = 1
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

// Load returns a candidate without changing the current store or initializing storage.
func (s Store) Load(ctx context.Context, key []byte, minimum uint64, initialize bool) (Store, error) {
	if len(key) < MinOwnerKeyBytes || len(key) > MaxOwnerKeyBytes {
		return s, ErrOwner
	}
	sl := Document{Version: stateVersion, Labels: map[string]facts.Label{}}
	raw, err := s.Bucket.ReadAll(ctx, stateObject)
	missing := gcerrors.Code(err) == gcerrors.NotFound
	// S3 hides missing objects behind AccessDenied when ListBucket is scoped
	// by prefix. Confirm absence with an authorized prefix listing. A denied
	// listing or an existing unreadable object must never reset the state.
	if gcerrors.Code(err) == gcerrors.PermissionDenied && minimum == 0 {
		items := s.Bucket.List(&blob.ListOptions{Prefix: stateObject})
		for {
			item, listErr := items.Next(ctx)
			if errors.Is(listErr, io.EOF) {
				missing = true
				break
			}
			if listErr != nil {
				return s, errors.Join(err, listErr)
			}
			if item.Key == stateObject {
				break
			}
		}
	}
	if err != nil && missing && minimum == 0 && !initialize {
		return s, ErrMissingState
	}
	if err != nil && (!missing || minimum != 0 || !initialize) {
		return s, err
	}
	storageKey, header, keyErr := stateEncryptionKey(key, raw, missing && minimum == 0)
	if keyErr != nil {
		return s, keyErr
	}
	block, keyErr := aes.NewCipher(storageKey)
	clear(storageKey)
	if keyErr != nil {
		return s, keyErr
	}
	aead, keyErr := cipher.NewGCMWithRandomNonce(block)
	if keyErr != nil {
		return s, keyErr
	}
	if !missing || minimum != 0 {
		plain, err := aead.Open(nil, nil, raw[len(header):], header)
		if err != nil {
			return s, ErrOwner
		}
		sl, err = decodeState(plain)
		if err != nil {
			return s, err
		}
	}
	if sl.Generation < minimum {
		return s, fmt.Errorf("stored generation %d is older than %d", sl.Generation, minimum)
	}
	s.Doc, s.owner, s.Sealer, s.header = sl, bytes.Clone(key), Sealer{aead}, header
	return s, nil
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

type SecretID struct{ Account, Connection, Name string }

type Secrets map[SecretID]json.RawMessage

// storedSecrets is the document layout: values by account, connection and name.
type storedSecrets map[string]map[string]map[string]json.RawMessage

func (s Secrets) MarshalJSON() ([]byte, error) {
	stored := storedSecrets{}
	for id, raw := range s {
		if stored[id.Account] == nil {
			stored[id.Account] = map[string]map[string]json.RawMessage{}
		}
		if stored[id.Account][id.Connection] == nil {
			stored[id.Account][id.Connection] = map[string]json.RawMessage{}
		}
		stored[id.Account][id.Connection][id.Name] = raw
	}
	return json.Marshal(stored)
}

func (s *Secrets) UnmarshalJSON(raw []byte) error {
	var stored storedSecrets
	if err := json.Unmarshal(raw, &stored); err != nil {
		return err
	}
	*s = Secrets{}
	for account, connections := range stored {
		for connection, values := range connections {
			for name, value := range values {
				(*s)[SecretID{account, connection, name}] = value
			}
		}
	}
	return nil
}

func (s Secrets) Clone() Secrets { return maps.Collect(maps.All(s)) }

// Connection returns one connection's values by name.
func (s Secrets) Connection(account, connection string) map[string]json.RawMessage {
	values := map[string]json.RawMessage{}
	for id, raw := range s {
		if id.Account == account && id.Connection == connection {
			values[id.Name] = raw
		}
	}
	return values
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
