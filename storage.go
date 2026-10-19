package main

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"iter"

	"github.com/tinfoilsh/monitor/facts"
	"gocloud.dev/blob"
	"gocloud.dev/gcerrors"
)

const (
	stateObject  = "monitor.enc"
	stateVersion = 1 // JSON format version, independent of encryption and Generation.
)

var errOwner = errors.New("invalid owner secret")

// sealed is the document encrypted in storage.
// Labels are shared by all streams authenticated with the same SSH fingerprint.
type sealed struct {
	Version    int                    `json:"version"`
	Generation uint64                 `json:"generation"`
	Keys       keyMaterial            `json:"keys"`
	Labels     map[string]facts.Label `json:"labels"`
	Policy     string                 `json:"policy"`
	Secrets    secretStore            `json:"secrets,omitempty"`
	Enrolled   map[string]bool        `json:"enrolled,omitempty"`
}

// decodeState migrates the decrypted document before decoding today's types.
// Each case upgrades one shipped version to the next. Keep transformations here
// so future field/type changes do not prevent older documents from being read.
// Persistence belongs to the normal validated commit, never to a migration.
func decodeState(plain []byte) (sealed, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(plain, &fields); err != nil {
		return sealed{}, fmt.Errorf("stored state: %w", err)
	}
	if fields == nil {
		return sealed{}, errors.New("stored state must be an object")
	}
	version := 0 // Deployed documents have no version field.
	if raw, ok := fields["version"]; ok {
		var stored *int
		if err := json.Unmarshal(raw, &stored); err != nil {
			return sealed{}, fmt.Errorf("stored state version: %w", err)
		}
		if stored == nil {
			return sealed{}, errors.New("stored state version must be an integer")
		}
		version = *stored
	}
	if version < 0 || version > stateVersion {
		return sealed{}, fmt.Errorf("unsupported stored state version %d (latest supported: %d)", version, stateVersion)
	}
	for version < stateVersion {
		switch version {
		case 0:
			// Version 1 names the existing layout; keys, credentials, labels,
			// policy and enrollment history retain their deployed formats.
			fields["version"] = json.RawMessage(`1`)
		default:
			return sealed{}, fmt.Errorf("no migration from stored state version %d", version)
		}
		version++
	}
	plain, err := json.Marshal(fields)
	if err != nil {
		return sealed{}, fmt.Errorf("migrated state: %w", err)
	}
	var sl sealed
	if err := json.Unmarshal(plain, &sl); err != nil {
		return sealed{}, fmt.Errorf("stored state: %w", err)
	}
	return sl, nil
}

// stateStore owns the last committed document and its encryption state.
// The monitor's authorization lock serializes loads and commits with runtime changes.
type stateStore struct {
	bucket *blob.Bucket
	doc    sealed
	owner  []byte
	aead   cipher.AEAD
	header []byte
}

// load returns a candidate without changing the current store or initializing storage.
func (s stateStore) load(ctx context.Context, key []byte, minimum uint64, initialize bool) (stateStore, error) {
	if len(key) < minOwnerKeyBytes || len(key) > maxOwnerKeyBytes {
		return s, errOwner
	}
	sl := sealed{Version: stateVersion, Labels: map[string]facts.Label{}}
	raw, err := s.bucket.ReadAll(ctx, stateObject)
	missing := gcerrors.Code(err) == gcerrors.NotFound
	// S3 hides missing objects behind AccessDenied when ListBucket is scoped
	// by prefix. Confirm absence with an authorized prefix listing. A denied
	// listing or an existing unreadable object must never reset the state.
	if gcerrors.Code(err) == gcerrors.PermissionDenied && minimum == 0 {
		items := s.bucket.List(&blob.ListOptions{Prefix: stateObject})
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
			return s, errOwner
		}
		sl, err = decodeState(plain)
		if err != nil {
			return s, err
		}
	}
	if sl.Generation < minimum {
		return s, fmt.Errorf("stored generation %d is older than %d", sl.Generation, minimum)
	}
	s.doc, s.owner, s.aead, s.header = sl, bytes.Clone(key), aead, header
	return s, nil
}

// commit changes the document only after the encrypted write succeeds.
func (s *stateStore) commit(ctx context.Context, next sealed) error {
	next.Version = stateVersion
	next.Generation++
	plain, err := json.Marshal(next)
	if err != nil {
		return err
	}
	if err := s.bucket.WriteAll(ctx, stateObject, s.aead.Seal(bytes.Clone(s.header), nil, plain, s.header), nil); err != nil {
		return err
	}
	s.doc = next
	return nil
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
