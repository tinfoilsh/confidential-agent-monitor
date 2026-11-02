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
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/s3"
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
	Bucket    *blob.Bucket
	BucketURL string
	Doc       Document
	owner     []byte
	Sealer
	header []byte
	etag   string
}

type Sealer struct{ aead cipher.AEAD }

// Load returns a candidate without changing the current store or writing storage, and
// whether it is new. Only confirmed absence with no saved minimum starts new state.
func (s Store) Load(ctx context.Context, key []byte, minimum uint64) (Store, bool, error) {
	if len(key) < MinOwnerKeyBytes || len(key) > MaxOwnerKeyBytes {
		return s, false, ErrOwner
	}
	sl := Document{Version: stateVersion, Labels: map[string]facts.Label{}}
	reader, err := s.Bucket.NewReader(ctx, stateObject, nil)
	var raw []byte
	s.etag = ""
	if err == nil {
		var object s3.GetObjectOutput
		if reader.As(&object) {
			s.etag = aws.ToString(object.ETag)
			if s.etag == "" {
				reader.Close()
				return s, false, errors.New("state read returned no ETag")
			}
		}
		raw, err = io.ReadAll(reader)
		err = errors.Join(err, reader.Close())
	}
	missing := false
	if err != nil {
		if missing, err = s.missing(ctx, err); err != nil {
			return s, false, err
		}
	}
	if missing && minimum != 0 {
		return s, false, fmt.Errorf("the Monitor has no saved state, but generation %d was saved", minimum)
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
	sealed := s.aead.Seal(bytes.Clone(s.header), nil, plain, s.header)
	var client *s3.Client
	if s.Bucket.As(&client) {
		// Use the ETag from the exact document loaded, then the successful PUT
		// response. A HEAD after writing could pick up another writer's ETag.
		u, err := url.Parse(s.BucketURL)
		if err != nil || u.Scheme != "s3" || u.Host == "" {
			return errors.New("missing S3 state binding")
		}
		input := &s3.PutObjectInput{Bucket: aws.String(u.Host), Key: aws.String(u.Query().Get("prefix") + stateObject), Body: bytes.NewReader(sealed)}
		if s.etag == "" {
			input.IfNoneMatch = aws.String("*")
		} else {
			input.IfMatch = aws.String(s.etag)
		}
		result, err := client.PutObject(ctx, input)
		if err != nil {
			return fmt.Errorf("commit state: %w", err)
		}
		if result.ETag == nil || strings.TrimSpace(*result.ETag) == "" {
			return errors.New("state write returned no ETag")
		}
		s.etag = *result.ETag
	} else if err := s.Bucket.WriteAll(ctx, stateObject, sealed, nil); err != nil {
		return err
	}
	s.Doc = next
	return nil
}

type SecretID struct{ Account, Connection, Name string }

// Secrets uses the deployed document layout: account, connection and name.
type Secrets map[string]map[string]map[string]json.RawMessage

func (s Secrets) Get(id SecretID) json.RawMessage { return s[id.Account][id.Connection][id.Name] }

// Set removes empty parents with the last value, preserving the stored layout.
func (s Secrets) Set(id SecretID, raw json.RawMessage) {
	if raw != nil {
		if s[id.Account] == nil {
			s[id.Account] = map[string]map[string]json.RawMessage{}
		}
		if s[id.Account][id.Connection] == nil {
			s[id.Account][id.Connection] = map[string]json.RawMessage{}
		}
		s[id.Account][id.Connection][id.Name] = raw
		return
	}
	delete(s[id.Account][id.Connection], id.Name)
	if len(s[id.Account][id.Connection]) == 0 {
		delete(s[id.Account], id.Connection)
	}
	if len(s[id.Account]) == 0 {
		delete(s, id.Account)
	}
}

// Clone isolates edits at every map level; credential records are immutable bytes.
func (s Secrets) Clone() Secrets {
	out := Secrets{}
	for account, connections := range s {
		out[account] = maps.Clone(connections)
		for connection, values := range connections {
			out[account][connection] = maps.Clone(values)
		}
	}
	return out
}

func (s Secrets) Connection(account, connection string) map[string]json.RawMessage {
	return s[account][connection]
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
