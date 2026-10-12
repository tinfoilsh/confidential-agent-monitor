package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	minOwnerKeyBytes = 16
	maxOwnerKeyBytes = 4096
	// Existing generated credentials and SHA-256 owner bindings used 32 bytes.
	ownerKeyBytes       = 32
	ownerArgonPHCPrefix = "$argon2id$v=19$m=262144,t=3,p=4$"
)

type ownerCommitment struct {
	hash []byte
	salt []byte // A nil salt identifies an existing SHA-256 binding.
}

func parseOwnerCommitment(legacy, phc string) (*ownerCommitment, error) {
	if (legacy == "") == (phc == "") {
		return nil, errors.New("set exactly one of MONITOR_OWNER_KEY_SHA256 and MONITOR_OWNER_KEY_ARGON2ID")
	}
	if legacy != "" {
		hash, err := hex.DecodeString(legacy)
		if err != nil || len(hash) != sha256.Size {
			return nil, errors.New("MONITOR_OWNER_KEY_SHA256 must be a SHA-256 digest in hex")
		}
		return &ownerCommitment{hash: hash}, nil
	}
	invalid := errors.New("MONITOR_OWNER_KEY_ARGON2ID must use Argon2id v19 m=262144,t=3,p=4 with a 32-byte salt and verifier")
	if !strings.HasPrefix(phc, ownerArgonPHCPrefix) {
		return nil, invalid
	}
	parts := strings.Split(strings.TrimPrefix(phc, ownerArgonPHCPrefix), "$")
	if len(parts) != 2 {
		return nil, invalid
	}
	decode := func(value string) ([]byte, error) {
		decoded, err := base64.RawStdEncoding.Strict().DecodeString(value)
		if err != nil || len(decoded) != sha256.Size || base64.RawStdEncoding.EncodeToString(decoded) != value {
			return nil, invalid
		}
		return decoded, nil
	}
	salt, err := decode(parts[0])
	if err != nil {
		return nil, err
	}
	hash, err := decode(parts[1])
	if err != nil {
		return nil, err
	}
	return &ownerCommitment{salt: salt, hash: hash}, nil
}

// matches runs under the Monitor mutex to bound Argon2 memory use. The public
// commitment is never used as the private state encryption key.
func (o *ownerCommitment) matches(key []byte) bool {
	if o == nil || len(key) < minOwnerKeyBytes || len(key) > maxOwnerKeyBytes {
		return false
	}
	if o.salt == nil {
		if len(key) != ownerKeyBytes {
			return false
		}
		hash := sha256.Sum256(key)
		return subtle.ConstantTimeCompare(o.hash, hash[:]) == 1
	}
	hash := argon2.IDKey(key, o.salt, 3, 256<<10, 4, 32)
	defer clear(hash)
	return subtle.ConstantTimeCompare(o.hash, hash) == 1
}
