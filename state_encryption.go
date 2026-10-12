package main

import (
	"bytes"
	"crypto/rand"

	"golang.org/x/crypto/argon2"
)

const (
	minOwnerKeyBytes = 16
	maxOwnerKeyBytes = 4096
	ownerKeyBytes    = 32
)

// Local development passphrases use a versioned state format with a random salt.
var stateMagic = []byte("TINFOIL-MONITOR-STATE\x00\x01")

func stateEncryptionKey(secret, raw []byte, create bool) (key, header []byte, err error) {
	if create && len(secret) != ownerKeyBytes {
		header = make([]byte, len(stateMagic)+32)
		copy(header, stateMagic)
		if _, err := rand.Read(header[len(stateMagic):]); err != nil {
			return nil, nil, err
		}
	} else if !create && bytes.HasPrefix(raw, stateMagic) {
		if len(raw) < len(stateMagic)+32+12+16 {
			return nil, nil, errOwner
		}
		header = bytes.Clone(raw[:len(stateMagic)+32])
	} else {
		// Existing state retains its original format and AES key. Reading it
		// must not silently rekey it or make rollback to the old release fail.
		if len(secret) != ownerKeyBytes {
			return nil, nil, errOwner
		}
		return bytes.Clone(secret), nil, nil
	}
	return argon2.IDKey(secret, header[len(stateMagic):], 3, 256<<10, 4, 32), header, nil
}
