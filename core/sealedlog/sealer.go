package sealedlog

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/argon2"
)

const (
	MinKeyBytes = 16
	MaxKeyBytes = 4096
	KeyBytes    = 32

	saltBytes    = 32
	sealOverhead = 12 + 16
	argonTime    = 3
	argonMemory  = 256 << 10
	argonThreads = 4
)

var (
	ErrKey     = errors.New("invalid secret")
	stateMagic = []byte("TINFOIL-MONITOR-STATE\x00\x01")
)

type Sealer struct {
	aead   cipher.AEAD
	header []byte
}

// A secret of KeyBytes is the key; any other is stretched with a salt that SealState writes ahead of the state.
func NewSealer(secret []byte) (Sealer, error) {
	if len(secret) == KeyBytes {
		return sealer(secret, nil)
	}
	header := make([]byte, len(stateMagic)+saltBytes)
	copy(header, stateMagic)
	if _, err := rand.Read(header[len(stateMagic):]); err != nil {
		return Sealer{}, err
	}
	return sealer(secret, header)
}

func OpenState(secret, raw []byte) (Sealer, []byte, error) {
	var header []byte
	if bytes.HasPrefix(raw, stateMagic) {
		if len(raw) < len(stateMagic)+saltBytes+sealOverhead {
			return Sealer{}, nil, ErrKey
		}
		header = bytes.Clone(raw[:len(stateMagic)+saltBytes])
	}
	s, err := sealer(secret, header)
	if err != nil {
		return s, nil, err
	}
	plain, err := s.aead.Open(nil, nil, raw[len(s.header):], s.header)
	if err != nil {
		return Sealer{}, nil, ErrKey
	}
	return s, plain, nil
}

func sealer(secret, header []byte) (Sealer, error) {
	if len(secret) < MinKeyBytes || len(secret) > MaxKeyBytes {
		return Sealer{}, ErrKey
	}
	var key []byte
	if header != nil {
		key = argon2.IDKey(secret, header[len(stateMagic):], argonTime, argonMemory, argonThreads, KeyBytes)
	} else if len(secret) == KeyBytes {
		key = bytes.Clone(secret)
	} else {
		return Sealer{}, ErrKey
	}
	block, err := aes.NewCipher(key)
	clear(key)
	if err != nil {
		return Sealer{}, err
	}
	aead, err := cipher.NewGCMWithRandomNonce(block)
	if err != nil {
		return Sealer{}, err
	}
	return Sealer{aead, header}, nil
}

func (s Sealer) SealState(plain []byte) []byte {
	return s.aead.Seal(bytes.Clone(s.header), nil, plain, s.header)
}

func (s Sealer) Seal(name string, plain []byte) []byte {
	return s.aead.Seal(nil, nil, plain, []byte(name))
}

func (s Sealer) Open(name string, sealed []byte) ([]byte, error) {
	return s.aead.Open(nil, nil, sealed, []byte(name))
}
