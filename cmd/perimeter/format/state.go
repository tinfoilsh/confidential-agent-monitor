package format

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"maps"

	"golang.org/x/crypto/argon2"
)

const (
	StateVersion = 2
	MinKeyBytes  = 16
	MaxKeyBytes  = 4096
	KeyBytes     = 32

	saltBytes    = 32
	sealOverhead = 12 + 16
	argonTime    = 3
	argonMemory  = 256 << 10
	argonThreads = 4
)

var ErrKey = errors.New("invalid owner secret")

type Keys struct {
	HostKey string `json:"host_key"`
	CACert  string `json:"ca_cert"`
	CAKey   string `json:"ca_key"`
}

type Label struct {
	Audience string            `json:"audience"`
	Trust    string            `json:"trust"`
	Because  map[string]string `json:"because,omitempty"`
}

type Document struct {
	Version     int              `json:"version"`
	Generation  uint64           `json:"generation"`
	Revision    uint64           `json:"revision"`
	Keys        Keys             `json:"keys"`
	Labels      map[string]Label `json:"labels"`
	Policy      string           `json:"policy"`
	Credentials Secrets          `json:"credentials,omitempty"`
	Enrolled    map[string]bool  `json:"enrolled,omitempty"`
}

func DecodeDocument(plain []byte, v1Presets map[string]bool) (Document, error) {
	plain, err := upgrade(plain, v1Presets)
	if err != nil {
		return Document{}, fmt.Errorf("stored state: %w", err)
	}
	var d Document
	if err := json.Unmarshal(plain, &d); err != nil {
		return Document{}, fmt.Errorf("stored state: %w", err)
	}
	if d.Version != StateVersion {
		return Document{}, fmt.Errorf("unsupported stored state version %d (latest supported: %d)", d.Version, StateVersion)
	}
	return d, nil
}

func EncodeDocument(d Document) ([]byte, error) {
	d.Version = StateVersion
	return json.Marshal(d)
}

type Sealer struct {
	aead   cipher.AEAD
	header []byte
}

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

type SecretID struct{ Connection, Name string }

type Secrets map[string]map[string]json.RawMessage

func (s Secrets) Get(id SecretID) json.RawMessage { return s[id.Connection][id.Name] }

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

func (s Secrets) Clone() Secrets {
	out := Secrets{}
	for connection, values := range s {
		out[connection] = maps.Clone(values)
	}
	return out
}

var stateMagic = []byte("TINFOIL-MONITOR-STATE\x00\x01")
