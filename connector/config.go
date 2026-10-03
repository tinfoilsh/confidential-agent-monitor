package connector

import (
	"bytes"
	"encoding/json"
	"net/url"

	"github.com/tinfoilsh/monitor/connector/credential"
)

func Decode(raw json.RawMessage, dst any) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}

type Endpoint struct {
	url.URL  `json:"-"`
	Address  string           `json:"url"`
	User     string           `json:"user"`
	Password credential.Value `json:"password"`
}

func (e *Endpoint) Fields() []Field {
	return []Field{{Path: []string{"password"}, Value: &e.Password, Redact: true}}
}

func (e *Endpoint) UnmarshalJSON(raw []byte) error {
	type plain Endpoint
	if err := Decode(raw, (*plain)(e)); err != nil {
		return err
	}
	u, err := ParseURL(e.Address)
	if err != nil {
		return err
	}
	if e.User != "" {
		u.User = url.User(e.User)
	}
	e.URL = *u
	return nil
}

// Field identifies a config path and its disclosure metadata.
// Value points to the live credential, or is nil for plain strings such as keys.
type Field struct {
	Path   []string
	Value  *credential.Value
	Redact bool
}
