package format

import (
	"bytes"
	"encoding/json"
	jsonv2 "encoding/json/v2"
	"errors"
)

var ErrCredentialShape = errors.New("credential must be a string, an oauth grant or a file under -secrets")

type Credential struct {
	Text  *string
	File  string
	OAuth json.RawMessage
}

func DecodeCredential(raw json.RawMessage) (Credential, error) {
	var c Credential
	if bytes.Equal(raw, []byte("null")) {
		return c, nil
	}
	var text string
	if json.Unmarshal(raw, &text) == nil {
		c.Text = &text
		return c, nil
	}
	var record struct {
		OAuth json.RawMessage `json:"oauth"`
		File  string          `json:"file"`
	}
	if err := jsonv2.Unmarshal(raw, &record, jsonv2.RejectUnknownMembers(true)); err != nil {
		return c, err
	}
	if bytes.Equal(record.OAuth, []byte("null")) {
		record.OAuth = nil
	}
	if (record.OAuth == nil) == (record.File == "") {
		return c, ErrCredentialShape
	}
	c.File, c.OAuth = record.File, record.OAuth
	return c, nil
}

func OAuthCredential(grant json.RawMessage) json.RawMessage {
	raw, _ := json.Marshal(map[string]json.RawMessage{"oauth": grant})
	return raw
}
