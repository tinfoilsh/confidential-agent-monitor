package format_test

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"testing"

	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/format"
)

// The fixtures were sealed by the deployed a188e35 store code.
func TestDeployedStateOpensDecodesAndReseals(t *testing.T) {
	want, err := os.ReadFile("testdata/document.json")
	if err != nil {
		t.Fatal(err)
	}
	for file, secret := range map[string][]byte{
		"testdata/legacy.bin":     bytes.Repeat([]byte{0x42}, 32),
		"testdata/passphrase.bin": []byte("fixture passphrase longer than thirty-two bytes"),
	} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		sealer, plain, err := format.OpenState(secret, raw)
		if err != nil || !bytes.Equal(plain, want) {
			t.Fatalf("%s: %s, %v", file, plain, err)
		}
		doc, err := format.DecodeDocument(plain, nil)
		if err != nil {
			t.Fatal(err)
		}
		if doc.Generation != 73 || doc.Revision != 11 || !doc.Enrolled["SHA256:removed"] || doc.Labels["SHA256:fixture"].Because["trust"] != "old request" {
			t.Fatalf("%s: %+v", file, doc)
		}
		records := doc.Credentials["service"]
		text, err := format.DecodeCredential(records["token"])
		if err != nil || text.Text == nil || *text.Text != "preserve-é" {
			t.Fatalf("%s: token %+v, %v", file, text, err)
		}
		if f, err := format.DecodeCredential(records["file"]); err != nil || f.File != "token.txt" || f.OAuth != nil {
			t.Fatalf("%s: file %+v, %v", file, f, err)
		}
		grant, err := format.DecodeCredential(records["oauth"])
		if err != nil || !bytes.Equal(format.OAuthCredential(grant.OAuth), records["oauth"]) {
			t.Fatalf("%s: oauth %s, %v", file, grant.OAuth, err)
		}

		encoded, err := format.EncodeDocument(doc)
		if err != nil {
			t.Fatal(err)
		}
		// A legacy key has no header; a passphrase keeps its salt header. The nonce and tag add 28 bytes.
		header := len(raw) - len(plain) - 28
		resealed := sealer.SealState(encoded)
		if len(resealed) != header+len(encoded)+28 || !bytes.Equal(resealed[:header], raw[:header]) {
			t.Fatalf("%s: format changed on reseal", file)
		}
		_, again, err := format.OpenState(secret, resealed)
		if err != nil {
			t.Fatalf("%s: reopen %v", file, err)
		}
		if reread, err := format.DecodeDocument(again, nil); err != nil || !reflect.DeepEqual(reread, doc) {
			t.Fatalf("%s: reread %+v, %v", file, reread, err)
		}
		corrupt := bytes.Clone(raw)
		corrupt[len(corrupt)-1] ^= 1
		if _, _, err := format.OpenState(secret, corrupt); !errors.Is(err, format.ErrKey) {
			t.Fatalf("%s: corrupt state %v", file, err)
		}
		if _, _, err := format.OpenState(bytes.Repeat([]byte{0x43}, 32), raw); !errors.Is(err, format.ErrKey) {
			t.Fatalf("%s: wrong key %v", file, err)
		}
	}
}

func TestVersion1AccountsBecomeConnections(t *testing.T) {
	v1 := map[string]any{
		"generation": 4,
		"policy": `[accounts.mail]
preset = "email"
contents = "me"
[accounts.mail.connections.imap.imap]
host = "imap.example.com"
[accounts.mail.connections.smtp.smtp]
host = "smtp.example.com"
[accounts.box]
preset = "fixture"
[accounts.box.connections.ssh.cli]
command = "true"
secrets = { KEY = {}, OTHER = {} }
[accounts.box.connections.extra.cli]
command = "false"
[default_access.mail]
level = "read"
[identities.agent.accounts.box]
level = "ask"
[identities.agent.rules.r1]
account = "mail"
action = "read"
`,
		"secrets": map[string]any{"mail": map[string]any{"imap": map[string]any{"password": "p"}}},
	}
	plain, _ := json.Marshal(v1)
	// fixture declares no connection, so each of its account connections is kept under its own name.
	doc, err := format.DecodeDocument(plain, map[string]bool{"email": true, "fixture": false})
	if err != nil {
		t.Fatal(err)
	}
	if doc.Generation != 4 || string(doc.Credentials["mail-imap"]["password"]) != `"p"` || len(doc.Credentials) != 1 {
		t.Fatalf("%+v", doc)
	}
	got, err := format.ReadTOML(doc.Policy)
	if err != nil {
		t.Fatal(err)
	}
	want, err := format.ReadTOML(`[connections.mail-imap]
preset = "email"
contents = "me"
imap = { host = "imap.example.com" }
[connections.mail-smtp]
preset = "email_send"
contents = "me"
smtp = { host = "smtp.example.com" }
[connections.box-ssh]
preset = "fixture"
cli = { command = "true", credentials = ["KEY", "OTHER"] }
[connections.box-extra]
preset = "fixture"
cli = { command = "false" }
[default_access.mail-imap]
level = "read"
[default_access.mail-smtp]
level = "read"
[identities.agent.connections.box-extra]
level = "ask"
[identities.agent.connections.box-ssh]
level = "ask"
[identities.agent.rules.r1]
connection = "mail"
action = "read"
`)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("got %v\nwant %v", got, want)
	}
}
