package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"reflect"
	"testing"

	"gocloud.dev/blob/memblob"
)

func TestMigratePresets(t *testing.T) {
	raw := json.RawMessage(`{"accounts":{
		"git":{"template":"github","policy_options":{"private":["team/*"]}},
		"api":{"template":"api","policy_options":{"preset":"github_api"},"connections":{"http":{"token":"preserve"}}},
		"tenant":{"template":"api","policy_options":{"preset":"aws_s3","origin":"https://example.com"}}
	},"identities":{"dev":{"accounts":{"api":{"level":"allow","actions":{"read":"off","write":"off","write.issues":"ask","admin":"ask"}}}}}}`)
	migrated, changed, err := migratePresets(raw)
	if err != nil || !changed {
		t.Fatalf("migration failed: %v, %v", changed, err)
	}
	var cfg struct {
		Accounts   map[string]account
		Identities map[string]identity
	}
	if err := json.Unmarshal(migrated, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Accounts["git"].Preset != "github" || cfg.Accounts["api"].Preset != "github" || cfg.Accounts["tenant"].Preset != "aws_s3" ||
		cfg.Accounts["git"].PolicyOptions.Private[0] != "team/*" || cfg.Accounts["tenant"].PolicyOptions.Origin != "https://example.com" ||
		cfg.Accounts["api"].Connections["http"]["token"] != "preserve" {
		t.Fatalf("account migration lost settings: %s", migrated)
	}
	want := map[string]string{"read": "off", "open.issues": "ask", "comment": "ask", "open.pulls": "off", "push": "off", "merge": "ask"}
	if !reflect.DeepEqual(cfg.Identities["dev"].Accounts["api"].Actions, want) {
		t.Fatalf("permission migration: %+v", cfg.Identities["dev"].Accounts["api"].Actions)
	}
	again, changed, err := migratePresets(migrated)
	if err != nil || changed || !bytes.Equal(again, migrated) {
		t.Fatalf("migration is not idempotent: %v, %v", changed, err)
	}
	raw = json.RawMessage(`{"accounts":{"api":{"template":"api","policy_options":{"preset":"github_api"}}},"presets":{"github_api":{"catalog":{}}}}`)
	migrated, _, err = migratePresets(raw)
	if err != nil || !bytes.Contains(migrated, []byte(`"preset":"github_api"`)) {
		t.Fatalf("owner preset was renamed: %s, %v", migrated, err)
	}
	for _, raw := range []string{
		`{"accounts":{"a":{"template":"api"}}}`,
		`{"accounts":{"a":{"template":"web","preset":"ssh"}}}`,
		`{"accounts":{"a":{"template":"web","policy_options":{"preset":"slack"}}}}`,
		`{"accounts":{"a":{"preset":"github_api"}},"presets":{"github":{}}}`,
		`{"accounts":{"a":{"preset":"github_api"}},"identities":{"dev":{"accounts":{"a":{"actions":{"write":"off","push":"allow"}}}}}}`,
	} {
		if _, _, err := migratePresets(json.RawMessage(raw)); err == nil {
			t.Fatalf("ambiguous migration accepted: %s", raw)
		}
	}
}

func TestStoredPresetMigration(t *testing.T) {
	store := memblob.OpenBucket(nil)
	open := func() *monitor { return &monitor{store: store, object: "monitor.enc", listen: "127.0.0.1:0"} }
	key := make([]byte, ownerKeyBytes)
	rand.Read(key)
	m := open()
	if _, err := m.unlock(t.Context(), key, 0); err != nil {
		t.Fatal(err)
	}
	legacy := m.doc
	legacy.Config = json.RawMessage(`{"accounts":{"web":{"template":"web","contents":"anyone","sends":"anyone"}}}`)
	legacy.Generation++
	if err := m.persist(t.Context(), legacy, key); err != nil {
		t.Fatal(err)
	}
	m = open()
	st, err := m.unlock(t.Context(), key, legacy.Generation)
	if err != nil {
		t.Fatal(err)
	}
	if st.cfg.Accounts["web"].Preset != "web" || m.doc.Generation != legacy.Generation+1 || m.doc.Keys != legacy.Keys {
		t.Fatal("unlock did not migrate while preserving keys and advancing the generation")
	}
	migrated := m.doc
	m = open()
	if _, err := m.unlock(t.Context(), key, migrated.Generation); err != nil {
		t.Fatal(err)
	}
	if m.doc.Generation != migrated.Generation || !bytes.Equal(m.doc.Config, migrated.Config) {
		t.Fatal("migration was not persisted or ran again")
	}
	if _, err := m.patch(t.Context(), []byte(`{"accounts":{"mail":{"template":"email","contents":"me","sends":"me"}}}`)); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(m.doc.Config, []byte(`"template"`)) || m.live.Load().cfg.Accounts["mail"].Preset != "email" {
		t.Fatal("legacy patch was not migrated")
	}
}
