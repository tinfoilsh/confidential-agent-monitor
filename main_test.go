package main

import (
	"context"
	"encoding/base64"
	"flag"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestOwnerStartup(t *testing.T) {
	if flag.Arg(0) == "monitor-startup" {
		os.Args = append(os.Args[:1], flag.Args()[1:]...)
		flag.CommandLine = flag.NewFlagSet(os.Args[0], flag.ExitOnError)
		main()
		return
	}
	public := "ed25519:" + base64.StdEncoding.EncodeToString(make([]byte, 32))
	for _, tc := range []struct {
		name, public, want string
		args               []string
	}{
		{name: "production requires public key", args: []string{"-production"}, want: "MONITOR_OWNER_PUBLIC_KEY must be"},
		{name: "worker uses server flag parser before owner startup", args: []string{"-production", "--connector-worker", "-extension", "/extension"}, want: "file file+net connector-listener:"},
		{name: "production file storage requires public key", args: []string{"-production", "-bucket", "file://" + t.TempDir()}, want: "MONITOR_OWNER_PUBLIC_KEY must be"},
		{name: "remote storage requires public key", args: []string{"-bucket", "s3://state"}, want: "MONITOR_OWNER_PUBLIC_KEY must be"},
		{name: "SHA256 flag removed", args: []string{"-owner-key-sha256", "removed"}, want: "flag provided but not defined: -owner-key-sha256"},
		{name: "Argon2 flag removed", args: []string{"-owner-key-argon2id", "removed"}, want: "flag provided but not defined: -owner-key-argon2id"},
		{name: "legacy environment cannot override public key", public: public, args: []string{"-production"}, want: "production and owner SSH require -ssh-host-key"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestOwnerStartup$", "--", "monitor-startup"}, tc.args...)...)
			cmd.Env = append(os.Environ(), "MONITOR_OWNER_PUBLIC_KEY="+tc.public,
				"MONITOR_OWNER_KEY_SHA256=removed", "MONITOR_OWNER_KEY_ARGON2ID=removed")
			output, err := cmd.CombinedOutput()
			if ctx.Err() != nil || err == nil || !strings.Contains(string(output), tc.want) {
				t.Fatalf("startup: %v\n%s", err, output)
			}
		})
	}
}
