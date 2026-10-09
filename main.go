package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
	"github.com/tinfoilsh/monitor/connector/browser"
	"github.com/tinfoilsh/monitor/connector/email"
	"github.com/tinfoilsh/monitor/connector/mcp"
	"github.com/tinfoilsh/monitor/connector/mqtt"
	"github.com/tinfoilsh/monitor/connector/nats"
	"github.com/tinfoilsh/monitor/connector/postgres"
	"github.com/tinfoilsh/monitor/connector/redis"
	"github.com/tinfoilsh/monitor/connector/session"
	"github.com/tinfoilsh/monitor/connector/signer"
	"github.com/tinfoilsh/monitor/connector/web"
	"gocloud.dev/blob"
	_ "gocloud.dev/blob/fileblob"
	_ "gocloud.dev/blob/s3blob"
)

const readHeaderTimeout = 30 * time.Second

// The kind is also the protocol policies see.
var connectorKinds = map[string]func() any{
	"http":      func() any { return new(web.HTTP) },
	"mcp":       func() any { return new(mcp.Server) },
	"ssh":       func() any { return new(session.SSH) },
	"sftp":      func() any { return new(session.SFTP) },
	"mqtt":      func() any { return new(mqtt.MQTT) },
	"nats":      func() any { return new(nats.NATS) },
	"cli":       func() any { return new(session.CLI) },
	"ssh-agent": func() any { return new(signer.SSHAgent) },
	"gpg-agent": func() any { return new(signer.GPGAgent) },
	"imap":      func() any { return new(email.IMAP) },
	"smtp":      func() any { return new(email.SMTP) },
	"redis":     func() any { return new(redis.Redis) },
	"postgres":  func() any { return new(postgres.Postgres) },
}

func main() {
	_ = godotenv.Load()
	listen := flag.String("listen", "127.0.0.1:2223", "SSH address, opened after unlock")
	api := flag.String("api", "127.0.0.1:8080", "owner API address")
	bucket := flag.String("bucket", "", "blob URL holding the encrypted state")
	object := flag.String("object", "monitor.enc", "key of the encrypted state")
	corpus := flag.String("corpus", "", "with a file:// bucket, append each request to a preset's account here")
	drafts := flag.String("drafts", "", "with a file:// bucket, also load the draft presets in this directory")
	extension := flag.String("extension", "", "the english-only extension directory; browser connections need it")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("unexpected server arguments; use the separately installed monitor client")
	}
	if *drafts != "" {
		if !strings.HasPrefix(*bucket, "file://") {
			log.Fatal("-drafts loads unreviewed presets, so it needs a file:// bucket")
		}
		draftFiles = os.DirFS(*drafts)
	}
	if *extension != "" {
		connectorKinds["browser"] = func() any { return &browser.Browser{Extension: *extension} }
	}
	if err := run(*listen, *api, *bucket, *object, *corpus); err != nil {
		log.Fatal(err)
	}
}

func run(listen, api, bucketURL, object, corpus string) error {
	dev := strings.HasPrefix(bucketURL, "file://")
	if !dev {
		delete(connectorKinds, "cli")
		delete(connectorKinds, "gpg-agent")
	}
	bucket, err := blob.OpenBucket(context.Background(), bucketURL)
	if err != nil {
		return err
	}
	m := &monitor{store: bucket, object: object, listen: listen, dev: dev}
	if corpus != "" {
		if !dev {
			return errors.New("-corpus holds request bodies in plain text, so it needs a file:// bucket")
		}
		f, err := os.OpenFile(corpus, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return err
		}
		m.corpus = json.NewEncoder(f)
	}
	return (&http.Server{Addr: api, Handler: m.handler(), ReadHeaderTimeout: readHeaderTimeout}).ListenAndServe()
}
