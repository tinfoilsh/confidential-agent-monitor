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

	_ "github.com/joho/godotenv/autoload"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/email"
	"github.com/tinfoilsh/monitor/connector/mcp"
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
var connectorKinds = map[string]func() connector.Connector{
	"http":      func() connector.Connector { return new(web.HTTP) },
	"mcp":       func() connector.Connector { return new(mcp.Server) },
	"ssh":       func() connector.Connector { return new(session.SSH) },
	"cli":       func() connector.Connector { return new(session.CLI) },
	"ssh-agent": func() connector.Connector { return new(signer.SSHAgent) },
	"gpg-agent": func() connector.Connector { return new(signer.GPGAgent) },
	"imap":      func() connector.Connector { return new(email.IMAP) },
	"smtp":      func() connector.Connector { return new(email.SMTP) },
	"redis":     func() connector.Connector { return new(redis.Redis) },
	"postgres":  func() connector.Connector { return new(postgres.Postgres) },
}

func main() {
	listen := flag.String("listen", "127.0.0.1:2223", "SSH address, opened after unlock")
	api := flag.String("api", "127.0.0.1:8080", "owner API address")
	bucket := flag.String("bucket", "", "blob URL holding the encrypted state")
	object := flag.String("object", "monitor.enc", "key of the encrypted state")
	corpus := flag.String("corpus", "", "with a file:// bucket, append each request to a preset's account here")
	flag.Parse()
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
