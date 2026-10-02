package main

import (
	"context"
	"flag"
	"log"
	"net/http"
	"strings"
	"time"

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

const (
	devBucket         = "file://"
	readHeaderTimeout = 30 * time.Second
)

// The kind is also the protocol policies see.
var connectorKinds = map[string]func() connector.Connector{
	"http":      func() connector.Connector { return new(web.HTTP) },
	"ssh":       func() connector.Connector { return new(session.SSH) },
	"cli":       func() connector.Connector { return new(session.CLI) },
	"ssh-agent": func() connector.Connector { return new(signer.SSHAgent) },
	"gpg-agent": func() connector.Connector { return new(signer.GPGAgent) },
	"imap":      func() connector.Connector { return new(email.IMAP) },
	"smtp":      func() connector.Connector { return new(email.SMTP) },
	"postgres":  func() connector.Connector { return new(postgres.Postgres) },
	"redis":     func() connector.Connector { return new(redis.Redis) },
	"mcp":       func() connector.Connector { return new(mcp.Server) },
}

func main() {
	listen := flag.String("listen", "127.0.0.1:2223", "SSH address, opened after unlock")
	api := flag.String("api", "127.0.0.1:8080", "owner API address")
	bucket := flag.String("bucket", "", "blob URL holding the encrypted state")
	object := flag.String("object", "monitor.enc", "key of the encrypted state")
	flag.Parse()
	if err := run(*listen, *api, *bucket, *object); err != nil {
		log.Fatal(err)
	}
}

func run(listen, api, bucketURL, object string) error {
	if !strings.HasPrefix(bucketURL, devBucket) {
		delete(connectorKinds, "cli")
		delete(connectorKinds, "gpg-agent")
	}
	bucket, err := blob.OpenBucket(context.Background(), bucketURL)
	if err != nil {
		return err
	}
	m := &monitor{store: bucket, object: object, listen: listen}
	return (&http.Server{Addr: api, Handler: m.handler(), ReadHeaderTimeout: readHeaderTimeout}).ListenAndServe()
}
