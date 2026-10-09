package main

import (
	"context"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tinfoilsh/monitor/connector"
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

const (
	readHeaderTimeout = 30 * time.Second
	stateObject       = "monitor.enc"
)

// The kind is also the protocol policies see.
var connectorKinds = map[string]func() connector.Server{
	"http":      func() connector.Server { return new(web.HTTP) },
	"mcp":       func() connector.Server { return new(mcp.Server) },
	"ssh":       func() connector.Server { return new(session.SSH) },
	"sftp":      func() connector.Server { return new(session.SFTP) },
	"mqtt":      func() connector.Server { return new(mqtt.MQTT) },
	"nats":      func() connector.Server { return new(nats.NATS) },
	"cli":       func() connector.Server { return new(session.CLI) },
	"ssh-agent": func() connector.Server { return new(signer.SSHAgent) },
	"gpg-agent": func() connector.Server { return new(signer.GPGAgent) },
	"imap":      func() connector.Server { return new(email.IMAP) },
	"smtp":      func() connector.Server { return new(email.SMTP) },
	"redis":     func() connector.Server { return new(redis.Redis) },
	"postgres":  func() connector.Server { return new(postgres.Postgres) },
}

func main() {
	listen := flag.String("listen", "127.0.0.1:2223", "SSH address; it refuses agents until unlock")
	api := flag.String("api", "127.0.0.1:8080", "owner API address")
	bucketURL := flag.String("bucket", "", "blob URL holding the encrypted state")
	drafts := flag.String("drafts", "", "with a file:// bucket, also load the draft presets in this directory")
	extension := flag.String("extension", "", "the english-only extension directory; browser connections need it")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("unexpected server arguments; use the separately installed monitor client")
	}
	dev := strings.HasPrefix(*bucketURL, "file://")
	if *drafts != "" {
		if !dev {
			log.Fatal("-drafts loads unreviewed presets, so it needs a file:// bucket")
		}
		draftFiles = os.DirFS(*drafts)
	}
	if *extension != "" {
		connectorKinds["browser"] = func() connector.Server { return &browser.Browser{Extension: *extension} }
	}
	if !dev {
		delete(connectorKinds, "cli")
		delete(connectorKinds, "gpg-agent")
	}
	bucket, err := blob.OpenBucket(context.Background(), *bucketURL)
	if err != nil {
		log.Fatal(err)
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	m := &monitor{store: bucket, dev: dev}
	go m.serveSSH(ln)
	log.Fatal((&http.Server{Addr: *api, Handler: m.handler(), ReadHeaderTimeout: readHeaderTimeout}).ListenAndServe())
}
