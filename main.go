package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
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
	"golang.org/x/crypto/ssh"
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
	bucketURL := flag.String("bucket", os.Getenv("TINFOIL_STORAGE_BUCKET"), "blob URL holding the encrypted state")
	drafts := flag.String("drafts", "", "with a file:// bucket, also load the draft presets in this directory")
	extension := flag.String("extension", "", "the english-only extension directory; browser connections need it")
	production := flag.Bool("production", false, "disable development connectors and profiling, including with a file:// bucket")
	ownerPublic := flag.String("owner-public-key", os.Getenv("MONITOR_OWNER_PUBLIC_KEY"), "Ed25519 owner public key")
	ownerHash := flag.String("owner-key-sha256", os.Getenv("MONITOR_OWNER_KEY_SHA256"), "legacy hex SHA-256 of a 32-byte owner key")
	ownerArgon := flag.String("owner-key-argon2id", os.Getenv("MONITOR_OWNER_KEY_ARGON2ID"), "Argon2id owner commitment")
	hostKey := flag.String("ssh-host-key", "", "runtime attested SSH private key")
	healthcheck := flag.Bool("healthcheck", false, "check the local owner API and exit, including while locked")
	originList := flag.String("owner-origins", "", "comma-separated browser origins allowed to call the owner API, such as https://dash.tinfoil.sh")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("unexpected server arguments; use the separately installed monitor client")
	}
	if *healthcheck {
		client := &http.Client{Timeout: 5 * time.Second}
		resp, err := client.Get("http://" + *api + "/healthz")
		if err != nil {
			log.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			log.Fatalf("healthcheck: %s", resp.Status)
		}
		return
	}
	var commitment *ownerCommitment
	var public ed25519.PublicKey
	if *ownerPublic != "" {
		if *ownerHash != "" || *ownerArgon != "" {
			log.Fatal("set only MONITOR_OWNER_PUBLIC_KEY for SSH ownership")
		}
		var err error
		public, err = parseOwnerPublicKey(*ownerPublic)
		if err != nil {
			log.Fatal(err)
		}
	} else if *production || *ownerHash != "" || *ownerArgon != "" {
		var err error
		commitment, err = parseOwnerCommitment(*ownerHash, *ownerArgon)
		if err != nil {
			log.Fatal(err)
		}
	}
	origins, err := ownerOrigins(*originList)
	if err != nil {
		log.Fatal(err)
	}
	var hostSigner ssh.Signer
	if *hostKey != "" {
		data, err := os.ReadFile(*hostKey)
		if err != nil {
			log.Fatal(err)
		}
		hostSigner, err = ssh.ParsePrivateKey(data)
		if err != nil {
			log.Fatal(err)
		}
	}
	if (*production || public != nil) && hostSigner == nil {
		log.Fatal("production and owner SSH require -ssh-host-key")
	}
	dev := !*production && strings.HasPrefix(*bucketURL, "file://")
	if *drafts != "" {
		if !dev {
			log.Fatal("-drafts needs a development file:// bucket without -production")
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
	m := &monitor{store: bucket, dev: dev, ownerCommitment: commitment, ownerPublicKey: public, sshHostKey: hostSigner}
	go m.serveSSH(ln)
	log.Fatal((&http.Server{Addr: *api, Handler: allowOrigins(origins, m.handler()), ReadHeaderTimeout: readHeaderTimeout}).ListenAndServe())
}

func parseOwnerPublicKey(value string) (ed25519.PublicKey, error) {
	encoded, ok := strings.CutPrefix(value, "ed25519:")
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if !ok || err != nil || len(key) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(key) != encoded {
		return nil, errors.New("MONITOR_OWNER_PUBLIC_KEY must be ed25519: followed by a base64 public key")
	}
	return ed25519.PublicKey(key), nil
}
