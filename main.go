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
	"github.com/tinfoilsh/monitor/internal/worker"
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
var connectorKinds = map[string]connector.Definition{
	"http":      web.Definition,
	"mcp":       mcp.Definition,
	"ssh":       session.SSHDefinition,
	"sftp":      session.SFTPDefinition,
	"cli":       session.CLIDefinition,
	"mqtt":      mqtt.Definition,
	"nats":      nats.Definition,
	"imap":      email.IMAPDefinition,
	"smtp":      email.SMTPDefinition,
	"redis":     redis.Definition,
	"postgres":  postgres.Definition,
	"ssh-agent": signer.SSHAgentDefinition,
	"gpg-agent": signer.GPGAgentDefinition,
}

func main() {
	listen := flag.String("listen", "127.0.0.1:2223", "SSH address; it refuses agents until unlock")
	api := flag.String("api", "127.0.0.1:8080", "owner API address")
	bucketURL := flag.String("bucket", os.Getenv("TINFOIL_STORAGE_BUCKET"), "blob URL holding the encrypted state")
	drafts := flag.String("drafts", "", "with a file:// bucket, also load the draft presets in this directory")
	extension := flag.String("extension", "", "the english-only extension directory; browser connections need it")
	production := flag.Bool("production", false, "disable development connectors and profiling, including with a file:// bucket")
	ownerPublic := flag.String("owner-public-key", os.Getenv("MONITOR_OWNER_PUBLIC_KEY"), "Ed25519 owner public key")
	hostKey := flag.String("ssh-host-key", "", "runtime attested SSH private key")
	healthcheck := flag.Bool("healthcheck", false, "check the local owner API and exit, including while locked")
	originList := flag.String("owner-origins", "", "comma-separated browser origins allowed to call the owner API, such as https://dash.tinfoil.sh")
	workers := flag.Bool("connector-workers", false, "run all connectors in isolated worker processes")
	workerRoot := flag.String("worker-root", "/opt/monitor/worker", "prepared read-only filesystem for connector workers")
	sandbox := flag.String("worker-sandbox", "bwrap", "connector sandbox launcher")
	workerMode := flag.Bool("connector-worker", false, "serve one connector on inherited descriptors")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("unexpected server arguments; use the separately installed monitor client")
	}
	if *extension != "" || *workerMode {
		connectorKinds["browser"] = browser.Definition(*extension, *workerMode)
	}
	if *workerMode {
		if err := worker.ServeInherited(connectorKinds); err != nil {
			log.Fatal(err)
		}
		return
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
	dev := !*production && strings.HasPrefix(*bucketURL, "file://")
	var public ed25519.PublicKey
	if *ownerPublic != "" || !dev {
		var err error
		public, err = parseOwnerPublicKey(*ownerPublic)
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
	if *drafts != "" {
		if !dev {
			log.Fatal("-drafts needs a development file:// bucket without -production")
		}
		draftFiles = os.DirFS(*drafts)
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
	m := &monitor{store: bucket, dev: dev, ownerPublicKey: public, sshHostKey: hostSigner}
	if *workers {
		m.workers = &worker.Local{Root: *workerRoot, Sandbox: *sandbox}
	}
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
