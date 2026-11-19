package main

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/config"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/connections"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/sandbox"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/worker"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/noisetransport"
	"github.com/tinfoilsh/confidential-agent-monitor/ui"
	"gocloud.dev/blob"
	_ "gocloud.dev/blob/fileblob"
	_ "gocloud.dev/blob/s3blob"
	"golang.org/x/crypto/ssh"
)

const (
	storageBucketEnv  = "TINFOIL_STORAGE_BUCKET"
	bucketEnv         = "MONITOR_BUCKET"
	ownerPublicKeyEnv = "MONITOR_OWNER_PUBLIC_KEY"
	defaultListen     = "127.0.0.1:2223"
	defaultAPI        = "127.0.0.1:8080"
	defaultWorkerRoot = "/opt/monitor/worker"
	serveWorkerFlag   = "serve-connector-worker"
)

const (
	maxWorkers        = 32
	workerBroker      = "/broker.sock"
	workerTmpBytes    = "67108864"
	workerMemoryLimit = "256MiB"
	workerMaxProcs    = "2"
)

var (
	listen           = flag.String("listen", defaultListen, "SSH address; it refuses agents until unlock")
	api              = flag.String("api", defaultAPI, "owner API address")
	bucketURL        = flag.String("bucket", cmp.Or(os.Getenv(storageBucketEnv), os.Getenv(bucketEnv)), "blob URL holding the encrypted state")
	production       = flag.Bool("production", false, "disable development features, including with a file:// bucket")
	uiDevURL         = flag.String("ui-dev-url", "", "proxy local UI development to a loopback Vite server (bun dev/run.ts)")
	ownerPublicKey   = flag.String("owner-public-key", os.Getenv(ownerPublicKeyEnv), "Ed25519 owner public key")
	ownerSessionKey  = flag.String("owner-session-key", "", "runtime attested X25519 key for owner sessions")
	connectorWorkers = flag.Bool("connector-workers", false, "run all connectors in isolated worker processes")
	workerRoot       = flag.String("worker-root", defaultWorkerRoot, "prepared read-only filesystem for connector workers")
	serveWorker      = flag.Bool(serveWorkerFlag, false, "serve one connector on inherited descriptors")
)

var (
	sshHostKey         ssh.Signer
	unlockKey          []byte
	identityCA         ssh.PublicKey
	basePolicy         string
	policyFile         string
	secretFiles        *os.Root
	ownerOrigins       []string
	development        bool
	passphraseKeys     bool
	workers            *worker.Local
	identityAttributes = map[string]func(json.RawMessage) error{sandbox.Attribute: sandbox.ValidateBoot}
	events             = slog.New(slog.NewJSONHandler(os.Stdout, nil))
)

var workerLimits = worker.Limits{Streams: 128, Upstreams: 32, Handshake: connections.DialTimeout, Credential: credentialTimeout, Sign: 10 * time.Second,
	Connections: 32, Idle: 8, PoolIdle: 30 * time.Second, Read: 10 * time.Second, ServeIdle: time.Minute, Drain: connections.RelayDrain}

func init() {
	flag.Func("ssh-host-key", "runtime attested SSH private key", func(path string) error {
		data, err := os.ReadFile(path)
		if err == nil {
			sshHostKey, err = ssh.ParsePrivateKey(data)
		}
		return err
	})
	flag.Func("owner-key-file", "development owner key to unlock with at start", func(path string) error {
		key, err := os.ReadFile(path)
		if err == nil {
			unlockKey, err = base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(key)))
		}
		return err
	})
	flag.Func("owner-origins", "comma-separated browser origins allowed to call the owner API, such as https://console.example.com", func(list string) error {
		for _, origin := range strings.Split(list, ",") {
			if origin = strings.TrimSpace(origin); origin == "" {
				continue
			}
			u, err := url.Parse(origin)
			if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Scheme+"://"+u.Host != origin {
				return fmt.Errorf("owner origin %q must be scheme://host[:port]", origin)
			}
			ownerOrigins = append(ownerOrigins, origin)
		}
		return nil
	})
	flag.Func("identity-ca", "file holding one SSH CA public key in authorized_keys format; its expiring user certificates name identities and their groups. Every key certified with one name shares that name's label", func(path string) error {
		data, err := os.ReadFile(path)
		if err == nil {
			identityCA, _, _, _, err = ssh.ParseAuthorizedKey(data)
		}
		return err
	})
	flag.Func("base-policy", "Rego file in package perimeter.base; every decision needs its allow and its approvals as it does owner policy's, every admin call by another caller than the owner needs its admin_allow, and its capable grants identities the routes, config and propose capabilities; owner policy cannot change it", func(path string) error {
		base, err := os.ReadFile(path)
		basePolicy = string(base)
		return err
	})
	flag.Func("policy-file", "TOML policy loaded at each unlock in place of the stored one; the admin API then cannot change the policy", func(path string) error {
		policyFile = path
		return nil
	})
	flag.Func("secrets", "directory that file credentials are read from at each use", func(path string) (err error) {
		secretFiles, err = os.OpenRoot(path)
		return err
	})
}

func main() {
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("unexpected server arguments; use the separately installed perimeter client")
	}
	if *serveWorker {
		if err := worker.ServeLocal(context.Background(), connections.Open, workerBroker, workerLimits); err != nil {
			log.Fatal(err)
		}
		return
	}

	development = !*production && strings.HasPrefix(*bucketURL, "file://")
	if basePolicy != "" {
		if _, err := config.PreparePolicy(context.Background(), new(config.Config), basePolicy); err != nil {
			log.Fatal(err)
		}
	}
	if *connectorWorkers {
		workers = &worker.Local{Limit: maxWorkers, Limits: workerLimits, Command: worker.Bubblewrap{Root: *workerRoot, Broker: workerBroker, TmpBytes: workerTmpBytes,
			MemoryLimit: workerMemoryLimit, MaxProcs: workerMaxProcs, Args: []string{"--" + serveWorkerFlag}}.Command}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	bucket, err := blob.OpenBucket(ctx, *bucketURL)
	if err != nil {
		log.Fatal(err)
	}
	defer bucket.Close()
	s := newState(ctx, bucket)

	app := http.StripPrefix("/app/", http.FileServerFS(ui.Files))
	if *uiDevURL != "" {
		if !development {
			log.Fatal("-ui-dev-url requires a development file:// bucket without -production")
		}
		if app, err = ui.DevProxy(*uiDevURL); err != nil {
			log.Fatal(err)
		}
	}

	var o *owner
	if *ownerPublicKey != "" || !development {
		if unlockKey != nil {
			log.Fatal("-owner-key-file requires a development file:// bucket without -owner-public-key")
		}
		o = new(owner)
		var valid bool
		if o.publicKey, valid = noisetransport.ParseSigner(*ownerPublicKey); !valid {
			log.Fatal("owner public key must be ed25519: followed by the base64 of a valid Ed25519 public key")
		}
		if o.sessionKey, err = noisetransport.LoadKey(*ownerSessionKey); err != nil {
			log.Fatal(err)
		}
	}
	passphraseKeys = o == nil
	if unlockKey != nil {
		if _, err := s.unlock(ctx, unlockKey, 0); err != nil {
			log.Fatal(err)
		}
	}

	sshListener, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	apiListener, err := net.Listen("tcp", *api)
	if err != nil {
		log.Fatal(err)
	}
	err = s.serve(ctx, sshListener, apiListener, o, app)
	stop()
	s.close()
	if err != nil {
		log.Fatal(err)
	}
}
