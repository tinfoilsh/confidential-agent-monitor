package main

import (
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"log/slog"
	"maps"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/tinfoil"
	"github.com/tinfoilsh/confidential-agent-monitor/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/email"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/mcp"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/mqtt"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/nats"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/postgres"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/redis"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/session"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/signer"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/tcp"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/web"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/worker"
	"github.com/tinfoilsh/confidential-agent-monitor/core/sshx"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/monitor"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/policy/standard"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter/presets"
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
	sandboxAttribute  = "sandbox"
)

var (
	listen           = flag.String("listen", defaultListen, "SSH address; it refuses agents until unlock")
	api              = flag.String("api", defaultAPI, "owner API address")
	bucket           = flag.String("bucket", cmp.Or(os.Getenv(storageBucketEnv), os.Getenv(bucketEnv)), "blob URL holding the encrypted state")
	production       = flag.Bool("production", false, "disable development features, including with a file:// bucket")
	uiDevURL         = flag.String("ui-dev-url", "", "proxy local UI development to a loopback Vite server (bun dev/run.ts)")
	ownerPublicKey   = flag.String("owner-public-key", os.Getenv(ownerPublicKeyEnv), "Ed25519 owner public key")
	ownerSessionKey  = flag.String("owner-session-key", "", "runtime attested X25519 key for owner sessions")
	connectorWorkers = flag.Bool("connector-workers", false, "run all connectors in isolated worker processes")
	workerRoot       = flag.String("worker-root", defaultWorkerRoot, "prepared read-only filesystem for connector workers")
	serveWorker      = flag.Bool(serveWorkerFlag, false, "serve one connector on inherited descriptors")

	options = monitor.Options{
		Vocabulary: standard.Vocabulary(), PolicyLibrary: standard.Library(),
		Attributes: map[string]func(json.RawMessage) error{sandboxAttribute: ValidateBoot},
		// Events is the stream a collector reads: one JSON line on stdout for each settled record.
		Events: slog.New(slog.NewJSONHandler(os.Stdout, nil)),
	}
	config       perimeter.Config
	unlock       []byte
	extraPresets fs.FS
)

func init() {
	flag.Func("ssh-host-key", "runtime attested SSH private key", func(path string) error {
		data, err := os.ReadFile(path)
		if err == nil {
			options.HostKey, err = ssh.ParsePrivateKey(data)
		}
		return err
	})
	flag.Func("owner-key-file", "development owner key to unlock with at start", func(path string) error {
		key, err := os.ReadFile(path)
		if err == nil {
			unlock, err = base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(key)))
		}
		return err
	})
	flag.Func("owner-origins", "comma-separated browser origins allowed to call the owner API, such as https://console.example.com", ownerOrigins)
	flag.Func("identity-ca", "file holding one SSH CA public key in authorized_keys format; its expiring user certificates name identities and their groups. A label follows the certified key, so the issuer must not certify a second key for a running workload", func(path string) error {
		data, err := os.ReadFile(path)
		if err == nil {
			config.IdentityCA, _, _, _, err = ssh.ParseAuthorizedKey(data)
		}
		return err
	})
	flag.Func("base-policy", "Rego file in package perimeter.base; its deny and approvals apply to every decision as owner policy's do, its admin_allow and admin_deny to every admin call, and its capable grants identities the routes, config and propose capabilities; owner policy cannot change it", func(path string) error {
		base, err := os.ReadFile(path)
		options.BasePolicy = string(base)
		return err
	})
	flag.Func("policy-file", "TOML policy loaded at each unlock in place of the stored one; the admin API then cannot change the policy", func(path string) error {
		options.Policy = func() (string, error) {
			file, err := os.ReadFile(path)
			return string(file), err
		}
		return nil
	})
	flag.Func("presets", "directory of an organization's own preset definitions, added to the shipped ones", func(path string) error {
		extraPresets = os.DirFS(path)
		_, err := fs.Stat(extraPresets, ".")
		return err
	})
	flag.Func("secrets", "directory that file credentials are read from at each use", func(path string) (err error) {
		options.Secrets, err = os.OpenRoot(path)
		return err
	})
}

func main() {
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("unexpected server arguments; use the separately installed perimeter client")
	}
	// The kind is also the protocol policies see.
	options.Connectors = map[string]connector.Kind{
		"tcp":         tcp.Kind,
		"http":        web.Kind,
		"mcp":         mcp.Kind,
		"ssh":         session.SSHKind,
		"sftp":        session.SFTPKind,
		"cli":         session.CLIKind,
		"mqtt":        mqtt.Kind,
		"nats":        nats.Kind,
		"imap":        email.IMAPKind,
		"smtp":        email.SMTPKind,
		"redis":       redis.Kind,
		"postgres":    postgres.Kind,
		"ssh-agent":   signer.SSHAgentKind,
		"gpg-agent":   signer.GPGAgentKind,
		"tinfoil":     tinfoil.Kind,
		"tinfoil-mcp": tinfoil.MCPKind,
	}
	// Workers run one connector over inherited descriptors. Host owns configuration,
	// authenticated streams, policy decisions and credentials.
	if *serveWorker {
		if err := worker.ServeChild(options.Connectors); err != nil {
			log.Fatal(err)
		}
		return
	}
	var err error
	dev := !*production && strings.HasPrefix(*bucket, "file://")
	routes := new(tinfoil.Forwarder)
	sandboxes := newSandboxes(routes)
	options.Admin = map[string]http.Handler{sandboxRelayRoute: monitor.JSON(maxRelayBytes, func(r *http.Request, in relayInput) (any, error) {
		return sandboxes.relay(r.Context(), in)
	})}
	config.UI = http.StripPrefix("/app/", http.FileServerFS(ui.Files))
	if *uiDevURL != "" {
		if !dev {
			log.Fatal("-ui-dev-url requires a development file:// bucket without -production")
		}
		if config.UI, err = uiDevProxy(*uiDevURL); err != nil {
			log.Fatal(err)
		}
	}
	// Production owners authenticate through SSH or Noise sessions and unlock the
	// encrypted state. Only local development permits bearer authentication.
	if *ownerPublicKey != "" || !dev {
		if unlock != nil {
			log.Fatal("-owner-key-file requires a development file:// bucket without -owner-public-key")
		}
		config.Owner = &perimeter.Owner{Relay: sandboxes.dialOwner}
		if config.Owner.Key, err = perimeter.ParseOwnerKey(*ownerPublicKey); err != nil {
			log.Fatal(err)
		}
		if config.Owner.SessionKey, err = perimeter.LoadSessionKey(*ownerSessionKey); err != nil {
			log.Fatal(err)
		}
	}
	options.PassphraseKeys = config.Owner == nil
	if !dev {
		maps.DeleteFunc(options.Connectors, func(_ string, kind connector.Kind) bool { return kind.Host })
	}
	if *connectorWorkers {
		launcher := &worker.Local{Root: *workerRoot, Args: []string{"--" + serveWorkerFlag}}
		options.Connectors = worker.Isolate(launcher, options.Connectors)
	}
	// Routes wrap the isolated kinds: a worker dials through its host's dialer.
	options.Connectors = routes.Kinds(options.Connectors)
	if options.Presets, err = presets.Load(options.Vocabulary, presets.Files, tinfoil.Presets, extraPresets); err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if options.Bucket, err = blob.OpenBucket(ctx, *bucket); err != nil {
		log.Fatal(err)
	}
	defer options.Bucket.Close()
	if config.Monitor, err = monitor.New(options); err != nil {
		log.Fatal(err)
	}
	defer config.Monitor.Close()
	routes.Identities = config.Monitor.Identities()
	config.Streams = tinfoil.Direct{Routes: routes, Hold: config.Monitor.Hold, Next: config.Monitor}
	config.Extensions = []sshx.Extension{routes.Publishers(func() bool {
		_, unlocked := config.Monitor.Generation()
		return unlocked
	})}
	if unlock != nil {
		if err := config.Monitor.Unlock(ctx, unlock); err != nil {
			log.Fatal(err)
		}
	}
	if config.SSH, err = net.Listen("tcp", *listen); err != nil {
		log.Fatal(err)
	}
	if config.API, err = net.Listen("tcp", *api); err != nil {
		log.Fatal(err)
	}
	if err := perimeter.Run(ctx, config); err != nil {
		log.Fatal(err)
	}
}

func uiDevProxy(address string) (http.Handler, error) {
	target, err := url.Parse(address)
	if err != nil || target.Scheme != "http" || target.Host == "" || target.User != nil ||
		(target.Path != "" && target.Path != "/") || target.RawQuery != "" || target.Fragment != "" ||
		(target.Hostname() != "localhost" && !net.ParseIP(target.Hostname()).IsLoopback()) {
		return nil, errors.New("-ui-dev-url must be a loopback HTTP origin, such as http://127.0.0.1:5173")
	}
	target.Path = ""
	proxy := httputil.NewSingleHostReverseProxy(target)
	proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "UI development server unavailable; start it with bun dev/run.ts", http.StatusBadGateway)
	}
	return proxy, nil
}

func ownerOrigins(list string) error {
	for _, origin := range strings.Split(list, ",") {
		if origin = strings.TrimSpace(origin); origin == "" {
			continue
		}
		u, err := url.Parse(origin)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Scheme+"://"+u.Host != origin {
			return fmt.Errorf("owner origin %q must be scheme://host[:port]", origin)
		}
		config.Origins = append(config.Origins, origin)
	}
	return nil
}
