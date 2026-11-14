package main

import (
	"cmp"
	"context"
	"encoding/base64"
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
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/kinds"
	"github.com/tinfoilsh/confidential-agent-monitor/owner"
	"github.com/tinfoilsh/confidential-agent-monitor/perimeter"
	"github.com/tinfoilsh/confidential-agent-monitor/presets"
	"github.com/tinfoilsh/confidential-agent-monitor/tinfoil"
	"github.com/tinfoilsh/confidential-agent-monitor/ui"
	"github.com/tinfoilsh/confidential-agent-monitor/worker"
	"gocloud.dev/blob"
	_ "gocloud.dev/blob/fileblob"
	_ "gocloud.dev/blob/s3blob"
	"golang.org/x/crypto/ssh"
)

const (
	storageBucketEnv   = "TINFOIL_STORAGE_BUCKET"
	bucketEnv          = "MONITOR_BUCKET"
	ownerPublicKeyEnv  = "MONITOR_OWNER_PUBLIC_KEY"
	defaultListen      = "127.0.0.1:2223"
	defaultAPI         = "127.0.0.1:8080"
	defaultWorkerRoot  = "/opt/monitor/worker"
	serveWorkerFlag    = "serve-connector-worker"
	healthcheckTimeout = 5 * time.Second
	localUI            = "ui/dist"
)

var (
	listen           = flag.String("listen", defaultListen, "SSH address; it refuses agents until unlock")
	api              = flag.String("api", defaultAPI, "owner API address")
	bucket           = flag.String("bucket", cmp.Or(os.Getenv(storageBucketEnv), os.Getenv(bucketEnv)), "blob URL holding the encrypted state")
	production       = flag.Bool("production", false, "disable local UI files, including with a file:// bucket")
	uiDevURL         = flag.String("ui-dev-url", "", "proxy local UI development to a loopback Vite server (bun dev/run.ts)")
	ownerPublicKey   = flag.String("owner-public-key", os.Getenv(ownerPublicKeyEnv), "Ed25519 owner public key")
	sshHostKey       = flag.String("ssh-host-key", "", "runtime attested SSH private key")
	ownerSessionKey  = flag.String("owner-session-key", "", "runtime attested X25519 key for owner sessions")
	ownerKeyFile     = flag.String("owner-key-file", "", "development owner key to unlock with at start")
	originList       = flag.String("owner-origins", "", "comma-separated browser origins allowed to call the owner API, such as https://console.example.com")
	connectorWorkers = flag.Bool("connector-workers", false, "run all connectors in isolated worker processes")
	workerRoot       = flag.String("worker-root", defaultWorkerRoot, "prepared read-only filesystem for connector workers")
	identityCA       = flag.String("identity-ca", "", "file holding one SSH CA public key in authorized_keys format; its expiring user certificates name identities and their groups. A label follows the certified key, so the issuer must not certify a second key for a running workload")
	basePolicy       = flag.String("base-policy", "", "Rego file in package perimeter.base; its deny and approvals apply to every decision as owner policy's do, and its admin_allow and admin_deny to every admin call; owner policy cannot change it")
	policyFile       = flag.String("policy-file", "", "TOML policy loaded at each unlock in place of the stored one; the admin API then cannot change the policy")
	presetDir        = flag.String("presets", "", "directory of an organization's own preset definitions, added to the shipped ones")
	secretDir        = flag.String("secrets", "", "directory that file credentials are read from at each use")
	healthcheck      = flag.Bool("healthcheck", false, "check the local owner API and exit, including while locked")
	serveWorker      = flag.Bool(serveWorkerFlag, false, "serve one connector on inherited descriptors")
)

func main() {
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("unexpected server arguments; use the separately installed perimeter client")
	}
	connectors := kinds.Standard()
	connectors["tinfoil"], connectors["tinfoil-mcp"] = tinfoil.Kind, tinfoil.MCPKind
	// Workers run one connector over inherited descriptors. Host owns configuration,
	// authenticated streams, policy decisions and credentials.
	if *serveWorker {
		if err := worker.ServeInherited(connectors); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *healthcheck {
		client := &http.Client{Timeout: healthcheckTimeout}
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, connectors); err != nil {
		log.Fatal(err)
	}
}

func run(ctx context.Context, connectors map[string]connector.Kind) error {
	dev := !*production && strings.HasPrefix(*bucket, "file://")
	c := perimeter.Config{
		Connectors: connectors,
		UI:         http.StripPrefix("/app/", http.FileServerFS(ui.Files)),
		// Events is the stream a collector reads: one JSON line on stdout for each settled record.
		Events: slog.New(slog.NewJSONHandler(os.Stdout, nil)),
	}
	var devFiles http.Handler
	var err error
	if *uiDevURL != "" {
		if devFiles, err = uiDevProxy(*uiDevURL, dev); err != nil {
			return err
		}
	} else if dev {
		if dir, err := os.Stat(localUI); err == nil && dir.IsDir() {
			devFiles = http.StripPrefix("/app/", http.FileServer(http.Dir(localUI)))
		}
	}
	// Production owners authenticate through SSH or Noise sessions and unlock the
	// encrypted state. Only local development permits bearer authentication.
	if *ownerPublicKey != "" || !dev {
		c.Owner = new(perimeter.Owner)
		if c.Owner.Key, err = owner.ParseOwnerKey(*ownerPublicKey); err != nil {
			return err
		}
	} else if devFiles != nil {
		c.UI = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			r.Header.Del("If-Modified-Since")
			r.Header.Del("If-None-Match")
			devFiles.ServeHTTP(w, r)
		})
	}
	if c.Origins, err = ownerOrigins(*originList); err != nil {
		return err
	}
	if *sshHostKey != "" {
		data, err := os.ReadFile(*sshHostKey)
		if err == nil {
			c.HostKey, err = ssh.ParsePrivateKey(data)
		}
		if err != nil {
			return err
		}
	}
	if (*production || c.Owner != nil) && c.HostKey == nil {
		return errors.New("production and owner SSH require -ssh-host-key")
	}
	if !dev {
		c.Connectors = maps.Clone(c.Connectors)
		maps.DeleteFunc(c.Connectors, func(_ string, kind connector.Kind) bool { return kind.Host })
	}
	if *connectorWorkers {
		launcher := &worker.Local{Root: cmp.Or(*workerRoot, defaultWorkerRoot), Args: []string{"--" + serveWorkerFlag}}
		c.Connectors = launcher.Isolate(c.Connectors)
	}
	if *identityCA != "" {
		data, err := os.ReadFile(*identityCA)
		if err == nil {
			c.IdentityCA, _, _, _, err = ssh.ParseAuthorizedKey(data)
		}
		if err != nil {
			return err
		}
	}
	if *basePolicy != "" {
		base, err := os.ReadFile(*basePolicy)
		if err != nil {
			return err
		}
		c.BasePolicy = string(base)
	}
	if *policyFile != "" {
		c.Policy = func() (string, error) {
			file, err := os.ReadFile(*policyFile)
			return string(file), err
		}
	}
	var dir fs.FS
	if *presetDir != "" {
		dir = os.DirFS(*presetDir)
		if _, err := fs.Stat(dir, "."); err != nil {
			return err
		}
	}
	if c.Presets, err = presets.Load(presets.Files, tinfoil.Presets, dir); err != nil {
		return err
	}
	if *secretDir != "" {
		if c.Secrets, err = os.OpenRoot(*secretDir); err != nil {
			return err
		}
	}
	if c.Owner != nil {
		if c.Owner.SessionKey, err = owner.LoadKey(*ownerSessionKey); err != nil {
			return err
		}
	}
	if *ownerKeyFile != "" {
		if c.Owner != nil {
			return errors.New("-owner-key-file requires a development file:// bucket without -owner-public-key")
		}
		key, err := os.ReadFile(*ownerKeyFile)
		if err == nil {
			c.Unlock, err = base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(key)))
		}
		if err != nil {
			return err
		}
	}
	if c.Bucket, err = blob.OpenBucket(ctx, *bucket); err != nil {
		return err
	}
	defer c.Bucket.Close()
	if c.SSH, err = net.Listen("tcp", cmp.Or(*listen, defaultListen)); err != nil {
		return err
	}
	if c.API, err = net.Listen("tcp", cmp.Or(*api, defaultAPI)); err != nil {
		c.SSH.Close()
		return err
	}
	return perimeter.Run(ctx, c)
}

func uiDevProxy(address string, development bool) (http.Handler, error) {
	if !development {
		return nil, errors.New("-ui-dev-url requires a development file:// bucket without -production")
	}
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

func ownerOrigins(list string) ([]string, error) {
	var origins []string
	for _, origin := range strings.Split(list, ",") {
		if origin = strings.TrimSpace(origin); origin == "" {
			continue
		}
		u, err := url.Parse(origin)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" || u.Scheme+"://"+u.Host != origin {
			return nil, fmt.Errorf("owner origin %q must be scheme://host[:port]", origin)
		}
		origins = append(origins, origin)
	}
	return origins, nil
}
