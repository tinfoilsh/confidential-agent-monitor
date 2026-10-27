package main

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
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
	"github.com/tinfoilsh/monitor/connector/tcp"
	"github.com/tinfoilsh/monitor/connector/tinfoil"
	"github.com/tinfoilsh/monitor/connector/web"
	"github.com/tinfoilsh/monitor/internal/monitor"
	"github.com/tinfoilsh/monitor/internal/worker"
	"github.com/tinfoilsh/monitor/ui"
	"gocloud.dev/blob"
	_ "gocloud.dev/blob/fileblob"
	_ "gocloud.dev/blob/s3blob"
	"golang.org/x/crypto/ssh"
)

const (
	readHeaderTimeout = 30 * time.Second
	preflightMaxAge   = "600"
)

// The kind is also the protocol policies see.
var connectorKinds = map[string]connector.Definition{
	"tcp":         tcp.Definition,
	"http":        web.Definition,
	"tinfoil":     tinfoil.Definition,
	"tinfoil-mcp": tinfoil.MCPDefinition,
	"mcp":         mcp.Definition,
	"ssh":         session.SSHDefinition,
	"sftp":        session.SFTPDefinition,
	"cli":         session.CLIDefinition,
	"mqtt":        mqtt.Definition,
	"nats":        nats.Definition,
	"imap":        email.IMAPDefinition,
	"smtp":        email.SMTPDefinition,
	"redis":       redis.Definition,
	"postgres":    postgres.Definition,
	"ssh-agent":   signer.SSHAgentDefinition,
	"gpg-agent":   signer.GPGAgentDefinition,
}

func main() {
	listen := flag.String("listen", "127.0.0.1:2223", "SSH address; it refuses agents until unlock")
	api := flag.String("api", "127.0.0.1:8080", "owner API address")
	bucketURL := flag.String("bucket", os.Getenv("TINFOIL_STORAGE_BUCKET"), "blob URL holding the encrypted state")
	extension := flag.String("extension", "", "the english-only extension directory; browser connections need it")
	production := flag.Bool("production", false, "disable development connectors and local UI files, including with a file:// bucket")
	uiDevURL := flag.String("ui-dev-url", "", "proxy local UI development to a loopback Vite server (bun dev/run.ts)")
	ownerPublic := flag.String("owner-public-key", os.Getenv("MONITOR_OWNER_PUBLIC_KEY"), "Ed25519 owner public key")
	hostKey := flag.String("ssh-host-key", "", "runtime attested SSH private key")
	healthcheck := flag.Bool("healthcheck", false, "check the local owner API and exit, including while locked")
	originList := flag.String("owner-origins", "", "comma-separated browser origins allowed to call the owner API, such as https://dash.tinfoil.sh")
	workers := flag.Bool("connector-workers", false, "run all connectors in isolated worker processes")
	workerRoot := flag.String("worker-root", "/opt/monitor/worker", "prepared read-only filesystem for connector workers")
	workerMode := flag.Bool("connector-worker", false, "serve one connector on inherited descriptors")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("unexpected server arguments; use the separately installed monitor client")
	}
	if *extension != "" || *workerMode {
		connectorKinds["browser"] = browser.Definition(*extension, *workerMode)
	}
	// Workers run one connector over inherited descriptors. Host owns configuration,
	// authenticated streams, policy decisions and credentials.
	if *workerMode {
		if err := worker.ServeInherited(connectorKinds); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *healthcheck {
		client := &http.Client{Timeout: 5 * time.Second}
		resp := must(client.Get("http://" + *api + "/healthz"))
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			log.Fatalf("healthcheck: %s", resp.Status)
		}
		return
	}
	dev := !*production && strings.HasPrefix(*bucketURL, "file://")
	assets := must(fs.Sub(ui.Files, "dist"))
	embeddedFiles := http.StripPrefix("/app/", http.FileServerFS(assets))
	var files http.Handler
	if *uiDevURL != "" {
		files = must(uiDevProxy(*uiDevURL, dev))
	} else if dev {
		if dir, err := os.Stat("ui/dist"); err == nil && dir.IsDir() {
			files = http.StripPrefix("/app/", http.FileServer(http.Dir("ui/dist")))
		}
	}
	// Production owners authenticate through SSH or signed RPC and unlock the
	// encrypted state. Only local development permits bearer authentication.
	var public ed25519.PublicKey
	if *ownerPublic != "" || !dev {
		public = must(parseOwnerPublicKey(*ownerPublic))
	}
	origins := must(ownerOrigins(*originList))
	var hostSigner ssh.Signer
	if *hostKey != "" {
		data := must(os.ReadFile(*hostKey))
		hostSigner = must(ssh.ParsePrivateKey(data))
	}
	if (*production || public != nil) && hostSigner == nil {
		log.Fatal("production and owner SSH require -ssh-host-key")
	}
	if !dev {
		delete(connectorKinds, "cli")
		delete(connectorKinds, "gpg-agent")
	}
	bucket := must(blob.OpenBucket(context.Background(), *bucketURL))
	defer bucket.Close()
	ln := must(net.Listen("tcp", *listen))
	defer ln.Close()
	options := monitor.Options{
		Bucket:         bucket,
		BucketURL:      *bucketURL,
		OwnerPublicKey: public,
		HostKey:        hostSigner,
		Connectors:     connectorKinds,
		EmbeddedFiles:  embeddedFiles,
	}
	if *workers {
		options.Workers = &worker.Local{Root: *workerRoot}
	}
	m := monitor.New(options)
	defer m.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	// SSH acts as a frontdoor for traffic.
	// Access control is applied based on the keypair identity identified during the handshake
	// Owners can connect to the API using either SSH or the HTTP listener
	go m.ServeSSH(ln)
	go func() {
		log.Fatal((&http.Server{Addr: *api, Handler: allowOrigins(origins, m.Handler(files)), ReadHeaderTimeout: readHeaderTimeout}).ListenAndServe())
	}()
	m.WriteAudit(ctx)
}

// Startup cannot serve a partially configured application.
func must[T any](value T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return value
}

func parseOwnerPublicKey(value string) (ed25519.PublicKey, error) {
	encoded, ok := strings.CutPrefix(value, "ed25519:")
	key, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if !ok || err != nil || len(key) != ed25519.PublicKeySize || base64.StdEncoding.EncodeToString(key) != encoded {
		return nil, errors.New("MONITOR_OWNER_PUBLIC_KEY must be ed25519: followed by a base64 public key")
	}
	return ed25519.PublicKey(key), nil
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

// ownerOrigins parses a comma-separated list of exact browser origins, such as https://dash.tinfoil.sh.
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

// allowOrigins lets the listed origins call the owner API from a browser, such as a dashboard
// holding the owner key in memory. Only the bearer key authenticates; credentials are never allowed.
func allowOrigins(origins []string, next http.Handler) http.Handler {
	if len(origins) == 0 {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Vary", "Origin")
		origin := r.Header.Get("Origin")
		if !slices.Contains(origins, origin) {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Access-Control-Allow-Origin", origin)
		w.Header().Set("Access-Control-Expose-Headers", "ETag")
		if r.Method == http.MethodOptions && r.Header.Get("Access-Control-Request-Method") != "" {
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST")
			w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type, If-None-Match")
			w.Header().Set("Access-Control-Max-Age", preflightMaxAge)
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
