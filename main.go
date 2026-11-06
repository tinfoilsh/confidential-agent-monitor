package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"maps"
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
	"github.com/tinfoilsh/monitor/internal/tinfoil/ownerauth"
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

func main() {
	listen := flag.String("listen", "127.0.0.1:2223", "SSH address; it refuses agents until unlock")
	api := flag.String("api", "127.0.0.1:8080", "owner API address")
	bucketURL := flag.String("bucket", os.Getenv("TINFOIL_STORAGE_BUCKET"), "blob URL holding the encrypted state")
	production := flag.Bool("production", false, "disable local UI files, including with a file:// bucket")
	uiDevURL := flag.String("ui-dev-url", "", "proxy local UI development to a loopback Vite server (bun dev/run.ts)")
	ownerPublic := flag.String("owner-public-key", os.Getenv("MONITOR_OWNER_PUBLIC_KEY"), "Ed25519 owner public key")
	hostKey := flag.String("ssh-host-key", "", "runtime attested SSH private key")
	sessionKey := flag.String("owner-session-key", "", "runtime attested X25519 key for owner sessions")
	healthcheck := flag.Bool("healthcheck", false, "check the local owner API and exit, including while locked")
	originList := flag.String("owner-origins", "", "comma-separated browser origins allowed to call the owner API, such as https://dash.tinfoil.sh")
	isolateConnectors := flag.Bool("connector-workers", false, "run all connectors in isolated worker processes")
	workerRoot := flag.String("worker-root", "/opt/monitor/worker", "prepared read-only filesystem for connector workers")
	serveWorker := flag.Bool("serve-connector-worker", false, "serve one connector on inherited descriptors")
	flag.Parse()
	if flag.NArg() != 0 {
		log.Fatal("unexpected server arguments; use the separately installed monitor client")
	}
	// The kind is also the protocol policies see.
	connectorKinds := map[string]connector.Kind{
		"tcp":         tcp.Kind,
		"http":        web.Kind,
		"tinfoil":     tinfoil.Kind,
		"tinfoil-mcp": tinfoil.MCPKind,
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
	}
	// Workers run one connector over inherited descriptors. Host owns configuration,
	// authenticated streams, policy decisions and credentials.
	if *serveWorker {
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
	var devFiles http.Handler
	if *uiDevURL != "" {
		devFiles = must(uiDevProxy(*uiDevURL, dev))
	} else if dev {
		if dir, err := os.Stat("ui/dist"); err == nil && dir.IsDir() {
			devFiles = http.StripPrefix("/app/", http.FileServer(http.Dir("ui/dist")))
		}
	}
	// Production owners authenticate through SSH or Noise sessions and unlock the
	// encrypted state. Only local development permits bearer authentication.
	var public ed25519.PublicKey
	if *ownerPublic != "" || !dev {
		public = must(ownerauth.ParseOwnerKey(*ownerPublic))
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
		maps.DeleteFunc(connectorKinds, func(_ string, kind connector.Kind) bool { return kind.Host })
	}
	bucket := must(blob.OpenBucket(context.Background(), *bucketURL))
	defer bucket.Close()
	ln := must(net.Listen("tcp", *listen))
	defer ln.Close()
	options := monitor.Options{
		Bucket:         bucket,
		OwnerPublicKey: public,
		HostKey:        hostSigner,
		Connectors:     connectorKinds,
		EmbeddedFiles:  embeddedFiles,
	}
	if public != nil {
		options.SessionKey = must(ownerauth.LoadKey(*sessionKey))
	}
	if *isolateConnectors {
		options.Workers = &worker.Local{Root: *workerRoot}
	}
	m := monitor.New(options)
	defer m.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go m.ServeSSH(ln)
	go func() {
		log.Fatal((&http.Server{Addr: *api, Handler: allowOrigins(origins, m.HTTPHandler(devFiles)), ReadHeaderTimeout: readHeaderTimeout}).ListenAndServe())
	}()
	m.RunAudit(ctx)
}

func must[T any](value T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return value
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
