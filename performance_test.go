//go:build performance

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/rpc"
	"github.com/tinfoilsh/monitor/connector/web"
	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/internal/worker"
	"gocloud.dev/blob/memblob"
	"golang.org/x/crypto/ssh"
)

// This opt-in harness uses production policy, SSH, TLS, HTTP and worker code.
// Only the provider and blob storage are local fixtures; no provider key is used.
type perfConfig struct {
	Output, WorkerExecutable, WorkerRoot string
	Modes                                []string
	Sizes, Histories                     []int
	Samples, HistoryBodyBytes            int
}

type perfResult struct {
	Name          string             `json:"name"`
	Samples       int                `json:"samples"`
	P50MS         float64            `json:"p50_ms"`
	P95MS         float64            `json:"p95_ms"`
	MaxMS         float64            `json:"max_ms"`
	AllocBytes    uint64             `json:"alloc_bytes_per_op"`
	HeapBytes     uint64             `json:"heap_bytes"`
	ResponseBytes int                `json:"response_bytes,omitempty"`
	Phases        map[string]float64 `json:"phases_mean_ms,omitempty"`
}

type perfReport struct {
	Schema      int               `json:"schema"`
	Go          string            `json:"go"`
	GOMAXPROCS  int               `json:"gomaxprocs"`
	Config      perfConfig        `json:"config"`
	Results     []perfResult      `json:"results"`
	Recognition []perfRecognition `json:"recognition"`
}

type perfRecognition struct {
	Method             string   `json:"method"`
	Path               string   `json:"path"`
	Operation          string   `json:"operation"`
	Requirements       []string `json:"requirements"`
	EvaluationMS       float64  `json:"evaluation_ms"`
	ApprovalDeadlineMS int64    `json:"approval_deadline_ms"`
}

func perfMeasure(t *testing.T, report *perfReport, name string, n int, fn func() (int, map[string]float64, error)) {
	t.Helper()
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	values := make([]float64, 0, n)
	result := perfResult{Name: name, Samples: n, Phases: map[string]float64{}}
	pprof.Do(t.Context(), pprof.Labels("scenario", name), func(context.Context) {
		for range n {
			start := time.Now()
			size, phases, err := fn()
			values = append(values, float64(time.Since(start))/float64(time.Millisecond))
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			result.ResponseBytes = size
			for k, v := range phases {
				result.Phases[k] += v / float64(n)
			}
		}
	})
	runtime.ReadMemStats(&after)
	result.AllocBytes = (after.TotalAlloc - before.TotalAlloc) / uint64(n)
	runtime.GC()
	runtime.ReadMemStats(&after)
	result.HeapBytes = after.HeapAlloc
	slices.Sort(values)
	result.P50MS, result.P95MS, result.MaxMS = values[(n-1)/2], values[(95*n+99)/100-1], values[n-1]
	report.Results = append(report.Results, result)
	t.Logf("%s p50=%.3fms p95=%.3fms alloc=%d heap=%d response=%d", name, result.P50MS, result.P95MS, result.AllocBytes, result.HeapBytes, result.ResponseBytes)
	// Preserve progress, including when a later scenario fails or runs out of memory.
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(report.Config.Output, append(raw, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
}

type perfFixture struct {
	m      *monitor
	key    string
	signer ssh.Signer
}

func perfMonitor(t *testing.T, launcher rpc.Launcher, dialer connector.Dialer) *perfFixture {
	t.Helper()
	bucket := memblob.OpenBucket(nil)
	m := &monitor{store: bucket, dev: true, workers: launcher}
	if err := m.unlock(t.Context(), bytes.Repeat([]byte{42}, 32), 0); err != nil {
		t.Fatal(err)
	}
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	key := ssh.FingerprintSHA256(signer.PublicKey())
	source := fmt.Sprintf(`
[lattices]
confidentiality = false
integrity = false
[accounts.anthropic]
preset = "anthropic"
contents = "anyone"
sends = "anyone"
strangers = false
[accounts.anthropic.connections."".http]
hosts = ["api.anthropic.com"]
[identities.perf]
key = %q
[identities.perf.accounts.anthropic]
level = "allow"
[identities.perf.accounts.anthropic.actions]
"messages.generate" = "allow"
`, strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))))
	m.mu.Lock()
	secrets := secretStore{"anthropic": {"": {"token": json.RawMessage(`"perf-fake-provider-key"`)}}}
	next, st, err := m.prepareCandidate(t.Context(), source, secrets)
	if err == nil && dialer != nil {
		st.Dialer = dialer
	}
	if err == nil {
		err = m.activate(t.Context(), next, st)
	}
	m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, c := range m.running {
			c.cancel()
		}
		for _, c := range m.running {
			<-c.done
		}
		bucket.Close()
	})
	c := st.connections["anthropic"]
	select {
	case <-c.ready:
	case <-c.done:
		t.Fatalf("connector startup: %v", c.err)
	case <-time.After(15 * time.Second):
		t.Fatal("connector startup timed out")
	}
	return &perfFixture{m, key, signer}
}

func perfRequest(size int) (*web.Request, []byte) {
	body := map[string]any{"model": "perf-fixture", "max_tokens": 1, "messages": []any{map[string]any{"role": "user", "content": strings.Repeat("x", size)}}}
	raw, _ := json.Marshal(body)
	return &web.Request{HTTP: &facts.HTTP{Method: "POST", Origin: "https://api.anthropic.com", Host: "api.anthropic.com", Path: "/v1/messages", Headers: http.Header{"Anthropic-Version": {"2023-06-01"}, "Content-Type": {"application/json"}}, Query: map[string][]string{}, BodyKind: "json", Body: body}}, raw
}

func (f *perfFixture) gate(ctx context.Context, request connector.Request) error {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	return f.m.gate(ctx, input{Key: f.key, Connection: "anthropic", Request: request})
}

// A counting response writer exercises real owner JSON encoding without keeping
// a second copy of the entire response in the test process.
type perfWriter struct {
	header       http.Header
	size, status int
}

func (w *perfWriter) Header() http.Header         { return w.header }
func (w *perfWriter) WriteHeader(code int)        { w.status = code }
func (w *perfWriter) Write(p []byte) (int, error) { w.size += len(p); return len(p), nil }

func TestPerformance(t *testing.T) {
	path := os.Getenv("MONITOR_PERF_CONFIG")
	if path == "" {
		t.Skip("run dev/perf")
	}
	var cfg perfConfig
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Samples < 1 || cfg.Output == "" {
		t.Fatal("invalid performance config")
	}
	log.SetOutput(io.Discard)
	defer log.SetOutput(os.Stderr)
	report := &perfReport{Schema: 1, Go: runtime.Version(), GOMAXPROCS: runtime.GOMAXPROCS(0), Config: cfg}
	t.Run("recognition", func(t *testing.T) {
		f := perfMonitor(t, nil, nil)
		for _, probe := range []struct{ method, path string }{{"HEAD", "/api/hello"}, {"GET", "/api/hello"}, {"GET", "/v1/models"}} {
			req := &web.Request{HTTP: &facts.HTTP{Method: probe.method, Path: probe.path, Origin: "https://api.anthropic.com", Host: "api.anthropic.com", BodyKind: "none", Headers: http.Header{"Anthropic-Version": {"2023-06-01"}}}}
			start := time.Now()
			d, _, err := f.m.evaluate(t.Context(), input{Key: f.key, Connection: "anthropic", Request: req})
			if err != nil {
				t.Fatal(err)
			}
			row := perfRecognition{Method: probe.method, Path: probe.path, EvaluationMS: float64(time.Since(start)) / float64(time.Millisecond)}
			if d.Facts.Operation != nil {
				row.Operation = d.Facts.Operation.ID
			}
			for _, r := range d.Requirements {
				row.Requirements = append(row.Requirements, r.ID)
			}
			if len(d.Requirements) > 0 {
				row.ApprovalDeadlineMS = approvalWait.Milliseconds()
			}
			report.Recognition = append(report.Recognition, row)
			t.Logf("%s %s: operation=%q requirements=%v approval deadline=%dms", row.Method, row.Path, row.Operation, row.Requirements, row.ApprovalDeadlineMS)
			perfMeasure(t, report, "recognition/"+probe.method+probe.path, 1, func() (int, map[string]float64, error) {
				ctx, cancel := context.WithTimeout(t.Context(), 25*time.Millisecond)
				defer cancel()
				err := f.gate(ctx, req)
				if len(d.Requirements) > 0 && ctx.Err() != nil && err != nil {
					return 0, nil, nil
				}
				return 0, nil, err
			})
		}
	})
	t.Run("policy", func(t *testing.T) {
		f := perfMonitor(t, nil, nil)
		for _, size := range cfg.Sizes {
			req, _ := perfRequest(size)
			perfMeasure(t, report, fmt.Sprintf("policy/body=%d", size), cfg.Samples, func() (int, map[string]float64, error) {
				return 0, nil, f.gate(t.Context(), req)
			})
			f.m.records = nil
		}
	})
	t.Run("owner", func(t *testing.T) {
		f := perfMonitor(t, nil, nil)
		for _, size := range []int{0, 600000} {
			f.m.live.Load().connections["anthropic"].details, _ = json.Marshal(map[string]any{"changes": []string{strings.Repeat("x", size)}})
			for _, cached := range []bool{false, true} {
				path := "/"
				if cached {
					catalog, err := f.m.catalogView(f.m.live.Load())
					if err != nil {
						t.Fatal(err)
					}
					path += "?catalog=" + catalog.id
				}
				perfMeasure(t, report, fmt.Sprintf("owner/details=%d/cached=%t", size, cached), cfg.Samples, func() (int, map[string]float64, error) {
					return perfOwnerRequest(f.m.handler(), f.m.owner, path)
				})
			}
			catalog, _ := f.m.catalogView(f.m.live.Load())
			path := "/?catalog=" + catalog.id
			warm := perfOwnerResponse(f.m.handler(), f.m.owner, path, nil)
			for _, variant := range []string{"gzip", "unchanged"} {
				headers := http.Header{"Accept-Encoding": {"gzip"}}
				if variant == "unchanged" {
					headers.Set("If-None-Match", warm.header.Get("ETag"))
				}
				perfMeasure(t, report, fmt.Sprintf("owner/details=%d/%s", size, variant), cfg.Samples, func() (int, map[string]float64, error) {
					w := perfOwnerResponse(f.m.handler(), f.m.owner, path, headers)
					if w.status != 200 && w.status != 304 {
						return 0, nil, fmt.Errorf("owner status %d", w.status)
					}
					return w.size, nil, nil
				})
			}
		}
	})
	t.Run("history", func(t *testing.T) {
		f := perfMonitor(t, nil, nil)
		handler := f.m.handler()
		req, _ := perfRequest(cfg.HistoryBodyBytes)
		count := 0
		for _, target := range cfg.Histories {
			for count < target {
				// Independently encoded records, just like separate real requests.
				if err := f.gate(t.Context(), req); err != nil {
					t.Fatal(err)
				}
				count++
			}
			perfMeasure(t, report, fmt.Sprintf("history/records=%d/body=%d", target, cfg.HistoryBodyBytes), min(cfg.Samples, 5), func() (int, map[string]float64, error) {
				return perfOwnerRequest(handler, f.m.owner, "/requests")
			})
			warm := perfOwnerResponse(handler, f.m.owner, "/requests?summary", nil)
			for _, variant := range []string{"summary", "unchanged"} {
				headers := http.Header{}
				if variant == "unchanged" {
					headers.Set("If-None-Match", warm.header.Get("ETag"))
				}
				perfMeasure(t, report, fmt.Sprintf("history_%s/records=%d/body=%d", variant, target, cfg.HistoryBodyBytes), min(cfg.Samples, 5), func() (int, map[string]float64, error) {
					w := perfOwnerResponse(handler, f.m.owner, "/requests?summary", headers)
					if w.status != 200 && w.status != 304 {
						return 0, nil, fmt.Errorf("owner status %d", w.status)
					}
					return w.size, nil, nil
				})
			}
			perfMeasure(t, report, fmt.Sprintf("history_with_admission/records=%d/body=%d", target, cfg.HistoryBodyBytes), 1, func() (int, map[string]float64, error) {
				done := make(chan struct{})
				var size int
				var pollErr error
				go func() { defer close(done); size, _, pollErr = perfOwnerRequest(handler, f.m.owner, "/requests") }()
				var waits []float64
				for {
					started := time.Now()
					f.m.mu.Lock()
					_, _, err := f.m.evaluate(t.Context(), input{Key: f.key, Connection: "anthropic", Request: &admissionRequest{Host: "api.anthropic.com", Port: 443}})
					f.m.mu.Unlock()
					if err != nil {
						<-done
						return 0, nil, err
					}
					waits = append(waits, float64(time.Since(started))/float64(time.Millisecond))
					select {
					case <-done:
						slices.Sort(waits)
						return size, map[string]float64{"admission_p95": waits[(95*len(waits)+99)/100-1], "admission_max": waits[len(waits)-1]}, pollErr
					default:
					}
				}
			})
			perfMeasure(t, report, fmt.Sprintf("admission/records=%d/body=%d", target, cfg.HistoryBodyBytes), cfg.Samples, func() (int, map[string]float64, error) {
				// Evaluation alone avoids changing the history being measured.
				f.m.mu.Lock()
				defer f.m.mu.Unlock()
				_, _, err := f.m.evaluate(t.Context(), input{Key: f.key, Connection: "anthropic", Request: &admissionRequest{Host: "api.anthropic.com", Port: 443}})
				return 0, nil, err
			})
		}
	})
	for _, mode := range cfg.Modes {
		t.Run(mode, func(t *testing.T) { perfHTTP(t, report, mode, false) })
	}
}

func perfOwnerRequest(handler http.Handler, owner []byte, path string) (int, map[string]float64, error) {
	w := perfOwnerResponse(handler, owner, path, nil)
	if w.status != 200 {
		return 0, nil, fmt.Errorf("owner status %d", w.status)
	}
	return w.size, nil, nil
}

func perfOwnerResponse(handler http.Handler, owner []byte, path string, headers http.Header) *perfWriter {
	r := httptest.NewRequest("GET", path, nil)
	for key, values := range headers {
		r.Header[key] = values
	}
	r.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(owner))
	w := &perfWriter{header: make(http.Header), status: 200}
	handler.ServeHTTP(w, r)
	return w
}

type perfDialer struct{ address string }

func (d perfDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if address != "api.anthropic.com:443" {
		return nil, fmt.Errorf("unexpected upstream %s", address)
	}
	return (&net.Dialer{}).DialContext(ctx, network, d.address)
}

func perfHTTP(t *testing.T, report *perfReport, mode string, verifyHello bool) {
	cfg := report.Config
	// The worker trusts only the fixture CA installed in its disposable root.
	var keys keyMaterial
	tlsConfig, err := loadCA(&keys)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tlsConfig.GetCertificate(&tls.ClientHelloInfo{ServerName: "api.anthropic.com"})
	if err != nil {
		t.Fatal(err)
	}
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		if r.URL.Path != "/api/hello" && r.Header.Get("X-Api-Key") != "perf-fake-provider-key" {
			http.Error(w, "credential substitution failed", 401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"ok":true}`)
	}))
	upstream.TLS = &tls.Config{Certificates: []tls.Certificate{*cert}}
	upstream.StartTLS()
	defer upstream.Close()
	// In-process production transports also use the test CA, restored on exit.
	roots := x509.NewCertPool()
	roots.AppendCertsFromPEM([]byte(keys.CACert))
	oldTransport := http.DefaultTransport
	base := oldTransport.(*http.Transport).Clone()
	base.TLSClientConfig = &tls.Config{RootCAs: roots}
	http.DefaultTransport = base
	defer func() { base.CloseIdleConnections(); http.DefaultTransport = oldTransport }()
	var launcher rpc.Launcher
	if mode == "worker" {
		if cfg.WorkerExecutable == "" || cfg.WorkerRoot == "" {
			t.Fatal("worker mode requires built executable and root")
		}
		if err := os.WriteFile(filepath.Join(cfg.WorkerRoot, "etc/ssl/certs/ca-certificates.crt"), []byte(keys.CACert), 0600); err != nil {
			t.Fatal(err)
		}
		launcher = &worker.Local{Executable: cfg.WorkerExecutable, Root: cfg.WorkerRoot}
	} else if mode != "inprocess" && mode != "direct" {
		t.Fatalf("unknown mode %q", mode)
	}
	dial := perfDialer{upstream.Listener.Addr().String()}.DialContext
	clientRoots := roots
	var f *perfFixture
	if mode != "direct" {
		perfMeasure(t, report, "startup/"+mode, 1, func() (int, map[string]float64, error) {
			f = perfMonitor(t, launcher, perfDialer{upstream.Listener.Addr().String()})
			return 0, nil, nil
		})
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		go f.m.serveSSH(ln)
		client, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{User: "perf", Auth: []ssh.AuthMethod{ssh.PublicKeys(f.signer)}, HostKeyCallback: ssh.FixedHostKey(f.m.live.Load().HostKey.PublicKey()), Timeout: 5 * time.Second})
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		monitorRoots := x509.NewCertPool()
		monitorRoots.AppendCertsFromPEM([]byte(f.m.doc.Keys.CACert))
		dial, clientRoots = client.DialContext, monitorRoots
	}
	if verifyHello {
		transport := &http.Transport{DialContext: dial, TLSClientConfig: &tls.Config{RootCAs: clientRoots}}
		defer transport.CloseIdleConnections()
		client := &http.Client{Transport: transport, Timeout: 2 * time.Second}
		for _, method := range []string{"GET", "HEAD"} {
			request, _ := http.NewRequestWithContext(t.Context(), method, "https://api.anthropic.com/api/hello", nil)
			response, err := client.Do(request)
			if err != nil {
				t.Fatalf("%s hello through %s: %v", method, mode, err)
			}
			io.Copy(io.Discard, response.Body)
			response.Body.Close()
			if response.StatusCode != 200 {
				t.Fatalf("%s hello status %d", method, response.StatusCode)
			}
		}
		return
	}
	for _, size := range cfg.Sizes {
		_, body := perfRequest(size)
		for _, cold := range []bool{true, false} {
			transport := &http.Transport{DialContext: dial, TLSClientConfig: &tls.Config{RootCAs: clientRoots}, DisableKeepAlives: cold}
			httpClient := &http.Client{Transport: transport, Timeout: 10 * time.Second}
			name := fmt.Sprintf("http/%s/body=%d/cold=%t", mode, size, cold)
			request := func() (int, map[string]float64, error) {
				started := time.Now()
				var mu sync.Mutex
				phases := map[string]float64{}
				mark := func(name string) {
					mu.Lock()
					defer mu.Unlock()
					phases[name] = float64(time.Since(started)) / float64(time.Millisecond)
				}
				trace := &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { mark("connection_ready") }, TLSHandshakeStart: func() { mark("tls_start") }, TLSHandshakeDone: func(tls.ConnectionState, error) { mark("tls_done") }, WroteRequest: func(httptrace.WroteRequestInfo) { mark("request_written") }, GotFirstResponseByte: func() { mark("first_byte") }}
				r, err := http.NewRequestWithContext(httptrace.WithClientTrace(t.Context(), trace), "POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(body))
				if err != nil {
					return 0, nil, err
				}
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Anthropic-Version", "2023-06-01")
				if mode == "direct" {
					r.Header.Set("X-Api-Key", "perf-fake-provider-key")
				} else {
					r.Header.Set("X-Api-Key", web.Placeholder("anthropic", "token"))
				}
				resp, err := httpClient.Do(r)
				if err != nil {
					return 0, nil, err
				}
				n, err := io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
				if resp.StatusCode != 200 {
					return 0, nil, fmt.Errorf("HTTP %d", resp.StatusCode)
				}
				mu.Lock()
				defer mu.Unlock()
				return int(n), maps.Clone(phases), err
			}
			if !cold {
				if _, _, err := request(); err != nil {
					t.Fatal(err)
				}
			}
			perfMeasure(t, report, name, cfg.Samples, request)
			transport.CloseIdleConnections()
		}
		if f != nil {
			f.m.mu.Lock()
			f.m.records = nil
			f.m.mu.Unlock()
		}
	}
}

func TestOwnerPolling(t *testing.T) {
	f := perfMonitor(t, nil, nil)
	req, _ := perfRequest(262144)
	if err := f.gate(t.Context(), req); err != nil {
		t.Fatal(err)
	}
	handler := f.m.handler()
	get := func(path, tag, encoding string, authenticated bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		if authenticated {
			r.Header.Set("Authorization", "Bearer "+base64.StdEncoding.EncodeToString(f.m.owner))
		}
		r.Header.Set("If-None-Match", tag)
		r.Header.Set("Accept-Encoding", encoding)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	full := get("/requests", "", "", true)
	compact := get("/requests?summary", "", "", true)
	if full.Code != 200 || compact.Code != 200 || full.Body.Len() < 500000 || compact.Body.Len() > 2048 {
		t.Fatalf("full=%d/%d summary=%d/%d", full.Code, full.Body.Len(), compact.Code, compact.Body.Len())
	}
	var rows []map[string]any
	if err := json.Unmarshal(compact.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	fact := rows[0]["facts"].(map[string]any)
	if rows[0]["summary"] != true || fact["parameters"] != nil || fact["details"] != nil || rows[0]["grant"] != nil {
		t.Fatal("summary contains full request data")
	}
	id := rows[0]["id"].(string)
	detail := get("/requests/"+id, "", "", true)
	if detail.Code != 200 || !bytes.Contains(detail.Body.Bytes(), []byte(strings.Repeat("x", 262144))) {
		t.Fatal("full request unavailable")
	}
	if w := get("/requests/gone", "", "", true); w.Code != 404 {
		t.Fatalf("missing record status=%d", w.Code)
	}
	tag := compact.Header().Get("ETag")
	if tag == "" {
		t.Fatal("no validator")
	}
	if w := get("/requests?summary", tag, "", true); w.Code != 304 || w.Body.Len() != 0 {
		t.Fatalf("unchanged response=%d/%d", w.Code, w.Body.Len())
	}
	if w := get("/requests?summary", tag, "", false); w.Code != 401 {
		t.Fatalf("validator bypassed authentication: %d", w.Code)
	}
	f.m.mu.Lock()
	f.m.records[0].State = statePending
	f.m.records[0].answered = make(chan struct{})
	f.m.records[0].Expires = time.Now().Add(time.Minute)
	f.m.mu.Unlock()
	pending := get("/requests?summary", tag, "", true)
	if pending.Code != 200 || pending.Header().Get("ETag") == tag || !bytes.Contains(pending.Body.Bytes(), []byte(`"state":"pending"`)) {
		t.Fatal("missed pending state change")
	}
	f.m.mu.Lock()
	err := f.m.answer(t.Context(), id, answerOnce)
	f.m.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if w := get("/requests?summary", pending.Header().Get("ETag"), "", true); w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"state":"approved"`)) {
		t.Fatal("missed approval")
	}
	compressed := get("/requests", "", "gzip", true)
	if compressed.Header().Get("Content-Encoding") != "gzip" || compressed.Body.Len() >= full.Body.Len()/10 {
		t.Fatal("response not compressed")
	}
	reader, err := gzip.NewReader(compressed.Body)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := io.ReadAll(reader)
	reader.Close()
	if err != nil || !bytes.Equal(decoded, get("/requests", "", "", true).Body.Bytes()) {
		t.Fatal("gzip changed JSON")
	}
	for _, coding := range []string{"gzip;q=0", "br", "gzip;q=invalid"} {
		if w := get("/requests", "", coding, true); w.Header().Get("Content-Encoding") != "" {
			t.Fatalf("compressed for %q", coding)
		}
	}
	// Large connector details remain available; repeat polls have no body.
	f.m.live.Load().connections["anthropic"].details = json.RawMessage(`{"changes":["` + strings.Repeat("x", 600000) + `"]}`)
	view := get("/", "", "gzip", true)
	if view.Code != 200 {
		t.Fatal(view.Code)
	}
	if w := get("/", view.Header().Get("ETag"), "gzip", true); w.Code != 304 || w.Body.Len() != 0 {
		t.Fatal("unchanged snapshot transferred again")
	}
	f.m.live.Load().connections["anthropic"].details = json.RawMessage(`{"blocked":0}`)
	if w := get("/", view.Header().Get("ETag"), "gzip", true); w.Code != 200 {
		t.Fatal("missed connector status change")
	}
}

func TestHelloRecognition(t *testing.T) {
	f := perfMonitor(t, nil, nil)
	for _, method := range []string{"GET", "HEAD", "POST"} {
		r := &web.Request{HTTP: &facts.HTTP{Method: method, Path: "/api/hello", Origin: "https://api.anthropic.com", Host: "api.anthropic.com", BodyKind: "none", Headers: http.Header{}}}
		d, _, err := f.m.evaluate(t.Context(), input{Key: f.key, Connection: "anthropic", Request: r})
		if err != nil {
			t.Fatal(err)
		}
		if method == "POST" {
			if d.Facts.Operation != nil || len(d.Requirements) == 0 {
				t.Fatal("unknown method became allowed")
			}
		} else if d.Facts.Operation == nil || len(d.Requirements) != 0 || d.Facts.Operation.Action != "hello.read" {
			t.Fatalf("%s still needs approval: %+v", method, d)
		}
	}
}

func TestHelloForwarding(t *testing.T) {
	path := os.Getenv("MONITOR_PERF_CONFIG")
	if path == "" {
		t.Skip("requires dev/perf's config and built worker")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cfg perfConfig
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"inprocess", "worker"} {
		t.Run(mode, func(t *testing.T) { perfHTTP(t, &perfReport{Config: cfg}, mode, true) })
	}
}
