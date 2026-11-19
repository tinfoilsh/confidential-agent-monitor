package connections_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/config"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/connections"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/catalog"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/worker"
	"github.com/tinfoilsh/confidential-agent-monitor/core/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/netx"
)

// These tests run Datadog requests through the shipped preset, the real HTTP connector,
// credential slots and the Perimeter's Rego decision, against a local TLS upstream.

const (
	ddAPIKey      = "real-dd-api-key-0123456789abcdef"
	ddAppKey      = "real-dd-app-key-0123456789abcdef0123456789"
	ddAPIHolder   = "tfm_datadog_apikey0001"
	ddAppHolder   = "tfm_datadog_appkey0002"
	ddConnection  = "datadog"
	ddAllowPolicy = "package sentinel\n\nallow := true\n"
)

var testCA struct {
	cert  *x509.Certificate
	key   *ecdsa.PrivateKey
	pool  *x509.CertPool
	mu    sync.Mutex
	cache map[string]*tls.Certificate
}

func TestMain(m *testing.M) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "perimeter test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	testCA.cert, _ = x509.ParseCertificate(der)
	testCA.key, testCA.pool, testCA.cache = key, x509.NewCertPool(), map[string]*tls.Certificate{}
	testCA.pool.AddCert(testCA.cert)
	dir, err := os.MkdirTemp("", "perimeter-ca")
	if err != nil {
		panic(err)
	}
	caFile := filepath.Join(dir, "ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
		panic(err)
	}
	// The connector's upstream transport uses the system roots, which read this before first use.
	os.Setenv("SSL_CERT_FILE", caFile)
	code := m.Run()
	os.RemoveAll(dir)
	os.Exit(code)
}

func leaf(host string) (*tls.Certificate, error) {
	testCA.mu.Lock()
	defer testCA.mu.Unlock()
	if c := testCA.cache[host]; c != nil {
		return c, nil
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	serial, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, KeyUsage: x509.KeyUsageDigitalSignature,
	}, testCA.cert, &key.PublicKey, testCA.key)
	if err != nil {
		return nil, err
	}
	c := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
	testCA.cache[host] = c
	return c, nil
}

func serverTLS() *tls.Config {
	return &tls.Config{GetCertificate: func(h *tls.ClientHelloInfo) (*tls.Certificate, error) { return leaf(h.ServerName) }}
}

type upstreamRequest struct {
	Dialed, Host, Method, Path, RawQuery string
	Header                               http.Header
	Body                                 []byte
}

type gateRecord struct {
	Operation *catalog.Operation
	Facts     map[string]any
	Decision  config.Decision
	Invalid   error
}

type ddHarness struct {
	t        *testing.T
	preset   *catalog.Preset
	cfg      *config.Config
	program  *config.Program
	setup    *connections.Setup
	instance connector.Instance
	level    string
	upstream net.Listener

	mu        sync.Mutex
	dialed    []string
	forwarded []upstreamRequest
	gated     []gateRecord
}

func newDatadogHarness(t *testing.T, level string) *ddHarness {
	t.Helper()
	presets, _, err := config.LoadPresets(nil)
	if err != nil {
		t.Fatal(err)
	}
	source := fmt.Sprintf("[policies]\nallow = %q\n\n[connections.%s]\npreset = \"datadog\"\ncontents = \"team\"\nstrangers = false\nsends = \"team\"\n", ddAllowPolicy, ddConnection)
	cfg, err := config.Load(source, presets)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := cfg.Spec(ddConnection)
	if err != nil {
		t.Fatal(err)
	}
	setup, err := connections.Parse(spec)
	if err != nil {
		t.Fatal(err)
	}
	program, err := config.PreparePolicy(context.Background(), cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	h := &ddHarness{t: t, preset: presets["datadog"], cfg: cfg, program: program, setup: setup, level: level}

	h.upstream, err = tls.Listen("tcp", "127.0.0.1:0", serverTLS())
	if err != nil {
		t.Fatal(err)
	}
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		h.mu.Lock()
		dialed := ""
		if len(h.dialed) > 0 {
			dialed = h.dialed[len(h.dialed)-1]
		}
		h.forwarded = append(h.forwarded, upstreamRequest{Dialed: dialed, Host: r.Host, Method: r.Method, Path: r.URL.Path, RawQuery: r.URL.RawQuery, Header: r.Header.Clone(), Body: body})
		h.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok","data":[]}`))
	})}
	go server.Serve(h.upstream)
	t.Cleanup(func() { server.Close() })

	placeholders := map[string]string{"api_key": ddAPIHolder, "application_key": ddAppHolder}
	secrets := map[string]string{"api_key": ddAPIKey, "application_key": ddAppKey}
	h.instance, err = setup.Open(context.Background(), worker.Host{
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			h.mu.Lock()
			h.dialed = append(h.dialed, address)
			h.mu.Unlock()
			var d net.Dialer
			return d.DialContext(ctx, "tcp", h.upstream.Addr().String())
		},
		Secret: func(_ context.Context, name string) (string, error) {
			if v, ok := secrets[name]; ok {
				return v, nil
			}
			return "", errors.New("no such credential")
		},
		Placeholder: func(name string) string { return placeholders[name] },
		TLS:         func(context.Context, string) *tls.Config { return serverTLS() },
	})
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// gate mirrors the Perimeter's decision path: connector hint, catalog resolution, then the Rego decision.
func (h *ddHarness) gate(ctx context.Context, e facts.Event) error {
	o, invalid := e.Decode()
	var rc connections.RequestContext
	if err := h.setup.Hint(&o, &rc); invalid == nil {
		invalid = err
	}
	record := gateRecord{Invalid: invalid}
	defer func() {
		h.mu.Lock()
		h.gated = append(h.gated, record)
		h.mu.Unlock()
	}()
	if invalid != nil {
		return invalid
	}
	if o.Operation != nil {
		record.Operation = h.preset.Catalog.Resolve(o.Operation.ID, o.Operation.Action, o.Operation.Effects)
	}
	rc.Label = config.InitialLabel
	if o.Parameters == nil {
		o.Parameters = map[string]any{}
	}
	scope := o.Scope
	if scope == nil {
		scope = o.Parameters
	}
	conn := h.cfg.Connections[ddConnection]
	request := map[string]any{
		"version": config.FactsVersion, "kind": config.KindOperation,
		"principal": facts.Principal{Key: "SHA256:test", Name: "agent"},
		"service":   "datadog", "connection": ddConnection, "operation": record.Operation,
		"parameters": o.Parameters, "context": rc, "title": o.Title, "details": o.Details,
	}
	encoded, err := json.Marshal(request)
	if err != nil {
		return err
	}
	json.Unmarshal(encoded, &record.Facts)
	input := config.DecisionInput{
		Facts: encoded,
		Authorization: config.AuthorizationInput{
			Access: config.Access{Level: h.level}, Reaches: h.level != "off",
			Effects: []map[string]string{{}, {}, {}, {}}, Rules: []config.Rule{}, Approved: []string{}, Scope: scope,
		},
		Connection: config.ConnectionInput{Contents: conn.Contents, Strangers: conn.Strangers, Sends: conn.Sends, Private: []string{}, PublicScope: []string{}},
	}
	if err := h.program.Eval(ctx, config.QueryDecision, input, &record.Decision); err != nil {
		return err
	}
	if !record.Decision.Allow {
		var reasons []string
		reasons = append(reasons, record.Decision.Deny...)
		for _, r := range record.Decision.Requirements {
			reasons = append(reasons, "requires "+r.ID)
		}
		return errors.New(strings.Join(reasons, "; "))
	}
	return nil
}

// client returns an HTTP client whose TLS connections are each served by the connector, as a bunker's proxy would.
func (h *ddHarness) client() *http.Client {
	return &http.Client{Transport: &http.Transport{
		DisableKeepAlives: true,
		DialTLSContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			agent, perimeter := net.Pipe()
			go h.instance.Serve(context.Background(), perimeter, ddConnection, connector.Target{Network: "tcp", Host: host, Port: 443}, h.gate)
			c := tls.Client(agent, &tls.Config{ServerName: host, RootCAs: testCA.pool})
			if err := c.HandshakeContext(ctx); err != nil {
				c.Close()
				return nil, err
			}
			return c, nil
		},
	}}
}

type ddResult struct {
	status    int
	body      string
	gate      gateRecord
	forwarded *upstreamRequest
}

func (h *ddHarness) do(req *http.Request) ddResult {
	h.t.Helper()
	h.mu.Lock()
	gated, forwarded := len(h.gated), len(h.forwarded)
	h.mu.Unlock()
	resp, err := h.client().Do(req)
	if err != nil {
		h.t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	h.mu.Lock()
	defer h.mu.Unlock()
	r := ddResult{status: resp.StatusCode, body: string(body)}
	if len(h.gated) == gated+1 {
		r.gate = h.gated[gated]
	} else if len(h.gated) != gated {
		h.t.Fatalf("%s %s: %d gate checks", req.Method, req.URL, len(h.gated)-gated)
	}
	if len(h.forwarded) == forwarded+1 {
		r.forwarded = &h.forwarded[forwarded]
	}
	return r
}

func ddRequest(t *testing.T, method, rawURL, body string, header map[string]string) *http.Request {
	t.Helper()
	var reader io.Reader
	if body != "" {
		reader = strings.NewReader(body)
	}
	req, err := http.NewRequest(method, rawURL, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("Accept", "application/json")
	for k, v := range header {
		req.Header.Set(k, v)
	}
	return req
}

var bothKeys = map[string]string{"DD-API-KEY": ddAPIHolder, "DD-APPLICATION-KEY": ddAppHolder}
var apiKeyOnly = map[string]string{"DD-API-KEY": ddAPIHolder}

type ddCase struct {
	name, method, url, body string
	header                  map[string]string
	id, action              string
	effects                 []string
	parameters              map[string]any
	outcome                 string // allow, ask or deny
}

func checkCase(t *testing.T, h *ddHarness, c ddCase) {
	t.Helper()
	req := ddRequest(t, c.method, c.url, c.body, c.header)
	if c.header == nil {
		for k, v := range bothKeys {
			req.Header.Set(k, v)
		}
	}
	r := h.do(req)
	if r.gate.Invalid != nil {
		t.Fatalf("refused as invalid: %v", r.gate.Invalid)
	}
	op := r.gate.Operation
	if c.id == "" && c.action == "" {
		if op != nil {
			t.Fatalf("expected an unknown request, matched %s (%s)", op.ID, op.Action)
		}
	} else {
		if op == nil {
			t.Fatalf("expected %s, got an unknown request (title %v)", c.id, r.gate.Facts["title"])
		}
		if (c.id != "" && op.ID != c.id) || (c.action != "" && op.Action != c.action) || !slices.Equal(op.Effects, c.effects) {
			t.Fatalf("matched %s action %s effects %v; want %s action %s effects %v", op.ID, op.Action, op.Effects, c.id, c.action, c.effects)
		}
	}
	params, _ := r.gate.Facts["parameters"].(map[string]any)
	for k, want := range c.parameters {
		if got, _ := json.Marshal(params[k]); string(got) != mustJSON(want) {
			t.Errorf("parameter %s = %s, want %s", k, got, mustJSON(want))
		}
	}
	switch c.outcome {
	case "allow":
		if !r.gate.Decision.Allow || r.status != http.StatusOK || r.forwarded == nil {
			t.Fatalf("expected forwarding, got status %d decision %+v body %s", r.status, r.gate.Decision, r.body)
		}
		u, _ := url.Parse(c.url)
		if r.forwarded.Host != u.Host || r.forwarded.Dialed != u.Host+":443" || r.forwarded.Path != u.Path || r.forwarded.Method != c.method {
			t.Fatalf("forwarded %+v for %s", r.forwarded, c.url)
		}
		if c.body != "" && string(r.forwarded.Body) != c.body {
			t.Fatalf("body changed: %s", r.forwarded.Body)
		}
		checkNoPlaceholders(t, r.forwarded)
	case "ask", "deny":
		if r.gate.Decision.Allow || r.status != http.StatusForbidden || r.forwarded != nil {
			t.Fatalf("expected refusal, got status %d decision %+v", r.status, r.gate.Decision)
		}
		asked := len(r.gate.Decision.Requirements) != 0 && len(r.gate.Decision.Deny) == 0
		if asked != (c.outcome == "ask") {
			t.Fatalf("expected %s, got deny %v requirements %v", c.outcome, r.gate.Decision.Deny, r.gate.Decision.Requirements)
		}
	default:
		t.Fatalf("bad outcome %q", c.outcome)
	}
}

func mustJSON(v any) string {
	raw, _ := json.Marshal(v)
	return string(raw)
}

func checkNoPlaceholders(t *testing.T, r *upstreamRequest) {
	t.Helper()
	all := r.RawQuery + string(r.Body) + r.Path
	for _, values := range r.Header {
		all += strings.Join(values, " ")
	}
	if strings.Contains(all, "tfm_") {
		t.Fatalf("a placeholder reached the upstream: %+v", r)
	}
}

var ddSites = []struct{ name, api, logs, events string }{
	{"US1", "api.datadoghq.com", "http-intake.logs.datadoghq.com", "event-management-intake.datadoghq.com"},
	{"US3", "api.us3.datadoghq.com", "http-intake.logs.us3.datadoghq.com", "event-management-intake.us3.datadoghq.com"},
	{"US5", "api.us5.datadoghq.com", "http-intake.logs.us5.datadoghq.com", "event-management-intake.us5.datadoghq.com"},
	{"EU1", "api.datadoghq.eu", "http-intake.logs.datadoghq.eu", "event-management-intake.datadoghq.eu"},
	{"AP1", "api.ap1.datadoghq.com", "http-intake.logs.ap1.datadoghq.com", "event-management-intake.ap1.datadoghq.com"},
	{"AP2", "api.ap2.datadoghq.com", "http-intake.logs.ap2.datadoghq.com", "event-management-intake.ap2.datadoghq.com"},
	{"UK1", "api.uk1.datadoghq.com", "http-intake.logs.uk1.datadoghq.com", "event-management-intake.uk1.datadoghq.com"},
	{"US1-FED", "api.ddog-gov.com", "http-intake.logs.ddog-gov.com", "event-management-intake.ddog-gov.com"},
	{"US2-FED", "api.us2.ddog-gov.com", "http-intake.logs.us2.ddog-gov.com", "event-management-intake.us2.ddog-gov.com"},
}

// Real request shapes from Datadog's API reference and official clients.
func datadogUseCases(api, logs, events string) []ddCase {
	now := time.Now().Unix()
	return []ddCase{
		{name: "validate API key", method: "GET", url: "https://" + api + "/api/v1/validate", header: apiKeyOnly, id: "Validate", effects: []string{"read"}, outcome: "allow"},
		{name: "query metrics v1", method: "GET", url: fmt.Sprintf("https://%s/api/v1/query?from=%d&to=%d&query=avg:system.cpu.user{*}by{host}", api, now-3600, now), id: "QueryMetrics", effects: []string{"read"}, outcome: "allow"},
		{name: "query timeseries v2", method: "POST", url: "https://" + api + "/api/v2/query/timeseries",
			body: fmt.Sprintf(`{"data":{"type":"timeseries_request","attributes":{"from":%d,"to":%d,"interval":5000,"queries":[{"data_source":"metrics","query":"avg:system.cpu.user{*}","name":"a"}],"formulas":[{"formula":"a"}]}}}`, (now-3600)*1000, now*1000),
			id:   "QueryTimeseriesData", effects: []string{"read"}, outcome: "allow"},
		{name: "query scalar v2", method: "POST", url: "https://" + api + "/api/v2/query/scalar",
			body: fmt.Sprintf(`{"data":{"type":"scalar_request","attributes":{"from":%d,"to":%d,"queries":[{"data_source":"metrics","query":"avg:system.cpu.user{*}","aggregator":"avg","name":"a"}]}}}`, (now-3600)*1000, now*1000),
			id:   "QueryScalarData", effects: []string{"read"}, outcome: "allow"},
		{name: "list active metrics", method: "GET", url: fmt.Sprintf("https://%s/api/v1/metrics?from=%d", api, now-3600), id: "ListActiveMetrics", effects: []string{"read"}, outcome: "allow"},
		{name: "search logs", method: "POST", url: "https://" + api + "/api/v2/logs/events/search",
			body:    `{"filter":{"query":"service:web status:error","from":"now-15m","to":"now","indexes":["main"]},"sort":"-timestamp","page":{"limit":25}}`,
			effects: []string{"read"}, action: "logs.events.read", outcome: "allow"},
		{name: "list logs GET", method: "GET", url: "https://" + api + "/api/v2/logs/events?filter%5Bquery%5D=service%3Aweb&filter%5Bfrom%5D=now-15m&filter%5Bto%5D=now&page%5Blimit%5D=10",
			effects: []string{"read"}, action: "logs.events.read", outcome: "allow"},
		{name: "list logs v1", method: "POST", url: "https://" + api + "/api/v1/logs-queries/list",
			body: `{"query":"service:web","time":{"from":"now-1h","to":"now"},"limit":10,"sort":"desc"}`, id: "ListLogs", effects: []string{"read"}, outcome: "allow"},
		{name: "aggregate logs", method: "POST", url: "https://" + api + "/api/v2/logs/analytics/aggregate",
			body: `{"compute":[{"aggregation":"count","type":"total"}],"filter":{"query":"*","from":"now-15m","to":"now"},"group_by":[{"facet":"service"}]}`,
			id:   "AggregateLogs", effects: []string{"read"}, outcome: "allow"},
		{name: "submit metrics v2", method: "POST", url: "https://" + api + "/api/v2/series", header: apiKeyOnly,
			body:   fmt.Sprintf(`{"series":[{"metric":"agent.deploys","type":1,"points":[{"timestamp":%d,"value":1}],"tags":["env:test"]}]}`, now),
			action: "series.write", effects: []string{"write"}, outcome: "allow"},
		{name: "submit metrics v1", method: "POST", url: "https://" + api + "/api/v1/series", header: apiKeyOnly,
			body: fmt.Sprintf(`{"series":[{"metric":"agent.deploys","points":[[%d,1]],"type":"count","tags":["env:test"]}]}`, now),
			id:   "SubmitMetrics", effects: []string{"write"}, outcome: "allow"},
		{name: "submit service check", method: "POST", url: "https://" + api + "/api/v1/check_run", header: apiKeyOnly,
			body: `[{"check":"app.ok","host_name":"web-1","status":0,"tags":["env:test"]}]`, id: "SubmitServiceCheck", effects: []string{"write"}, outcome: "allow"},
		{name: "submit logs", method: "POST", url: "https://" + logs + "/api/v2/logs?ddtags=env%3Atest", header: apiKeyOnly,
			body: `[{"ddsource":"agent","ddtags":"env:test","hostname":"web-1","message":"deployed","service":"web"}]`,
			id:   "SubmitLog", action: "logs.write", effects: []string{"write"}, parameters: map[string]any{"ddtags": "env:test"}, outcome: "allow"},
		{name: "submit logs v1 input", method: "POST", url: "https://" + logs + "/v1/input", header: apiKeyOnly,
			body: `{"message":"deployed","service":"web"}`, id: "SubmitLog.v1", effects: []string{"write"}, outcome: "allow"},
		{name: "post event v1", method: "POST", url: "https://" + api + "/api/v1/events",
			body: `{"title":"Deploy finished","text":"web v42 deployed","tags":["env:test"],"alert_type":"info"}`, id: "CreateEvent", effects: []string{"write"}, outcome: "allow"},
		{name: "post event v2", method: "POST", url: "https://" + events + "/api/v2/events",
			body: `{"data":{"type":"event","attributes":{"category":"change","title":"Deploy","message":"web v42","attributes":{"changed_resource":{"name":"web","type":"feature_flag"}}}}}`,
			id:   "CreateEvent.v2", effects: []string{"write"}, outcome: "allow"},
		{name: "search events", method: "POST", url: "https://" + api + "/api/v2/events/search",
			body: `{"filter":{"query":"source:deploy","from":"now-1d","to":"now"},"page":{"limit":5}}`, action: "events.read", effects: []string{"read"}, outcome: "allow"},
		{name: "list monitors", method: "GET", url: "https://" + api + "/api/v1/monitor?page=0&page_size=50&monitor_tags=team%3Aweb", id: "ListMonitors", effects: []string{"read"}, outcome: "allow"},
		{name: "get monitor", method: "GET", url: "https://" + api + "/api/v1/monitor/12345", id: "GetMonitor", effects: []string{"read"}, parameters: map[string]any{"monitor_id": "12345"}, outcome: "allow"},
		{name: "validate monitor", method: "POST", url: "https://" + api + "/api/v1/monitor/validate",
			body: `{"name":"High CPU","type":"metric alert","query":"avg(last_5m):avg:system.cpu.user{*} > 90","message":"CPU high @slack-ops"}`, id: "ValidateMonitor", effects: []string{"read"}, outcome: "allow"},
		{name: "create monitor", method: "POST", url: "https://" + api + "/api/v1/monitor",
			body: `{"name":"High CPU","type":"metric alert","query":"avg(last_5m):avg:system.cpu.user{*} > 90","message":"CPU high","tags":["team:web"],"options":{"thresholds":{"critical":90}}}`,
			id:   "CreateMonitor", effects: []string{"write"}, parameters: map[string]any{"name": "High CPU"}, outcome: "allow"},
		{name: "update monitor", method: "PUT", url: "https://" + api + "/api/v1/monitor/12345", body: `{"message":"CPU high, see runbook"}`, id: "UpdateMonitor", effects: []string{"write"}, outcome: "allow"},
		{name: "delete monitor", method: "DELETE", url: "https://" + api + "/api/v1/monitor/12345", id: "DeleteMonitor", effects: []string{"delete"}, outcome: "allow"},
		{name: "create downtime", method: "POST", url: "https://" + api + "/api/v2/downtime",
			body:   `{"data":{"type":"downtime","attributes":{"scope":"env:staging","monitor_identifier":{"monitor_tags":["team:web"]},"schedule":{"start":null},"message":"maintenance"}}}`,
			action: "downtime.write", effects: []string{"write"}, outcome: "allow"},
		{name: "cancel downtime", method: "DELETE", url: "https://" + api + "/api/v2/downtime/00e000000-0000-1234-0000-000000000000", action: "downtime.delete", effects: []string{"delete"}, outcome: "allow"},
		{name: "list dashboards", method: "GET", url: "https://" + api + "/api/v1/dashboard?filter%5Bshared%5D=false", id: "ListDashboards", effects: []string{"read"}, outcome: "allow"},
		{name: "get dashboard", method: "GET", url: "https://" + api + "/api/v1/dashboard/abc-def-ghi", id: "GetDashboard", effects: []string{"read"}, parameters: map[string]any{"dashboard_id": "abc-def-ghi"}, outcome: "allow"},
		{name: "create dashboard", method: "POST", url: "https://" + api + "/api/v1/dashboard",
			body: `{"title":"Service overview","layout_type":"ordered","widgets":[{"definition":{"type":"timeseries","requests":[{"q":"avg:system.cpu.user{*}"}]}}]}`,
			id:   "CreateDashboard", effects: []string{"write"}, outcome: "allow"},
		{name: "share dashboard publicly", method: "POST", url: "https://" + api + "/api/v1/dashboard/public",
			body: `{"dashboard_id":"abc-def-ghi","dashboard_type":"custom_timeboard","share_type":"open"}`, id: "CreatePublicDashboard", effects: []string{"publish"}, outcome: "ask"},
		{name: "list hosts", method: "GET", url: "https://" + api + "/api/v1/hosts?filter=env%3Aprod&count=100", id: "ListHosts", effects: []string{"read"}, outcome: "allow"},
		{name: "mute host", method: "POST", url: "https://" + api + "/api/v1/host/web-1/mute", body: `{"message":"deploying","override":false}`, id: "MuteHost", effects: []string{"write"}, outcome: "allow"},
		{name: "create incident", method: "POST", url: "https://" + api + "/api/v2/incidents",
			body: `{"data":{"type":"incidents","attributes":{"title":"Checkout errors","customer_impacted":false}}}`, id: "CreateIncident", effects: []string{"write"}, outcome: "allow"},
		{name: "list SLOs", method: "GET", url: "https://" + api + "/api/v1/slo?limit=10", id: "ListSLOs", effects: []string{"read"}, outcome: "allow"},
		{name: "SLO history", method: "GET", url: fmt.Sprintf("https://%s/api/v1/slo/abc123/history?from_ts=%d&to_ts=%d", api, now-86400, now), id: "GetSLOHistory", effects: []string{"read"}, outcome: "allow"},
		{name: "search spans", method: "POST", url: "https://" + api + "/api/v2/spans/events/search",
			body: `{"data":{"type":"search_request","attributes":{"filter":{"query":"service:web","from":"now-15m","to":"now"},"page":{"limit":25},"sort":"timestamp"}}}`,
			id:   "ListSpans", effects: []string{"read"}, outcome: "allow"},
		{name: "search RUM", method: "POST", url: "https://" + api + "/api/v2/rum/events/search",
			body: `{"filter":{"query":"@type:session","from":"now-15m","to":"now"},"page":{"limit":25}}`, id: "SearchRUMEvents", effects: []string{"read"}, outcome: "allow"},
		{name: "search audit", method: "POST", url: "https://" + api + "/api/v2/audit/events/search",
			body: `{"filter":{"query":"@evt.name:Request","from":"now-15m","to":"now"},"page":{"limit":10}}`, action: "audit.events.read", effects: []string{"read"}, outcome: "allow"},
		{name: "trigger synthetics", method: "POST", url: "https://" + api + "/api/v1/synthetics/tests/trigger",
			body: `{"tests":[{"public_id":"abc-def-ghi"}]}`, id: "TriggerTests", effects: []string{"execute"}, outcome: "allow"},
		{name: "create API key", method: "POST", url: "https://" + api + "/api/v2/api_keys",
			body: `{"data":{"type":"api_keys","attributes":{"name":"agent key"}}}`, action: "api_keys.admin", effects: []string{"admin"}, outcome: "allow"},
		{name: "list v1 API keys", method: "GET", url: "https://" + api + "/api/v1/api_key", id: "ListAPIKeys", effects: []string{"admin"}, outcome: "allow"},
		{name: "invite users", method: "POST", url: "https://" + api + "/api/v2/user_invitations",
			body: `{"data":[{"type":"user_invitations","relationships":{"user":{"data":{"type":"users","id":"00000000-0000-0000-0000-000000000000"}}}}]}`,
			id:   "SendInvitations", effects: []string{"admin", "send", "share"}, outcome: "allow"},
		{name: "page on-call", method: "POST", url: "https://navy.oncall.datadoghq.com/api/v2/on-call/pages",
			body: `{"data":{"type":"pages","attributes":{"title":"Checkout down","urgency":"high","target":{"type":"team_handle","identifier":"web"}}}}`,
			id:   "CreateOnCallPage", effects: []string{"send"}, outcome: "allow"},
		{name: "unknown endpoint", method: "GET", url: "https://" + api + "/api/v9/not-a-route", outcome: "ask"},
	}
}

func TestDatadogUseCases(t *testing.T) {
	h := newDatadogHarness(t, "allow")
	for _, site := range ddSites {
		for _, c := range datadogUseCases(site.api, site.logs, site.events) {
			t.Run(site.name+"/"+c.name, func(t *testing.T) { checkCase(t, h, c) })
		}
	}
}

func TestDatadogCredentialPlacement(t *testing.T) {
	h := newDatadogHarness(t, "allow")
	check := func(r ddResult, header string, want ...string) {
		t.Helper()
		if r.forwarded == nil {
			t.Fatalf("not forwarded: %d %s %+v", r.status, r.body, r.gate)
		}
		if got := r.forwarded.Header.Values(header); !slices.Equal(got, want) {
			t.Fatalf("%s = %q, want %q", header, got, want)
		}
	}
	for _, site := range ddSites {
		r := h.do(ddRequest(t, "GET", "https://"+site.api+"/api/v1/monitor", "", bothKeys))
		check(r, "Dd-Api-Key", ddAPIKey)
		check(r, "Dd-Application-Key", ddAppKey)
	}

	// Header names are case-insensitive, as the official clients send them in different cases.
	r := h.do(ddRequest(t, "GET", "https://api.datadoghq.com/api/v1/monitor", "", map[string]string{"dd-api-key": ddAPIHolder, "Dd-Application-Key": ddAppHolder}))
	check(r, "Dd-Api-Key", ddAPIKey)
	check(r, "Dd-Application-Key", ddAppKey)

	// The API key alone reaches intake routes; no application key is invented.
	r = h.do(ddRequest(t, "POST", "https://api.datadoghq.eu/api/v2/series", `{"series":[]}`, apiKeyOnly))
	check(r, "Dd-Api-Key", ddAPIKey)
	check(r, "Dd-Application-Key")

	// Legacy v1 query-string keys are replaced and never captured in the request's facts.
	r = h.do(ddRequest(t, "GET", "https://api.datadoghq.com/api/v1/hosts?api_key="+ddAPIHolder+"&application_key="+ddAppHolder+"&count=5", "", nil))
	if r.forwarded == nil || r.gate.Operation == nil || r.gate.Operation.ID != "ListHosts" {
		t.Fatalf("query keys: %+v", r)
	}
	q, _ := url.ParseQuery(r.forwarded.RawQuery)
	if q.Get("api_key") != ddAPIKey || q.Get("application_key") != ddAppKey || q.Get("count") != "5" {
		t.Fatalf("forwarded query %s", r.forwarded.RawQuery)
	}
	if facts := mustJSON(r.gate.Facts); strings.Contains(facts, `"api_key":`) || strings.Contains(facts, "application_key=") || strings.Contains(facts, "tfm_") {
		t.Fatalf("query credentials leaked into facts: %s", facts)
	}

	// The legacy logs intake takes the API key as a path segment.
	r = h.do(ddRequest(t, "POST", "https://http-intake.logs.datadoghq.com/v1/input/"+ddAPIHolder+"?ddtags=env%3Atest", `{"message":"hi"}`, map[string]string{}))
	if r.forwarded == nil || r.forwarded.Path != "/v1/input/"+ddAPIKey || r.gate.Operation == nil || r.gate.Operation.ID != "SubmitLog.v1.path_key" {
		t.Fatalf("path key: %+v", r)
	}

	// A real key sent in the query is fingerprinted before capture.
	r = h.do(ddRequest(t, "GET", "https://api.datadoghq.com/api/v1/hosts?api_key=leaked-real-key", "", map[string]string{}))
	if strings.Contains(mustJSON(r.gate.Facts), "leaked-real-key") {
		t.Fatalf("a raw query key reached the facts: %s", mustJSON(r.gate.Facts))
	}

	// Refusals: a placeholder in the wrong header, a repeated placeholder, or an unknown placeholder.
	for name, header := range map[string]map[string]string{
		"application key in API key header": {"DD-API-KEY": ddAppHolder},
		"API key in Authorization":          {"Authorization": "Bearer " + ddAPIHolder},
		"unknown placeholder":               {"DD-API-KEY": "tfm_datadog_unknown"},
		"padded placeholder":                {"DD-API-KEY": " " + ddAPIHolder + "x"},
	} {
		r := h.do(ddRequest(t, "GET", "https://api.datadoghq.com/api/v1/monitor", "", header))
		if r.status != http.StatusForbidden || r.forwarded != nil || r.gate.Invalid == nil {
			t.Fatalf("%s: status %d forwarded %v invalid %v", name, r.status, r.forwarded != nil, r.gate.Invalid)
		}
	}
}

func TestDatadogClaims(t *testing.T) {
	h := newDatadogHarness(t, "allow")
	for _, site := range ddSites {
		for _, host := range []string{site.api, site.logs, site.events} {
			if h.setup.Claim(connector.Target{Network: "tcp", Host: host, Port: 443}) < 0 {
				t.Errorf("%s is not claimed", host)
			}
		}
	}
	for _, host := range []string{"datadoghq.com.evil.example", "evil-datadoghq.com", "datadoghq.com", "api.datadoghq.co", "api.datadoghq.com.example", "example.com", "browser-intake-datadoghq.com"} {
		if h.setup.Claim(connector.Target{Network: "tcp", Host: host, Port: 443}) >= 0 {
			t.Errorf("%s is claimed", host)
		}
	}
	if h.setup.Claim(connector.Target{Network: "tcp", Host: "api.datadoghq.com", Port: 80}) >= 0 {
		t.Errorf("plain HTTP is claimed")
	}
	if !slices.Equal(h.setup.SecretNames, []string{"api_key", "application_key"}) {
		t.Errorf("secret names %v", h.setup.SecretNames)
	}
}

func TestDatadogAccessLevels(t *testing.T) {
	read := newDatadogHarness(t, "read")
	for _, c := range []ddCase{
		{method: "POST", url: "https://api.datadoghq.com/api/v2/logs/events/search", body: `{"filter":{"query":"*"}}`, action: "logs.events.read", effects: []string{"read"}, outcome: "allow"},
		{method: "POST", url: "https://api.datadoghq.com/api/v2/query/timeseries", body: `{"data":{"type":"timeseries_request","attributes":{"from":1,"to":2,"queries":[]}}}`, id: "QueryTimeseriesData", effects: []string{"read"}, outcome: "allow"},
		{method: "POST", url: "https://api.datadoghq.com/api/v1/monitor", body: `{"name":"x","type":"metric alert","query":"q"}`, id: "CreateMonitor", effects: []string{"write"}, outcome: "deny"},
		{method: "DELETE", url: "https://api.datadoghq.com/api/v1/dashboard/abc-def-ghi", id: "DeleteDashboard", effects: []string{"delete"}, outcome: "deny"},
		{method: "GET", url: "https://api.datadoghq.com/api/v9/unknown", outcome: "deny"},
	} {
		t.Run("read "+c.method+" "+c.url, func(t *testing.T) { checkCase(t, read, c) })
	}
	ask := newDatadogHarness(t, "ask")
	for _, c := range []ddCase{
		{method: "GET", url: "https://api.datadoghq.com/api/v1/monitor", id: "ListMonitors", effects: []string{"read"}, outcome: "allow"},
		{method: "POST", url: "https://api.datadoghq.com/api/v1/monitor", body: `{"name":"x","type":"metric alert","query":"q"}`, id: "CreateMonitor", effects: []string{"write"}, outcome: "ask"},
	} {
		t.Run("ask "+c.method+" "+c.url, func(t *testing.T) { checkCase(t, ask, c) })
	}
}

func TestDatadogPresetReview(t *testing.T) {
	presets, _, err := config.LoadPresets(nil)
	if err != nil {
		t.Fatal(err)
	}
	var preset struct {
		HTTP struct {
			Operations map[string]struct {
				Method, Path, Origin string
				Effects              []string
			} `json:"operations"`
		} `json:"http"`
	}
	if err := json.Unmarshal(presets["datadog"].Source, &preset); err != nil {
		t.Fatal(err)
	}
	if len(preset.HTTP.Operations) < 2000 {
		t.Fatalf("only %d operations", len(preset.HTTP.Operations))
	}
	reads := map[string]bool{}
	for id, o := range preset.HTTP.Operations {
		if o.Method == "GET" && !slices.Contains(o.Effects, "read") && !slices.Contains(o.Effects, "admin") {
			t.Errorf("%s: GET without read effects %v", id, o.Effects)
		}
		if o.Method == "DELETE" && !slices.Contains(o.Effects, "delete") {
			t.Errorf("%s: DELETE without delete effect %v", id, o.Effects)
		}
		if slices.Equal(o.Effects, []string{"read"}) {
			reads[o.Method+" "+o.Path] = true
		}
	}
	// Searches and queries sent as POST bodies change nothing.
	for _, route := range []string{
		"POST /api/v2/logs/events/search", "POST /api/v1/logs-queries/list", "POST /api/v2/query/timeseries", "POST /api/v2/query/scalar",
		"POST /api/v2/spans/events/search", "POST /api/v2/rum/events/search", "POST /api/v2/events/search", "POST /api/v2/audit/events/search",
		"POST /api/v2/logs/analytics/aggregate", "POST /api/v2/spans/analytics/aggregate", "POST /api/v2/security_monitoring/signals/search",
		"POST /api/v1/monitor/validate", "GET /api/v1/query",
	} {
		if !reads[route] {
			t.Errorf("%s is not read-only", route)
		}
	}
}

// TestDatadogOfficialPythonClient drives the official datadog-api-client through the connector as an
// HTTPS proxy. Set DATADOG_SDK_PYTHON to a Python with datadog-api-client installed to run it.
func TestDatadogOfficialPythonClient(t *testing.T) {
	python := os.Getenv("DATADOG_SDK_PYTHON")
	if python == "" {
		t.Skip("DATADOG_SDK_PYTHON is not set")
	}
	h := newDatadogHarness(t, "allow")
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := &http.Server{Handler: netx.Connect(func(ctx context.Context, network, host string, port uint32, accept func() (net.Conn, error)) error {
		conn, err := accept()
		if err != nil {
			return err
		}
		h.instance.Serve(context.Background(), conn, ddConnection, connector.Target{Network: network, Host: host, Port: port}, h.gate)
		return nil
	})}
	go proxy.Serve(ln)
	defer proxy.Close()

	cmd := exec.Command(python, "-I", "testdata/datadog_sdk.py")
	cmd.Env = append(os.Environ(), "DD_PROXY=http://"+ln.Addr().String(), "DD_CA="+os.Getenv("SSL_CERT_FILE"), "DD_API_KEY="+ddAPIHolder, "DD_APP_KEY="+ddAppHolder)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("SDK run failed: %v\n%s", err, out)
	}
	var calls []struct{ Site, Call string }
	if err := json.Unmarshal(bytes.TrimSpace(out[bytes.LastIndexByte(bytes.TrimSpace(out), '\n')+1:]), &calls); err != nil {
		t.Fatalf("SDK output: %v\n%s", err, out)
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.forwarded) != len(calls) {
		t.Fatalf("%d SDK calls, %d forwarded\n%s", len(calls), len(h.forwarded), out)
	}
	for i, g := range h.gated {
		if g.Invalid != nil || g.Operation == nil || !g.Decision.Allow {
			t.Errorf("SDK call %v: invalid %v operation %v decision %+v", calls[i], g.Invalid, g.Operation, g.Decision)
			continue
		}
		f := h.forwarded[i]
		checkNoPlaceholders(t, &f)
		if f.Header.Get("Dd-Api-Key") != ddAPIKey {
			t.Errorf("SDK call %v: API key not placed", calls[i])
		}
		t.Logf("%s %-40s -> %s %s%s (%s, %v)", calls[i].Site, calls[i].Call, f.Method, f.Host, f.Path, g.Operation.ID, g.Operation.Effects)
	}
}
