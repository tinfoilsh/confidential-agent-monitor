package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"slices"
	"strings"
	"time"

	"code.dny.dev/ssrf"
	"github.com/coder/websocket"
	gosmtp "github.com/emersion/go-smtp"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/format"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/email"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/mcp"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/mqtt"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/nats"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/postgres"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/redis"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/session"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/signer"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/slots"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/tcp"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/web"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/worker"
	"github.com/tinfoilsh/confidential-agent-monitor/core"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/netx"
	"golang.org/x/crypto/ssh"
)

// Protocols: each connection's kind selects its parser, its host capabilities and its policy hints.
// The same selection opens a connector in process and in an isolated worker.

const (
	connectionDomain  = ".perimeter"
	placeholderPrefix = "tfm_"
	// HTTP bodies and WebSocket messages larger than this are opaque to policy.
	maxBodyBytes = 8 << 20
	// SigV4 signs bodies of at most this size.
	maxSignedBodyBytes   = 16 << 20
	connectorOpenTimeout = time.Minute
	dialTimeout          = 30 * time.Second
	upstreamTimeout      = 30 * time.Second
	maxWorkers           = 32
	maxMailBytes         = 25 << 20
	maxMQTTPacket        = 1 << 20
	// maxMQTTPending bounds the QoS 2 publishes awaiting release.
	maxMQTTPending   = 16
	workerBroker     = "/broker.sock"
	workerListenerFD = 3
)

// Deployed protocol and worker limits.
var (
	sftpLimits   = session.SFTPLimits{Packet: 1 << 20, Handles: 1024}
	cliLimits    = session.Limits{Stdin: 1 << 20, WaitDelay: time.Second}
	natsLimits   = nats.Limits{Payload: 1 << 20, Line: 8192, Subscriptions: 1024, PendingMessages: 128, PendingBytes: 4 << 20, Timeout: upstreamTimeout}
	workerLimits = worker.Limits{Streams: 128, Upstreams: 32, Handshake: dialTimeout, Credential: credentialTimeout, Sign: 10 * time.Second,
		Connections: 32, Idle: 8, PoolIdle: 30 * time.Second, Read: 10 * time.Second, ServeIdle: time.Minute, Drain: relayDrain}
)

// protocols are the connection kinds, which policies also see as protocols. hostProtocols reach
// host resources outside their grants, so only local development registers them.
var (
	protocols     = []string{"tcp", "http", "mcp", "ssh", "sftp", "cli", "mqtt", "nats", "imap", "smtp", "redis", "postgres", "ssh-agent", "gpg-agent", "tinfoil", "tinfoil-mcp"}
	hostProtocols = []string{"cli", "gpg-agent"}
)

type dialFunc = func(ctx context.Context, network, address string) (net.Conn, error)

const (
	protocolIdentity       = "perimeter"
	mcpVersion             = "0.1.0"
	websocketResponseLimit = -1 // Stream responses, including images, without buffering a whole message.
)

// connectorSSH accepts streams whose agent the outer transport already authenticated.
func connectorSSH(host ssh.Signer) *ssh.ServerConfig {
	server := &ssh.ServerConfig{NoClientAuth: true}
	if host != nil {
		server.AddHostKey(host)
	}
	return server
}

// operationSummary is protocol-neutral catalog metadata, never an authorization input.
type operationSummary struct {
	Action  string   `json:"action"`
	Effects []string `json:"effects,omitempty"`
}

// parsed is one connection's setup as its protocol parsed it: what the table stages, what
// discovery and the catalog show, how policy reads its observations and how it opens.
type parsed struct {
	ConnectionSpec
	claim             func(string, uint32) int
	hosts             []string // upstream hosts and host patterns the setup names
	discovery         []string
	slots             any
	operations        map[string]operationSummary // nil: no operation listing
	secretNames       []string
	perMessage        bool // each operation is gated against captured input, so streams outlive label changes
	listsPlaceholders bool // agents send credential placeholders in place of secrets
	hostKey           bool // the connector authenticates as the Perimeter's SSH host
	// hint fills the sends and observes hints policy resolves for an observation and any effects
	// its protocol implies, or refuses an observation the product does not admit.
	hint func(o *facts.Observation, c *requestContext) error
	open func(ctx context.Context, h worker.Host) (worker.Instance, error)
}

// parseConnection selects spec's protocol. It validates and compiles the setup without I/O.
func parseConnection(spec ConnectionSpec) (*parsed, error) {
	p := &parsed{ConnectionSpec: spec, hint: func(*facts.Observation, *requestContext) error { return nil }}
	serveHTTP := func(ctx context.Context, c net.Conn, server *http.Server) error {
		return netx.ServeConn(ctx, c, server)
	}
	relay := func(ctx context.Context, a, b net.Conn) { netx.Relay(ctx, a, b, relayDrain) }
	switch spec.Protocol {
	case "tcp":
		t, err := tcp.Parse(spec.Config)
		if err != nil {
			return nil, err
		}
		p.claim, p.hosts = t.Claim, t.Hosts
		p.hint = func(_ *facts.Observation, c *requestContext) error {
			c.Sends, c.Observes = "anyone", format.Label{Audience: "me", Trust: "untrusted"}
			return nil
		}
		p.open = func(_ context.Context, h worker.Host) (worker.Instance, error) {
			return worker.Instance{Serve: t.Handler(h.Dial, relay)}, nil
		}
	case "http", "tinfoil":
		var set slots.Set
		parseSlots := func(raw json.RawMessage) (web.Slots, error) {
			var err error
			set, err = slots.Parse(raw, httpSlots)
			return web.Slots{Claim: set.Claim, Covers: set.Covers, Bind: set.Bind}, err
		}
		var setup *web.Setup
		var enclave *tinfoilSetup
		var err error
		if spec.Protocol == "http" {
			setup, err = web.Parse(spec.Config, spec.Definition, spec.Options, parseSlots)
		} else {
			enclave, setup, set, err = parseTinfoil(spec)
		}
		if err != nil {
			return nil, err
		}
		if enclave == nil {
			p.discovery = setup.Hosts
		}
		p.claim, p.hosts, p.slots, p.secretNames, p.perMessage, p.listsPlaceholders = setup.Claim, setup.Hosts, set, set.Names(), true, true
		sends := map[string]string{}
		if setup.Preset != nil {
			p.operations = map[string]operationSummary{}
			for id, op := range setup.Preset.Operations {
				// The product requires every reviewed operation to declare its effects.
				if len(op.Effects) == 0 {
					return nil, fmt.Errorf("invalid operation %q", id)
				}
				var audience string
				if op.Sends != nil && json.Unmarshal(op.Sends, &audience) != nil || !validEffects(op.Effects) || !validSends(audience) {
					return nil, fmt.Errorf("invalid effects or audience for operation %s", id)
				}
				p.operations[id], sends[id] = operationSummary{Action: op.Action, Effects: op.Effects}, audience
			}
		}
		p.hint = func(o *facts.Observation, c *requestContext) error {
			var details struct {
				HTTP struct {
					WebSocket bool   `json:"websocket"`
					Method    string `json:"method"`
				} `json:"http"`
			}
			raw, _ := json.Marshal(o.Details)
			json.Unmarshal(raw, &details)
			switch {
			case details.HTTP.WebSocket && details.HTTP.Method == "":
				// A received WebSocket message neither repeats the request's effects nor sends upstream;
				// the connection labels its entire opaque payload.
				c.Sends = "me"
				if o.Operation != nil {
					o.Operation.Effects = []string{"read"}
				}
			case details.HTTP.WebSocket && o.Operation == nil:
				return errors.New("WebSocket requests require a reviewed operation")
			case o.Operation != nil:
				c.Sends = sends[o.Operation.ID]
			}
			return nil
		}
		p.open = func(ctx context.Context, h worker.Host) (worker.Instance, error) {
			if enclave != nil {
				return enclave.open(ctx, setup, h)
			}
			return worker.Instance{Serve: func(ctx context.Context, conn net.Conn, name, host string, port uint32, gate core.Gate) {
				transport := upstreamTransport(h.Dial)
				defer transport.CloseIdleConnections()
				web.Handler{Setup: setup, Transport: transport, CheckRedirect: refuseRedirects, Accept: websocket.AcceptOptions{}, UpstreamReadLimit: websocketResponseLimit,
					TLS: h.TLS, ServeHTTP: serveHTTP, Placeholder: h.Placeholder, Secret: h.Secret, MaxBody: maxBodyBytes}.Serve(ctx, conn, name, host, port, gate)
			}}, nil
		}
	case "mcp", "tinfoil-mcp":
		var setup *mcp.Setup
		var repo string
		var err error
		if spec.Protocol == "mcp" {
			setup, err = mcp.Parse(spec.Config, spec.Definition)
		} else {
			setup, repo, err = parseTinfoilMCP(spec)
		}
		if err != nil {
			return nil, err
		}
		// A preset's data flow applies to every tool call.
		var sends string
		var observes *format.Label
		if pr := setup.Preset; pr != nil {
			if len(pr.Sends) != 0 && facts.DecodeNumbers(pr.Sends, &sends) != nil || len(pr.Observes) != 0 && facts.DecodeNumbers(pr.Observes, &observes) != nil ||
				!validSends(sends) || observes != nil && !validLabel(*observes) {
				return nil, errors.New("invalid MCP data-flow settings")
			}
		}
		p.hosts, p.secretNames = setup.Hosts(), []string{"token"}
		p.hint = func(_ *facts.Observation, c *requestContext) error {
			c.Sends = sends
			if observes != nil {
				c.Observes = *observes
			}
			return nil
		}
		p.open = func(ctx context.Context, h worker.Host) (worker.Instance, error) {
			transport := upstreamTransport(h.Dial)
			var base http.RoundTripper = transport
			closeTransport := transport.CloseIdleConnections
			if repo != "" {
				attested, err := attest(ctx, h, "token", setup.Hosts()[0], repo, transport)
				if err != nil {
					transport.CloseIdleConnections()
					return worker.Instance{}, err
				}
				base, closeTransport = attested, func() { attested.CloseIdleConnections(); transport.CloseIdleConnections() }
			}
			info := &mcpsdk.Implementation{Name: protocolIdentity, Version: mcpVersion}
			client := mcp.Client{HTTP: &http.Client{Transport: base, CheckRedirect: refuseRedirects}, Timeout: upstreamTimeout, TLS: h.TLS, ServeHTTP: serveHTTP,
				ClientInfo: info, ServerInfo: info,
				Streamable: &mcpsdk.StreamableHTTPOptions{Stateless: true, PropagateRequestCancellation: true, DisableLocalhostProtection: true},
				// Only tools and instructions the owner pinned are exposed.
				Expose: func(current *mcp.Snapshot) ([]*mcpsdk.Tool, string) {
					ok, _ := setup.Pin.Approved(current)
					if len(ok) > 0 {
						return ok, current.Instructions
					}
					return ok, ""
				}}
			if h.Configured("token") {
				client.Token = func(ctx context.Context) (string, error) { return h.Secret(ctx, "token") }
			}
			session, err := mcp.Open(ctx, setup, client)
			if err != nil {
				closeTransport()
				return worker.Instance{}, err
			}
			current := session.Snapshot()
			ok, _ := setup.Pin.Approved(current)
			status := map[string]any{"blocked": len(current.Tools) - len(ok)}
			if len(ok) < len(current.Tools) {
				status["changes"], status["pin"] = setup.Pin.Diff(current), current
			}
			details, _ := json.Marshal(status)
			return worker.Instance{Serve: session.Serve, Details: details, Close: func() error {
				err := session.Close()
				closeTransport()
				return err
			}}, nil
		}
	case "ssh", "sftp":
		var hosts []string
		var handler func(dialFunc, *ssh.ServerConfig, func(context.Context) (string, error)) core.Serve
		if spec.Protocol == "ssh" {
			c, err := session.ParseSSH(spec.Config)
			if err != nil {
				return nil, err
			}
			hosts, handler = c.Hosts(), c.Handler
		} else {
			c, err := session.ParseSFTP(spec.Config)
			if err != nil {
				return nil, err
			}
			hosts = c.Hosts()
			handler = func(dial dialFunc, server *ssh.ServerConfig, key func(context.Context) (string, error)) core.Serve {
				return c.Handler(dial, server, key, sftpLimits)
			}
		}
		p.hosts, p.secretNames, p.hostKey = hosts, []string{"key"}, true
		p.open = func(_ context.Context, h worker.Host) (worker.Instance, error) {
			return worker.Instance{Serve: handler(h.Dial, connectorSSH(h.HostKey), func(ctx context.Context) (string, error) { return h.Secret(ctx, "key") })}, nil
		}
	case "cli":
		c, err := session.ParseCLI(spec.Config)
		if err != nil {
			return nil, err
		}
		p.secretNames, p.hostKey = c.Credentials, true
		p.open = func(_ context.Context, h worker.Host) (worker.Instance, error) {
			return worker.Instance{Serve: c.Handler(connectorSSH(h.HostKey), h.Secret, cliLimits, protocolIdentity)}, nil
		}
	case "ssh-agent":
		c, err := signer.ParseSSHAgent(spec.Config)
		if err != nil {
			return nil, err
		}
		p.secretNames = c.Credentials
		p.open = func(_ context.Context, h worker.Host) (worker.Instance, error) {
			return worker.Instance{Serve: c.Handler(h.Secret)}, nil
		}
	case "gpg-agent":
		c, err := signer.ParseGPGAgent(spec.Config)
		if err != nil {
			return nil, err
		}
		p.open = func(context.Context, worker.Host) (worker.Instance, error) {
			// The agent socket is a host resource, dialed directly.
			return worker.Instance{Serve: c.Handler((&net.Dialer{Timeout: dialTimeout}).DialContext)}, nil
		}
	case "imap", "smtp", "redis", "mqtt", "nats", "postgres":
		return parseEndpoint(p, spec)
	default:
		return nil, fmt.Errorf("unknown kind %s", spec.Protocol)
	}
	p.claim = routeClaim(p.hosts, p.claim)
	return p, nil
}

// parseEndpoint selects the protocols that dial one upstream URL with a password.
func parseEndpoint(p *parsed, spec ConnectionSpec) (*parsed, error) {
	var hosts []string
	var handler func(h worker.Host) core.Serve
	password := func(h worker.Host) func(context.Context) (string, error) {
		return func(ctx context.Context) (string, error) { return h.Secret(ctx, "password") }
	}
	p.secretNames = []string{"password"}
	var err error
	switch spec.Protocol {
	case "imap":
		var c *email.IMAP
		if c, err = email.ParseIMAP(spec.Config); err == nil {
			hosts = c.Hosts()
			handler = func(h worker.Host) core.Serve { return c.Preauthenticated(h.Dial, password(h), protocolIdentity) }
		}
	case "smtp":
		var c *email.SMTP
		if c, err = email.ParseSMTP(spec.Config); err == nil {
			hosts = c.Hosts()
			handler = func(h worker.Host) core.Serve {
				return c.Handler(h.Dial, password(h),
					func(string, string, string) error { return nil }, // The outer transport authenticated the stream.
					func(ctx context.Context, host string, backend gosmtp.Backend) *gosmtp.Server {
						server := gosmtp.NewServer(backend)
						server.Domain, server.AllowInsecureAuth = protocolIdentity, true
						server.MaxMessageBytes, server.TLSConfig = maxMailBytes, h.TLS(ctx, host)
						return server
					}, func(ctx context.Context, conn net.Conn) net.Listener { return netx.Listen(ctx, conn) })
			}
		}
		var options PolicyOptions
		json.Unmarshal(spec.Options, &options)
		p.hint = func(o *facts.Observation, c *requestContext) error {
			var details struct {
				SMTP struct {
					To []string `json:"to"`
				} `json:"smtp"`
			}
			raw, _ := json.Marshal(o.Details)
			json.Unmarshal(raw, &details)
			// Mail to the connection's own address stays within its audience.
			c.Sends = sendsConnection
			for _, to := range details.SMTP.To {
				if !strings.EqualFold(to, options.Address) {
					c.Sends = "anyone"
				}
			}
			return nil
		}
	case "redis":
		var c *redis.Redis
		if c, err = redis.Parse(spec.Config); err == nil {
			hosts = c.Hosts()
			handler = func(h worker.Host) core.Serve { return c.Handler(h.Dial, password(h)) }
		}
	case "mqtt":
		var c *mqtt.MQTT
		if c, err = mqtt.Parse(spec.Config); err == nil {
			hosts = c.Hosts()
			handler = func(h worker.Host) core.Serve { return c.Handler(h.Dial, password(h), maxMQTTPacket, maxMQTTPending) }
		}
		p.perMessage = true
		p.hint = connectionAudience
	case "nats":
		var c *nats.NATS
		if c, err = nats.Parse(spec.Config); err == nil {
			hosts = c.Hosts()
			handler = func(h worker.Host) core.Serve {
				return c.Preauthenticated(h.Dial, h.Secret, natsLimits, protocolIdentity)
			}
		}
		p.secretNames, p.perMessage = []string{"password", "token"}, true
		p.hint = connectionAudience
	case "postgres":
		var c *postgres.Postgres
		if c, err = postgres.Parse(spec.Config); err == nil {
			hosts = c.Hosts()
			handler = func(h worker.Host) core.Serve { return c.Handler(h.Dial, password(h), h.TLS, upstreamTimeout) }
		}
	}
	if err != nil {
		return nil, err
	}
	p.hosts = hosts
	p.open = func(_ context.Context, h worker.Host) (worker.Instance, error) {
		return worker.Instance{Serve: handler(h)}, nil
	}
	p.claim = routeClaim(p.hosts, p.claim)
	return p, nil
}

// connectionAudience sends a pub/sub message to the connection's configured audience.
func connectionAudience(_ *facts.Observation, c *requestContext) error {
	c.Sends = sendsConnection
	return nil
}

func validSends(sends string) bool {
	return sends == "" || sends == sendsConnection || slices.Contains(audiences, sends)
}

// observe binds a connection's captured event to the facts policy and audit read: its
// protocol's hints, and its operation's lineage and effects from the preset's actions.
func (st *settings) observe(connection string, event facts.Event) (requestFacts, error) {
	o, err := event.Decode()
	f := requestFacts{Parameters: o.Parameters, Scope: o.Scope, Title: o.Title, Details: o.Details}
	c := st.connections[connection]
	if c == nil {
		return f, errChanged
	}
	if refused := c.hint(&o, &f.Context); err == nil {
		err = refused
	}
	if o.Operation != nil {
		f.Operation = resolveOperation(o.Operation.ID, o.Operation.Action, o.Operation.Effects, presets[st.Connections[connection].Preset].Catalog.Actions)
	}
	return f, err
}

// upstreamTransport sends a connector's requests through dial.
func upstreamTransport(dial dialFunc) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = dial
	return transport
}

// guardedDialer checks the resolved address, so DNS cannot steer an upstream into a refused range.
func guardedDialer(allowed []netip.Prefix) *net.Dialer {
	var v4, v6 []netip.Prefix
	for _, p := range allowed {
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	guard := ssrf.New(ssrf.WithAnyPort(), ssrf.WithAllowedV4Prefixes(v4...), ssrf.WithAllowedV6Prefixes(v6...))
	return &net.Dialer{Timeout: dialTimeout, Control: guard.Safe}
}

// client is for requests the Perimeter makes itself, such as OAuth.
func (st *settings) client() *http.Client {
	return &http.Client{Transport: upstreamTransport(guardedDialer(st.AllowNetworks).DialContext), CheckRedirect: refuseRedirects}
}

// refuseRedirects fails a redirect, which could carry a credential elsewhere.
func refuseRedirects(*http.Request, []*http.Request) error {
	return errors.New("redirects are refused")
}

// opener opens c's connector with st's capabilities, in this process or an isolated worker.
// Its dial reaches reserved route hosts only as its setup names them.
func (s *state) opener(st *settings, c *installed) core.Open {
	dial := s.routeDial(c.hosts, guardedDialer(st.AllowNetworks).DialContext)
	var hostKey ssh.Signer
	if c.hostKey {
		hostKey = st.hostKey
	}
	return func(ctx context.Context) (core.Connector, error) {
		if workers == nil {
			instance, err := c.open(ctx, worker.Host{Dial: dial, HostKey: hostKey, TLS: st.streamTLS,
				Secret:      func(ctx context.Context, name string) (string, error) { return c.secrets[name].Value(ctx) },
				Configured:  func(name string) bool { return c.secrets[name].Configured() },
				Placeholder: func(name string) string { return c.placeholders[name] },
			})
			return core.Connector{Serve: instance.Serve, Close: instance.Close, Details: instance.Details, Control: instance.Control}, err
		}
		data, err := json.Marshal(c.ConnectionSpec)
		if err != nil {
			return core.Connector{}, err
		}
		grants := worker.Grants{Connect: netx.Connect(netx.Dial(dial, relayDrain)), Secrets: map[string]worker.Secret{}, HostKey: hostKey,
			Certificate: func(name string) (*tls.Certificate, error) {
				return st.tls.GetCertificate(&tls.ClientHelloInfo{ServerName: name})
			}}
		for name, value := range c.secrets {
			grants.Secrets[name] = worker.Secret{Configured: value.Configured(), Placeholder: c.placeholders[name], Value: value.Value}
		}
		p, err := worker.Launch(ctx, workers.Start, data, grants, workerLimits)
		if err != nil {
			return core.Connector{}, err
		}
		return core.Connector{Serve: p.Serve, Close: p.Close, Ready: p.Ready, Details: p.Details(), Control: p.Control()}, nil
	}
}

// streamTLS is the server configuration for one stream; a client without SNI is issued the stream's host.
func (st *settings) streamTLS(_ context.Context, host string) *tls.Config {
	config := st.tls.Clone()
	issue := config.GetCertificate
	config.GetCertificate = func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if hello.ServerName == "" {
			named := *hello
			named.ServerName = host
			hello = &named
		}
		return issue(hello)
	}
	return config
}

// httpSlots place credentials in HTTP requests, never in form fields.
var httpSlots = slots.Options{Prefix: placeholderPrefix, MaxSignedBody: maxSignedBodyBytes}

// serveWorkerChild serves the one connection a Perimeter host launched this process for.
func serveWorkerChild() error {
	file := os.NewFile(workerListenerFD, "connector-listener")
	ln, err := net.FileListener(file)
	file.Close()
	if err != nil {
		return err
	}
	broker := func(ctx context.Context) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", workerBroker)
	}
	return worker.Serve(context.Background(), func(ctx context.Context, data json.RawMessage, h worker.Host) (worker.Instance, error) {
		var spec ConnectionSpec
		if err := json.Unmarshal(data, &spec); err != nil {
			return worker.Instance{}, err
		}
		p, err := parseConnection(spec)
		if err != nil {
			return worker.Instance{}, err
		}
		return p.open(ctx, h)
	}, os.Stdin, ln, broker, workerLimits)
}
