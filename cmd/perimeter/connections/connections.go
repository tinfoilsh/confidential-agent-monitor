package connections

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/coder/websocket"
	gosmtp "github.com/emersion/go-smtp"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/config"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/format"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/sandbox"
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

const (
	Domain             = ".perimeter"
	placeholderPrefix  = "tfm_"
	maxBodyBytes       = 8 << 20
	maxSignedBodyBytes = 16 << 20
	DialTimeout        = 30 * time.Second
	RelayDrain         = 10 * time.Second
	upstreamTimeout    = 30 * time.Second
	maxMailBytes       = 25 << 20
	maxMQTTPacket      = 1 << 20
	maxMQTTPending     = 16
)

var (
	sftpLimits = session.SFTPLimits{Packet: 1 << 20, Handles: 1024}
	cliLimits  = session.Limits{Stdin: 1 << 20, WaitDelay: time.Second}
	natsLimits = nats.Limits{Payload: 1 << 20, Line: 8192, Subscriptions: 1024, PendingMessages: 128, PendingBytes: 4 << 20, Timeout: upstreamTimeout}
)

var (
	protocols     = []string{"tcp", "http", "mcp", "ssh", "sftp", "cli", "mqtt", "nats", "imap", "smtp", "redis", "postgres", "ssh-agent", "gpg-agent", "tinfoil", "tinfoil-mcp"}
	hostProtocols = []string{"cli", "gpg-agent"}
)

func Registered(protocol string, development bool) bool {
	return slices.Contains(protocols, protocol) && (development || !slices.Contains(hostProtocols, protocol))
}

type dialFunc = func(ctx context.Context, network, address string) (net.Conn, error)

const (
	protocolIdentity       = "perimeter"
	mcpVersion             = "0.1.0"
	websocketResponseLimit = -1
)

func connectorSSH(host ssh.Signer) *ssh.ServerConfig {
	server := &ssh.ServerConfig{NoClientAuth: true}
	if host != nil {
		server.AddHostKey(host)
	}
	return server
}

type RequestContext struct {
	Label    format.Label `json:"label"`
	Sends    string       `json:"sends"`
	Observes format.Label `json:"observes"`
}

type Setup struct {
	config.ConnectionSpec
	Claim             func(string, uint32) int
	Hosts             []string
	Discovery         []string
	Slots             any
	Operations        map[string]config.OperationSummary
	SecretNames       []string
	PerMessage        bool
	ListsPlaceholders bool
	HostKey           bool
	Hint              func(o *facts.Observation, c *RequestContext) error
	Open              func(ctx context.Context, h worker.Host) (worker.Instance, error)
}

func Parse(spec config.ConnectionSpec) (*Setup, error) {
	p := &Setup{ConnectionSpec: spec, Hint: func(*facts.Observation, *RequestContext) error { return nil }}
	serveHTTP := func(ctx context.Context, c net.Conn, server *http.Server) error {
		return netx.ServeConn(ctx, c, server)
	}
	relay := func(ctx context.Context, a, b net.Conn) { netx.Relay(ctx, a, b, RelayDrain) }
	switch spec.Protocol {
	case "tcp":
		t, err := tcp.Parse(spec.Config)
		if err != nil {
			return nil, err
		}
		p.Claim, p.Hosts = t.Claim, t.Hosts
		p.Hint = func(_ *facts.Observation, c *RequestContext) error {
			c.Sends, c.Observes = "anyone", format.Label{Audience: "me", Trust: "untrusted"}
			return nil
		}
		p.Open = func(_ context.Context, h worker.Host) (worker.Instance, error) {
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
			p.Discovery = setup.Hosts
		}
		p.Claim, p.Hosts, p.Slots, p.SecretNames, p.PerMessage, p.ListsPlaceholders = setup.Claim, setup.Hosts, set, set.Names(), true, true
		sends := map[string]string{}
		if setup.Preset != nil {
			p.Operations = map[string]config.OperationSummary{}
			for id, op := range setup.Preset.Operations {
				if len(op.Effects) == 0 {
					return nil, fmt.Errorf("invalid operation %q", id)
				}
				var audience string
				if op.Sends != nil && json.Unmarshal(op.Sends, &audience) != nil || !config.ValidEffects(op.Effects) || !validSends(audience) {
					return nil, fmt.Errorf("invalid effects or audience for operation %s", id)
				}
				p.Operations[id], sends[id] = config.OperationSummary{Action: op.Action, Effects: op.Effects}, audience
			}
		}
		p.Hint = func(o *facts.Observation, c *RequestContext) error {
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
		p.Open = func(ctx context.Context, h worker.Host) (worker.Instance, error) {
			if enclave != nil {
				return enclave.open(ctx, setup, h)
			}
			return worker.Instance{Serve: func(ctx context.Context, conn net.Conn, name, host string, port uint32, gate core.Gate) {
				transport := UpstreamTransport(h.Dial)
				defer transport.CloseIdleConnections()
				web.Handler{Setup: setup, Transport: transport, CheckRedirect: RefuseRedirects, Accept: websocket.AcceptOptions{}, UpstreamReadLimit: websocketResponseLimit,
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
		var sends string
		var observes *format.Label
		if pr := setup.Preset; pr != nil {
			if len(pr.Sends) != 0 && facts.DecodeNumbers(pr.Sends, &sends) != nil || len(pr.Observes) != 0 && facts.DecodeNumbers(pr.Observes, &observes) != nil ||
				!validSends(sends) || observes != nil && !config.ValidLabel(*observes) {
				return nil, errors.New("invalid MCP data-flow settings")
			}
		}
		p.Hosts, p.SecretNames = setup.Hosts(), []string{"token"}
		p.Hint = func(_ *facts.Observation, c *RequestContext) error {
			c.Sends = sends
			if observes != nil {
				c.Observes = *observes
			}
			return nil
		}
		p.Open = func(ctx context.Context, h worker.Host) (worker.Instance, error) {
			transport := UpstreamTransport(h.Dial)
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
			client := mcp.Client{HTTP: &http.Client{Transport: base, CheckRedirect: RefuseRedirects}, Timeout: upstreamTimeout, TLS: h.TLS, ServeHTTP: serveHTTP,
				ClientInfo: info, ServerInfo: info,
				Streamable: &mcpsdk.StreamableHTTPOptions{Stateless: true, PropagateRequestCancellation: true, DisableLocalhostProtection: true},
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
		p.Hosts, p.SecretNames, p.HostKey = hosts, []string{"key"}, true
		p.Open = func(_ context.Context, h worker.Host) (worker.Instance, error) {
			return worker.Instance{Serve: handler(h.Dial, connectorSSH(h.HostKey), func(ctx context.Context) (string, error) { return h.Secret(ctx, "key") })}, nil
		}
	case "cli":
		c, err := session.ParseCLI(spec.Config)
		if err != nil {
			return nil, err
		}
		p.SecretNames, p.HostKey = c.Credentials, true
		p.Open = func(_ context.Context, h worker.Host) (worker.Instance, error) {
			return worker.Instance{Serve: c.Handler(connectorSSH(h.HostKey), h.Secret, cliLimits, protocolIdentity)}, nil
		}
	case "ssh-agent":
		c, err := signer.ParseSSHAgent(spec.Config)
		if err != nil {
			return nil, err
		}
		p.SecretNames = c.Credentials
		p.Open = func(_ context.Context, h worker.Host) (worker.Instance, error) {
			return worker.Instance{Serve: c.Handler(h.Secret)}, nil
		}
	case "gpg-agent":
		c, err := signer.ParseGPGAgent(spec.Config)
		if err != nil {
			return nil, err
		}
		p.Open = func(context.Context, worker.Host) (worker.Instance, error) {
			return worker.Instance{Serve: c.Handler((&net.Dialer{Timeout: DialTimeout}).DialContext)}, nil
		}
	case "imap", "smtp", "redis", "mqtt", "nats", "postgres":
		return parseEndpoint(p, spec)
	default:
		return nil, fmt.Errorf("unknown kind %s", spec.Protocol)
	}
	p.Claim = sandbox.RouteClaim(p.Hosts, p.Claim)
	return p, nil
}

func parseEndpoint(p *Setup, spec config.ConnectionSpec) (*Setup, error) {
	var hosts []string
	var handler func(h worker.Host) core.Serve
	password := func(h worker.Host) func(context.Context) (string, error) {
		return func(ctx context.Context) (string, error) { return h.Secret(ctx, "password") }
	}
	p.SecretNames = []string{"password"}
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
					func(string, string, string) error { return nil },
					func(ctx context.Context, host string, backend gosmtp.Backend) *gosmtp.Server {
						server := gosmtp.NewServer(backend)
						server.Domain, server.AllowInsecureAuth = protocolIdentity, true
						server.MaxMessageBytes, server.TLSConfig = maxMailBytes, h.TLS(ctx, host)
						return server
					}, func(ctx context.Context, conn net.Conn) net.Listener { return netx.Listen(ctx, conn) })
			}
		}
		var options config.PolicyOptions
		json.Unmarshal(spec.Options, &options)
		p.Hint = func(o *facts.Observation, c *RequestContext) error {
			var details struct {
				SMTP struct {
					To []string `json:"to"`
				} `json:"smtp"`
			}
			raw, _ := json.Marshal(o.Details)
			json.Unmarshal(raw, &details)
			c.Sends = config.SendsConnection
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
		p.PerMessage = true
		p.Hint = connectionAudience
	case "nats":
		var c *nats.NATS
		if c, err = nats.Parse(spec.Config); err == nil {
			hosts = c.Hosts()
			handler = func(h worker.Host) core.Serve {
				return c.Preauthenticated(h.Dial, h.Secret, natsLimits, protocolIdentity)
			}
		}
		p.SecretNames, p.PerMessage = []string{"password", "token"}, true
		p.Hint = connectionAudience
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
	p.Hosts = hosts
	p.Open = func(_ context.Context, h worker.Host) (worker.Instance, error) {
		return worker.Instance{Serve: handler(h)}, nil
	}
	p.Claim = sandbox.RouteClaim(p.Hosts, p.Claim)
	return p, nil
}

func connectionAudience(_ *facts.Observation, c *RequestContext) error {
	c.Sends = config.SendsConnection
	return nil
}

func validSends(sends string) bool {
	return sends == "" || sends == config.SendsConnection || slices.Contains(config.Audiences, sends)
}

func UpstreamTransport(dial dialFunc) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = dial
	return transport
}

func RefuseRedirects(*http.Request, []*http.Request) error {
	return errors.New("redirects are refused")
}

var httpSlots = slots.Options{Prefix: placeholderPrefix, MaxSignedBody: maxSignedBodyBytes}
