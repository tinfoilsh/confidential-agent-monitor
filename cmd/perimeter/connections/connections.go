package connections

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

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
	"github.com/tinfoilsh/confidential-agent-monitor/connector/tinfoil"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/udp"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/web"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/worker"
	"github.com/tinfoilsh/confidential-agent-monitor/core/connector"
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
	httpSlots  = slots.Options{Prefix: placeholderPrefix, MaxSignedBody: maxSignedBodyBytes}
)

var hostProtocols = []string{"cli", "gpg-agent"}

var parsers = map[string]func(config.ConnectionSpec, *Setup) error{
	"tcp":         parseTCP,
	"udp":         parseUDP,
	"http":        parseHTTP,
	"tinfoil":     parseTinfoil,
	"mcp":         parseMCP,
	"tinfoil-mcp": parseTinfoilMCP,
	"ssh":         parseSSH,
	"sftp":        parseSSH,
	"cli":         parseCLI,
	"ssh-agent":   parseSSHAgent,
	"gpg-agent":   parseGPGAgent,
	"imap":        parseEndpoint,
	"smtp":        parseEndpoint,
	"redis":       parseEndpoint,
	"mqtt":        parseEndpoint,
	"nats":        parseEndpoint,
	"postgres":    parseEndpoint,
}

func Registered(protocol string, development bool) bool {
	return parsers[protocol] != nil && (development || !slices.Contains(hostProtocols, protocol))
}

type dialFunc = func(ctx context.Context, network, address string) (net.Conn, error)

const (
	protocolIdentity = "perimeter"
	mcpVersion       = "0.1.0"
)

type RequestContext struct {
	Label    format.Label `json:"label"`
	Sends    string       `json:"sends"`
	Observes format.Label `json:"observes"`
}

type Setup struct {
	config.ConnectionSpec
	Network           string
	Claim             func(connector.Target) int
	Hosts             []string
	Discovery         []string
	Slots             any
	Operations        map[string]config.OperationSummary
	SecretNames       []string
	PerMessage        bool
	ListsPlaceholders bool
	HostKey           bool
	Hint              func(o *facts.Observation, c *RequestContext) error
	Open              func(ctx context.Context, h worker.Host) (connector.Instance, error)
}

func Parse(spec config.ConnectionSpec) (*Setup, error) {
	parse := parsers[spec.Protocol]
	if parse == nil {
		return nil, fmt.Errorf("unknown kind %s", spec.Protocol)
	}
	p := &Setup{ConnectionSpec: spec, Network: "tcp", Hint: func(*facts.Observation, *RequestContext) error { return nil }}
	if err := parse(spec, p); err != nil {
		return nil, err
	}
	p.Claim = sandbox.RouteClaim(p.Hosts, p.Claim)
	return p, nil
}

func Open(ctx context.Context, data json.RawMessage, h worker.Host) (connector.Instance, error) {
	var spec config.ConnectionSpec
	if err := json.Unmarshal(data, &spec); err != nil {
		return connector.Instance{}, err
	}
	p, err := Parse(spec)
	if err != nil {
		return connector.Instance{}, err
	}
	return p.Open(ctx, h)
}

func Placeholder(k format.Keys, id format.SecretID) string {
	mac := hmac.New(sha256.New, []byte(k.CAKey))
	mac.Write([]byte("monitor credential placeholder v1\x00"))
	raw, _ := json.Marshal([]string{id.Connection, "", id.Name})
	mac.Write(raw)
	suffix := strings.ToLower(base32.StdEncoding.EncodeToString(mac.Sum(nil))[:9])
	return placeholderPrefix + id.Connection + "_" + suffix
}

func parseTCP(spec config.ConnectionSpec, p *Setup) error {
	t, err := tcp.Parse(spec.Config)
	if err != nil {
		return err
	}
	p.Claim, p.Hosts = t.Claim, t.Hosts
	p.Hint = func(_ *facts.Observation, c *RequestContext) error {
		c.Sends, c.Observes = config.AudienceAnyone, format.Label{Audience: config.AudienceMe, Trust: config.TrustUntrusted}
		return nil
	}
	p.Open = func(_ context.Context, h worker.Host) (connector.Instance, error) {
		return connector.Instance{Serve: t.Handler(h.Dial, RelayDrain)}, nil
	}
	return nil
}

func parseUDP(spec config.ConnectionSpec, p *Setup) error {
	if err := parseTCP(spec, p); err != nil {
		return err
	}
	claim := p.Claim
	p.Network, p.PerMessage = "udp", true
	p.Open = func(_ context.Context, h worker.Host) (connector.Instance, error) {
		return connector.Instance{Serve: udp.Handler(claim, h.Dial)}, nil
	}
	return nil
}

func parseHTTP(spec config.ConnectionSpec, p *Setup) error {
	var set slots.Set
	setup, err := web.Parse(spec.Config, spec.Definition, spec.Options, func(raw json.RawMessage) (web.Slots, error) {
		var err error
		set, err = slots.Parse(raw, httpSlots)
		return set, err
	})
	if err != nil {
		return err
	}
	p.Discovery = setup.Hosts
	p.Open = func(_ context.Context, h worker.Host) (connector.Instance, error) {
		return connector.Instance{Serve: func(ctx context.Context, conn net.Conn, name string, target connector.Target, gate connector.Gate) {
			transport := netx.Transport(h.Dial)
			defer transport.CloseIdleConnections()
			web.Handler{Setup: setup, Transport: transport, TLS: h.TLS, Placeholder: h.Placeholder, Secret: h.Secret, MaxBody: maxBodyBytes}.Serve(ctx, conn, name, target, gate)
		}}, nil
	}
	return httpSetup(p, setup, set)
}

func httpSetup(p *Setup, setup *web.Setup, set slots.Set) error {
	p.Claim, p.Hosts = setup.Claim, setup.Hosts
	p.Slots, p.SecretNames = set, set.Names()
	p.PerMessage, p.ListsPlaceholders = true, true
	sends := map[string]string{}
	if setup.Preset != nil {
		p.Operations = map[string]config.OperationSummary{}
		for id, op := range setup.Preset.Operations {
			if len(op.Effects) == 0 {
				return fmt.Errorf("invalid operation %q", id)
			}
			var audience string
			if op.Sends != nil && json.Unmarshal(op.Sends, &audience) != nil || !config.ValidEffects(op.Effects) || !validSends(audience) {
				return fmt.Errorf("invalid effects or audience for operation %s", id)
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
			c.Sends = config.AudienceMe
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
	return nil
}

func parseTinfoil(spec config.ConnectionSpec, p *Setup) error {
	t, err := tinfoil.Parse(spec.Config)
	if err != nil {
		return err
	}
	set, err := slots.New([]slots.Slot{t.Slot()}, httpSlots)
	if err != nil {
		return err
	}
	setup, err := web.New(spec.Definition, spec.Options, nil, set)
	if err != nil {
		return err
	}
	p.Open = func(ctx context.Context, h worker.Host) (connector.Instance, error) {
		return t.Open(ctx, setup, h, Domain, maxBodyBytes)
	}
	return httpSetup(p, setup, set)
}

func parseMCP(spec config.ConnectionSpec, p *Setup) error {
	setup, err := mcp.Parse(spec.Config, spec.Definition)
	if err != nil {
		return err
	}
	return mcpSetup(p, setup, "")
}

func parseTinfoilMCP(spec config.ConnectionSpec, p *Setup) error {
	var cfg struct {
		mcp.Setup
		Repo string `json:"repo"`
	}
	if err := mcp.Decode(spec.Config, spec.Definition, &cfg, &cfg.Setup); err != nil {
		return err
	}
	u, _ := url.Parse(cfg.URL)
	if u.Scheme != "https" || u.User != nil {
		return errors.New("Tinfoil MCP requires an HTTPS URL without user information")
	}
	if err := tinfoil.Validate(u.Host, cfg.Repo); err != nil {
		return err
	}
	return mcpSetup(p, &cfg.Setup, cfg.Repo)
}

func mcpSetup(p *Setup, setup *mcp.Setup, repo string) error {
	var sends string
	var observes *format.Label
	if pr := setup.Preset; pr != nil {
		if len(pr.Sends) != 0 && facts.DecodeNumbers(pr.Sends, &sends) != nil || len(pr.Observes) != 0 && facts.DecodeNumbers(pr.Observes, &observes) != nil ||
			!validSends(sends) || observes != nil && !config.ValidLabel(*observes) {
			return errors.New("invalid MCP data-flow settings")
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
	p.Open = func(ctx context.Context, h worker.Host) (connector.Instance, error) {
		transport := netx.Transport(h.Dial)
		var base http.RoundTripper = transport
		closeTransport := transport.CloseIdleConnections
		if repo != "" {
			attested, err := tinfoil.Attest(ctx, h, "token", setup.Hosts()[0], repo, transport)
			if err != nil {
				transport.CloseIdleConnections()
				return connector.Instance{}, err
			}
			base, closeTransport = attested, func() { attested.CloseIdleConnections(); transport.CloseIdleConnections() }
		}
		client := mcp.Client{HTTP: &http.Client{Transport: base, CheckRedirect: netx.RefuseRedirects}, Timeout: upstreamTimeout, TLS: h.TLS,
			Name: protocolIdentity, Version: mcpVersion, Expose: setup.Pin.Expose}
		if h.Configured("token") {
			client.Token = func(ctx context.Context) (string, error) { return h.Secret(ctx, "token") }
		}
		mcpSession, err := mcp.Open(ctx, setup, client)
		if err != nil {
			closeTransport()
			return connector.Instance{}, err
		}
		return connector.Instance{Serve: mcpSession.Serve, Details: setup.Pin.Status(mcpSession.Snapshot()), Close: func() error {
			err := mcpSession.Close()
			closeTransport()
			return err
		}}, nil
	}
	return nil
}

func parseSSH(spec config.ConnectionSpec, p *Setup) error {
	var hosts []string
	var handler func(dialFunc, ssh.Signer, func(context.Context) (string, error)) connector.Serve
	if spec.Protocol == "ssh" {
		c, err := session.ParseSSH(spec.Config)
		if err != nil {
			return err
		}
		hosts, handler = c.Hosts(), c.Handler
	} else {
		c, err := session.ParseSFTP(spec.Config)
		if err != nil {
			return err
		}
		hosts = c.Hosts()
		handler = func(dial dialFunc, host ssh.Signer, key func(context.Context) (string, error)) connector.Serve {
			return c.Handler(dial, host, key, sftpLimits)
		}
	}
	p.Hosts = hosts
	p.SecretNames, p.HostKey = []string{"key"}, true
	p.Open = func(_ context.Context, h worker.Host) (connector.Instance, error) {
		return connector.Instance{Serve: handler(h.Dial, h.HostKey, func(ctx context.Context) (string, error) { return h.Secret(ctx, "key") })}, nil
	}
	return nil
}

func parseCLI(spec config.ConnectionSpec, p *Setup) error {
	c, err := session.ParseCLI(spec.Config)
	if err != nil {
		return err
	}
	p.SecretNames, p.HostKey = c.Credentials, true
	p.Open = func(_ context.Context, h worker.Host) (connector.Instance, error) {
		return connector.Instance{Serve: c.Handler(h.HostKey, h.Secret, cliLimits, protocolIdentity)}, nil
	}
	return nil
}

func parseSSHAgent(spec config.ConnectionSpec, p *Setup) error {
	c, err := signer.ParseSSHAgent(spec.Config)
	if err != nil {
		return err
	}
	p.SecretNames = c.Credentials
	p.Open = func(_ context.Context, h worker.Host) (connector.Instance, error) {
		return connector.Instance{Serve: c.Handler(h.Secret)}, nil
	}
	return nil
}

func parseGPGAgent(spec config.ConnectionSpec, p *Setup) error {
	c, err := signer.ParseGPGAgent(spec.Config)
	if err != nil {
		return err
	}
	p.Open = func(context.Context, worker.Host) (connector.Instance, error) {
		return connector.Instance{Serve: c.Handler((&net.Dialer{Timeout: DialTimeout}).DialContext)}, nil
	}
	return nil
}

func parseEndpoint(spec config.ConnectionSpec, p *Setup) error {
	var hosts []string
	var handler func(h worker.Host) connector.Serve
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
			handler = func(h worker.Host) connector.Serve { return c.Preauthenticated(h.Dial, password(h), protocolIdentity) }
		}
	case "smtp":
		var c *email.SMTP
		if c, err = email.ParseSMTP(spec.Config); err == nil {
			hosts = c.Hosts()
			handler = func(h worker.Host) connector.Serve {
				return c.Handler(h.Dial, password(h), func(string, string, string) error { return nil }, protocolIdentity, maxMailBytes, h.TLS)
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
					c.Sends = config.AudienceAnyone
				}
			}
			return nil
		}
	case "redis":
		var c *redis.Redis
		if c, err = redis.Parse(spec.Config); err == nil {
			hosts = c.Hosts()
			handler = func(h worker.Host) connector.Serve { return c.Handler(h.Dial, password(h)) }
		}
	case "mqtt":
		var c *mqtt.MQTT
		if c, err = mqtt.Parse(spec.Config); err == nil {
			hosts = c.Hosts()
			handler = func(h worker.Host) connector.Serve {
				return c.Handler(h.Dial, password(h), maxMQTTPacket, maxMQTTPending)
			}
		}
		p.PerMessage = true
		p.Hint = connectionAudience
	case "nats":
		var c *nats.NATS
		if c, err = nats.Parse(spec.Config); err == nil {
			hosts = c.Hosts()
			handler = func(h worker.Host) connector.Serve {
				return c.Preauthenticated(h.Dial, h.Secret, natsLimits, protocolIdentity)
			}
		}
		p.SecretNames, p.PerMessage = []string{"password", "token"}, true
		p.Hint = connectionAudience
	case "postgres":
		var c *postgres.Postgres
		if c, err = postgres.Parse(spec.Config); err == nil {
			hosts = c.Hosts()
			handler = func(h worker.Host) connector.Serve { return c.Handler(h.Dial, password(h), h.TLS, upstreamTimeout) }
		}
	}
	if err != nil {
		return err
	}
	p.Hosts = hosts
	p.Open = func(_ context.Context, h worker.Host) (connector.Instance, error) {
		return connector.Instance{Serve: handler(h)}, nil
	}
	return nil
}

func connectionAudience(_ *facts.Observation, c *RequestContext) error {
	c.Sends = config.SendsConnection
	return nil
}

func validSends(sends string) bool {
	return sends == "" || sends == config.SendsConnection || slices.Contains(config.Audiences, sends)
}
