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
	userAgent        = protocolIdentity + "/" + mcpVersion
)

// A connector's hint about one request: who sees what it sends, and what its response returns to the agent.
type Flow struct {
	SendsTo string       `json:"sends_to"`
	Returns format.Label `json:"returns"`
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
	Flow              func(facts.Observation) Flow
	Open              func(ctx context.Context, h worker.Host) (connector.Instance, error)
}

func Parse(spec config.ConnectionSpec) (*Setup, error) {
	parse := parsers[spec.Protocol]
	if parse == nil {
		return nil, fmt.Errorf("unknown kind %s", spec.Protocol)
	}
	p := &Setup{ConnectionSpec: spec, Network: "tcp", Flow: func(facts.Observation) Flow { return Flow{} }}
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
	p.Flow = func(facts.Observation) Flow {
		return Flow{SendsTo: config.AudienceAnyone, Returns: format.Label{Audience: config.AudienceMe, Trust: config.TrustUntrusted}}
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
		var list []slots.Slot
		if len(raw) != 0 {
			if err := facts.DecodeNumbers(raw, &list); err != nil {
				return nil, err
			}
		}
		var err error
		set, err = slots.New(append(list, signInSlots(spec.Definition)...), httpSlots)
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

func signInSlots(definition json.RawMessage) []slots.Slot {
	var preset struct {
		Catalog struct {
			Fields []struct {
				Key   string `json:"key"`
				OAuth *struct {
					AuthURL  string `json:"auth_url"`
					TokenURL string `json:"token_url"`
				} `json:"oauth"`
			} `json:"fields"`
		} `json:"catalog"`
	}
	json.Unmarshal(definition, &preset)
	var derived []slots.Slot
	for _, f := range preset.Catalog.Fields {
		if f.OAuth == nil {
			continue
		}
		for _, endpoint := range [][2]string{{slots.OAuthAuthorize, f.OAuth.AuthURL}, {slots.OAuthToken, f.OAuth.TokenURL}} {
			if u, err := url.Parse(endpoint[1]); err == nil && slots.ValidOrigin(u.Scheme+"://"+u.Host) {
				derived = append(derived, slots.Slot{Value: f.Key, Origin: u.Scheme + "://" + u.Host, OAuth: endpoint[0]})
			}
		}
	}
	return derived
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
			if op.Sends != nil && json.Unmarshal(op.Sends, &audience) != nil || !config.ValidEffects(op.Effects) || !validSendsTo(audience) {
				return fmt.Errorf("invalid effects or audience for operation %s", id)
			}
			p.Operations[id], sends[id] = config.OperationSummary{Action: op.Action, Effects: op.Effects}, audience
		}
	}
	p.Flow = func(o facts.Observation) Flow {
		websocket, method := WebSocket(o)
		switch {
		// A message the upstream sends on a WebSocket reaches only the agent.
		case websocket && method == "":
			return Flow{SendsTo: config.AudienceMe}
		case o.Operation == nil:
			return Flow{}
		case o.Operation.Action == web.SignInAction:
			return Flow{SendsTo: config.AudienceMe, Returns: config.InitialLabel}
		}
		return Flow{SendsTo: sends[o.Operation.ID]}
	}
	return nil
}

func WebSocket(o facts.Observation) (websocket bool, method string) {
	var details struct {
		HTTP struct {
			WebSocket bool   `json:"websocket"`
			Method    string `json:"method"`
		} `json:"http"`
	}
	raw, _ := json.Marshal(o.Details)
	json.Unmarshal(raw, &details)
	return details.HTTP.WebSocket, details.HTTP.Method
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
	var place *mcp.Placement
	if pr := setup.Preset; pr != nil {
		if len(pr.Sends) != 0 && facts.DecodeNumbers(pr.Sends, &sends) != nil || len(pr.Observes) != 0 && facts.DecodeNumbers(pr.Observes, &observes) != nil ||
			!validSendsTo(sends) || observes != nil && !config.ValidLabel(*observes) {
			return errors.New("invalid MCP data-flow settings")
		}
		if place = pr.Token; place != nil {
			u, _ := url.Parse(setup.URL)
			if _, err := slots.New([]slots.Slot{{Value: "token", Origin: u.Scheme + "://" + u.Host, Header: place.Header, Prefix: place.Prefix, Query: place.Query, Basic: place.Basic}}, slots.Options{}); err != nil {
				return err
			}
		}
	}
	p.Hosts, p.SecretNames = setup.Hosts(), []string{"token"}
	flow := Flow{SendsTo: sends}
	if observes != nil {
		flow.Returns = *observes
	}
	p.Flow = func(facts.Observation) Flow { return flow }
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
		client := mcp.Client{HTTP: &http.Client{Transport: Identified{base}, CheckRedirect: netx.RefuseRedirects}, Timeout: upstreamTimeout, TLS: h.TLS,
			Name: protocolIdentity, Version: mcpVersion, Expose: setup.Pin.Expose}
		if h.Configured("token") {
			client.Token = func(ctx context.Context) (string, error) { return h.Secret(ctx, "token") }
			if !h.OAuth("token") {
				client.Place = place
			}
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

type Identified struct{ http.RoundTripper }

func (t Identified) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Header.Get("User-Agent") == "" {
		r = r.Clone(r.Context())
		r.Header.Set("User-Agent", userAgent)
	}
	return t.RoundTripper.RoundTrip(r)
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
		p.Flow = sendsToConnection
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
		p.Flow = sendsToConnection
	case "nats":
		var c *nats.NATS
		if c, err = nats.Parse(spec.Config); err == nil {
			hosts = c.Hosts()
			handler = func(h worker.Host) connector.Serve {
				return c.Preauthenticated(h.Dial, h.Secret, natsLimits, protocolIdentity)
			}
		}
		p.SecretNames, p.PerMessage = []string{"password", "token"}, true
		p.Flow = sendsToConnection
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

func sendsToConnection(facts.Observation) Flow { return Flow{SendsTo: config.SendsToConnection} }

var privateActions = map[string]bool{config.RequestsRead: true, config.AuditRead: true}

// Requests and the audit log are the owner's private data; every other action shows configuration, which is not.
func PerimeterFlow(o facts.Observation) Flow {
	if o.Operation != nil && privateActions[o.Operation.Action] {
		return Flow{Returns: format.Label{Audience: config.AudienceMe, Trust: config.TrustTrusted}}
	}
	return Flow{Returns: config.InitialLabel}
}

func validSendsTo(sends string) bool {
	return sends == "" || sends == config.SendsToConnection || slices.Contains(config.Audiences, sends)
}
