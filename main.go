// Command monitor is an SSH server that forwards the direct-tcpip channels of a stock
// ssh client. Every target is a relay that terminates its protocol, asks the policy
// before each operation, and attaches the stored credential in place of the client's.
package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/tinfoilsh/mcp-sentinel"
	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

const (
	hostKeyFile       = "host_key"
	placeholderPrefix = "tfm_"
	dialTimeout       = 30 * time.Second
	stateMode         = 0o700
	secretMode        = 0o600
	defaultPolicies   = "policies"
	extensionName     = "name"
	extensionKey      = "key"
)

type config struct {
	Listen         string                 `yaml:"listen"`
	AuthorizedKeys string                 `yaml:"authorized_keys"`
	Policies       string                 `yaml:"policies"`
	Connections    map[string]*connection `yaml:"connections"`
}

// connection is either an http binding of secrets to hosts or exactly one relay.
type connection struct {
	Hosts    []string          `yaml:"hosts"`
	Secrets  map[string]string `yaml:"secrets"`
	protocol string
	relay    relay
}

// relay terminates one protocol on an accepted channel and gates each operation it forwards.
type relay interface {
	serve(cc *channelConn)
}

// relays maps each connection kind to its config type. The kind is also the protocol policies see.
var relays = map[string]func() relay{
	"ssh":       func() relay { return new(sshRelay) },
	"cli":       func() relay { return new(cliRelay) },
	"ssh-agent": func() relay { return new(sshAgentRelay) },
	"gpg-agent": func() relay { return new(gpgAgentRelay) },
	"imap":      func() relay { return new(imapRelay) },
	"smtp":      func() relay { return new(smtpRelay) },
	"postgres":  func() relay { return new(postgresRelay) },
	"redis":     func() relay { return new(redisRelay) },
}

func (c *connection) UnmarshalYAML(node *yaml.Node) error {
	type binding connection
	if err := node.Decode((*binding)(c)); err != nil {
		return err
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		kind := node.Content[i].Value
		newRelay, ok := relays[kind]
		if !ok {
			continue
		}
		if c.relay != nil {
			return fmt.Errorf("line %d: a connection has one kind, not %s and %s", node.Line, c.protocol, kind)
		}
		c.protocol, c.relay = kind, newRelay()
		if err := node.Content[i+1].Decode(c.relay); err != nil {
			return err
		}
	}
	if c.relay != nil && (c.Hosts != nil || c.Secrets != nil) {
		return fmt.Errorf("line %d: a %s connection takes no hosts or secrets", node.Line, c.protocol)
	}
	return nil
}

// endpoint is an upstream URL holding the stored credential, parsed when the config loads.
type endpoint struct{ url.URL }

func (e *endpoint) UnmarshalText(text []byte) error {
	u, err := url.Parse(string(text))
	if err != nil {
		return err
	}
	e.URL = *u
	return nil
}

type monitor struct {
	config
	policy *sentinel.Policy
	front  *ssh.ServerConfig
	inner  *ssh.ServerConfig
	tls    *tls.Config
	ca     tls.Certificate
	https  chanListener
	http   chanListener
	smtp   chanListener

	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

func main() {
	configPath := flag.String("c", "monitor.yml", "config file")
	stateDir := flag.String("state", "state", "directory holding the host key and CA")
	flag.Parse()
	if err := run(*configPath, *stateDir, flag.Args()); err != nil {
		log.Fatal(err)
	}
}

func run(configPath, stateDir string, args []string) error {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}
	m := &monitor{leaves: map[string]*tls.Certificate{}, https: make(chanListener), http: make(chanListener), smtp: make(chanListener)}
	if err := yaml.Unmarshal(raw, &m.config); err != nil {
		return fmt.Errorf("%s: %w", configPath, err)
	}
	if len(args) == 1 && args[0] == "env" {
		for name, c := range m.Connections {
			for secret := range c.Secrets {
				fmt.Printf("export %s=%s\n", secret, placeholder(name, secret))
			}
		}
		return nil
	}
	policies := rego.Load([]string{cmp.Or(m.Policies, defaultPolicies)}, nil)
	if m.policy, err = sentinel.NewPolicy(context.Background(), policies); err != nil {
		return err
	}
	if err := os.MkdirAll(stateDir, stateMode); err != nil {
		return err
	}
	hostKey, err := loadHostKey(filepath.Join(stateDir, hostKeyFile))
	if err != nil {
		return err
	}
	if m.ca, err = loadCA(stateDir); err != nil {
		return err
	}
	m.tls = &tls.Config{GetCertificate: m.certificate}
	m.front = &ssh.ServerConfig{PublicKeyCallback: m.authorized}
	m.front.AddHostKey(hostKey)
	m.inner = &ssh.ServerConfig{NoClientAuth: true}
	m.inner.AddHostKey(hostKey)

	ln, err := net.Listen("tcp", m.Listen)
	if err != nil {
		return err
	}
	go m.serveHTTP()
	go m.serveSMTP()
	log.Printf("monitor listening on %s", ln.Addr())
	for {
		nc, err := ln.Accept()
		if err != nil {
			return err
		}
		go m.serve(nc)
	}
}

// authorized rereads the key file on every attempt, so keys change without a restart.
func (m *monitor) authorized(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	rest, err := os.ReadFile(m.AuthorizedKeys)
	if err != nil {
		return nil, err
	}
	for len(rest) > 0 {
		listed, comment, _, next, err := ssh.ParseAuthorizedKey(rest)
		if err != nil {
			break
		}
		if bytes.Equal(listed.Marshal(), key.Marshal()) {
			return &ssh.Permissions{Extensions: map[string]string{extensionName: comment, extensionKey: ssh.FingerprintSHA256(key)}}, nil
		}
		rest = next
	}
	return nil, errors.New("key is not authorized")
}

func loadHostKey(path string) (ssh.Signer, error) {
	encoded, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		block, err := ssh.MarshalPrivateKey(private, "")
		if err != nil {
			return nil, err
		}
		encoded = pem.EncodeToMemory(block)
		if err := os.WriteFile(path, encoded, secretMode); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(encoded)
}

func placeholder(connection, secret string) string {
	return placeholderPrefix + connection + "_" + secret
}

// address fills in the scheme's default port when the URL names none.
func address(u *url.URL, secure, port, securePort string) string {
	if u.Port() != "" {
		return u.Host
	}
	if u.Scheme == secure {
		port = securePort
	}
	return net.JoinHostPort(u.Hostname(), port)
}

func dialURL(u *url.URL, secure, port, securePort string) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	defer cancel()
	target := address(u, secure, port, securePort)
	if u.Scheme == secure {
		return (&tls.Dialer{Config: &tls.Config{ServerName: u.Hostname()}}).DialContext(ctx, "tcp", target)
	}
	return (&net.Dialer{}).DialContext(ctx, "tcp", target)
}
