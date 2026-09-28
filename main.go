// Command monitor is an SSH server that forwards the direct-tcpip channels of a stock
// ssh client. It terminates each protocol it understands, attaches the real credential
// in place of the one the client sent, and refuses every other target.
package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"
	"gopkg.in/yaml.v3"
)

const (
	hostKeyFile       = "host_key"
	placeholderPrefix = "tfm_"
	dialTimeout       = 30 * time.Second
	stateMode         = 0o700
	secretMode        = 0o600
)

type config struct {
	Listen         string                 `yaml:"listen"`
	AuthorizedKeys string                 `yaml:"authorized_keys"`
	Connections    map[string]*connection `yaml:"connections"`
}

// connection is one of ssh, postgres, or redis, or an http binding of secrets to hosts.
type connection struct {
	SSH      *sshTarget        `yaml:"ssh"`
	Postgres string            `yaml:"postgres"`
	Redis    string            `yaml:"redis"`
	Hosts    []string          `yaml:"hosts"`
	Secrets  map[string]string `yaml:"secrets"`
}

type monitor struct {
	config
	front *ssh.ServerConfig
	inner *ssh.ServerConfig
	tls   *tls.Config
	ca    tls.Certificate
	https chanListener
	http  chanListener

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
	m := &monitor{leaves: map[string]*tls.Certificate{}, https: make(chanListener), http: make(chanListener)}
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
		listed, _, _, next, err := ssh.ParseAuthorizedKey(rest)
		if err != nil {
			break
		}
		if bytes.Equal(listed.Marshal(), key.Marshal()) {
			return &ssh.Permissions{}, nil
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
