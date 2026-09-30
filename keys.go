package main

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/tinfoilsh/monitor/connector"
	"golang.org/x/crypto/ssh"
)

const (
	caCertFile    = "ca.pem"
	caKeyFile     = "ca.key"
	caName        = "monitor dev CA"
	caLifetime    = 10 * 365 * 24 * time.Hour
	leafLifetime  = 24 * time.Hour
	leafBackdate  = time.Hour
	pemCert       = "CERTIFICATE"
	pemPrivateKey = "PRIVATE KEY"
	hostKeyFile   = "host_key"
)

type authority struct {
	ca     tls.Certificate
	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

func loadCA(dir string) (*tls.Config, error) {
	certPath, keyPath := filepath.Join(dir, caCertFile), filepath.Join(dir, caKeyFile)
	if _, err := os.Stat(certPath); errors.Is(err, os.ErrNotExist) {
		if err := createCA(certPath, keyPath); err != nil {
			return nil, err
		}
	}
	ca, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	a := &authority{ca: ca, leaves: map[string]*tls.Certificate{}}
	return &tls.Config{GetCertificate: a.certificate}, nil
}

func createCA(certPath, keyPath string) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	template := &x509.Certificate{
		Subject:               pkix.Name{CommonName: caName},
		NotBefore:             now,
		NotAfter:              now.Add(caLifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return err
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: pemPrivateKey, Bytes: private}), secretMode); err != nil {
		return err
	}
	return os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: pemCert, Bytes: der}), secretMode)
}

// Without SNI, the leaf is minted for the channel's target.
func (a *authority) certificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := hello.ServerName
	if c, ok := hello.Conn.(*connector.Stream); ok && name == "" {
		name = c.Host
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if leaf := a.leaves[name]; leaf != nil && time.Now().Before(leaf.Leaf.NotAfter) {
		return leaf, nil
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		Subject:     pkix.Name{CommonName: name},
		NotBefore:   now.Add(-leafBackdate),
		NotAfter:    now.Add(leafLifetime),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(name); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.ca.Leaf, &key.PublicKey, a.ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	leaf := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}
	a.leaves[name] = leaf
	return leaf, nil
}

func loadHostKey(dir string) (ssh.Signer, error) {
	path := filepath.Join(dir, hostKeyFile)
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
