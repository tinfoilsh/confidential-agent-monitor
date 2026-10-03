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
	"net"
	"sync"
	"time"

	"github.com/tinfoilsh/monitor/connector"
	"golang.org/x/crypto/ssh"
)

const (
	caLifetime   = 10 * 365 * 24 * time.Hour
	leafLifetime = 24 * time.Hour
	leafBackdate = time.Hour
)

type keyMaterial struct {
	HostKey string `json:"host_key"`
	CACert  string `json:"ca_cert"`
	CAKey   string `json:"ca_key"`
}

type authority struct {
	ca     tls.Certificate
	mu     sync.Mutex
	leaves map[string]*tls.Certificate
}

func loadCA(k *keyMaterial) (*tls.Config, error) {
	if k.CACert == "" {
		if err := createCA(k); err != nil {
			return nil, err
		}
	}
	ca, err := tls.X509KeyPair([]byte(k.CACert), []byte(k.CAKey))
	if err != nil {
		return nil, err
	}
	a := &authority{ca: ca, leaves: map[string]*tls.Certificate{}}
	return &tls.Config{GetCertificate: a.certificate}, nil
}

func createCA(k *keyMaterial) error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	template := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "monitor dev CA"},
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
	k.CAKey = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	k.CACert = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	return nil
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

func loadHostKey(k *keyMaterial) (ssh.Signer, error) {
	if k.HostKey == "" {
		_, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		block, err := ssh.MarshalPrivateKey(private, "")
		if err != nil {
			return nil, err
		}
		k.HostKey = string(pem.EncodeToMemory(block))
	}
	return ssh.ParsePrivateKey([]byte(k.HostKey))
}
