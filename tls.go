package main

import (
	"crypto/ecdsa"
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
	"time"
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
)

func loadCA(dir string) (tls.Certificate, error) {
	certPath, keyPath := filepath.Join(dir, caCertFile), filepath.Join(dir, caKeyFile)
	if _, err := os.Stat(certPath); errors.Is(err, os.ErrNotExist) {
		if err := createCA(certPath, keyPath); err != nil {
			return tls.Certificate{}, err
		}
	}
	return tls.LoadX509KeyPair(certPath, keyPath)
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

// certificate mints a leaf for the SNI name, or for the channel's target when the client sent none.
func (m *monitor) certificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := hello.ServerName
	if c, ok := hello.Conn.(*channelConn); ok && name == "" {
		name = c.host
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if leaf := m.leaves[name]; leaf != nil && time.Now().Before(leaf.Leaf.NotAfter) {
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
	der, err := x509.CreateCertificate(rand.Reader, template, m.ca.Leaf, &key.PublicKey, m.ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	leaf := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}
	m.leaves[name] = leaf
	return leaf, nil
}
