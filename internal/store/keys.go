package store

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
	"time"

	"golang.org/x/crypto/ssh"
)

const (
	caLifetime   = 10 * 365 * 24 * time.Hour
	leafLifetime = 24 * time.Hour
	leafBackdate = time.Hour
)

// Keys is the Monitor's persisted key material, created on first use.
type Keys struct {
	HostKey string `json:"host_key"`
	CACert  string `json:"ca_cert"`
	CAKey   string `json:"ca_key"`
}

// TLS mints connection leaves from the CA, creating it if k has none.
func (k *Keys) TLS() (*tls.Config, error) {
	if k.CACert == "" {
		if err := k.createCA(); err != nil {
			return nil, err
		}
	}
	ca, err := tls.X509KeyPair([]byte(k.CACert), []byte(k.CAKey))
	if err != nil {
		return nil, err
	}
	return &tls.Config{GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) { return leaf(ca, hello.ServerName) }}, nil
}

func (k *Keys) createCA() error {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now()
	template := &x509.Certificate{
		Subject:               pkix.Name{CommonName: "perimeter dev CA"},
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

// leaf issues a certificate for the name selected by the transport.
func leaf(ca tls.Certificate, name string) (*tls.Certificate, error) {
	if name == "" {
		return nil, errors.New("a selected connection needs TLS server name indication")
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
	der, err := x509.CreateCertificate(rand.Reader, template, ca.Leaf, &key.PublicKey, ca.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// HostSigner is the SSH host key, created if k has none.
func (k *Keys) HostSigner() (ssh.Signer, error) {
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
