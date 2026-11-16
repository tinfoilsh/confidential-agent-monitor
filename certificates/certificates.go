// Package certificates mints TLS server certificates and verifies SSH user certificates.
package certificates

import (
	"bytes"
	"crypto/ecdsa"
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

// Authority mints short-lived TLS server certificates by server name.
type Authority struct{ tls.Certificate }

func NewAuthority(name string, lifetime time.Duration) (*Authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	template := &x509.Certificate{
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             now,
		NotAfter:              now.Add(lifetime),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	return LoadAuthority((&Authority{tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}}).PEM())
}

func LoadAuthority(certPEM, keyPEM string) (*Authority, error) {
	c, err := tls.X509KeyPair([]byte(certPEM), []byte(keyPEM))
	if err != nil {
		return nil, err
	}
	return &Authority{c}, nil
}

func (a *Authority) PEM() (cert, key string) {
	private, _ := x509.MarshalPKCS8PrivateKey(a.PrivateKey)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: a.Certificate.Certificate[0]})), string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
}

// Issue mints a certificate for name, valid from backdate ago until lifetime from now.
func (a *Authority) Issue(name string, lifetime, backdate time.Duration) (*tls.Certificate, error) {
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
		NotBefore:   now.Add(-backdate),
		NotAfter:    now.Add(lifetime),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(name); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{name}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.Leaf, &key.PublicKey, a.PrivateKey)
	if err != nil {
		return nil, err
	}
	return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
}

// SSHClaims are what a verified SSH user certificate states about its key.
type SSHClaims struct {
	KeyID       string
	Principals  []string
	ValidBefore uint64
}

// VerifySSHUser checks that cert is a user certificate that authority signed for principal and that is valid now.
func VerifySSHUser(authority ssh.PublicKey, cert *ssh.Certificate, principal string) (SSHClaims, error) {
	if cert.CertType != ssh.UserCert || !bytes.Equal(cert.SignatureKey.Marshal(), authority.Marshal()) {
		return SSHClaims{}, errors.New("certificate is not a user certificate from the authority")
	}
	if err := new(ssh.CertChecker).CheckCert(principal, cert); err != nil {
		return SSHClaims{}, err
	}
	return SSHClaims{KeyID: cert.KeyId, Principals: cert.ValidPrincipals, ValidBefore: cert.ValidBefore}, nil
}
