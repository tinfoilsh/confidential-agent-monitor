package tinfoil

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
	"github.com/tinfoilsh/monitor/connector/web"
)

type testTransport func(*http.Request) (*http.Response, error)

func (f testTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func testTLS(t *testing.T, names ...string) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage:    x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, certificate, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err = x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	leaf := &x509.Certificate{
		SerialNumber: big.NewInt(2), DNSNames: names,
		NotBefore: certificate.NotBefore, NotAfter: certificate.NotAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err = x509.CreateCertificate(rand.Reader, leaf, certificate, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
		return &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, nil
	}}, roots
}

func TestInferenceRoutes(t *testing.T) {
	const privateHost = "team-inference.monitor"
	const enclave = "inference.tinfoil.sh"
	serverTLS, roots := testTLS(t, privateHost, enclave, "other.monitor")
	env := &connector.Env{TLS: serverTLS}

	for _, test := range []struct {
		name, url, channelHost, authorization string
		deny, untrusted, wrongName            bool
		status                                int
	}{
		{name: "private HTTPS", url: "https://" + privateHost + "/v1/models", status: 200},
		{name: "private HTTPS dummy key", url: "https://" + privateHost + "/v1/models", authorization: "Bearer monitor", status: 200},
		{name: "existing private HTTP", url: "http://" + privateHost + "/v1/models", status: 200},
		{name: "public HTTPS placeholder", url: "https://" + enclave + "/v1/models", channelHost: enclave, authorization: "Bearer tfm_test_key", status: 200},
		{name: "selected public HTTPS placeholder", url: "https://" + enclave + "/v1/models", authorization: "Bearer tfm_test_key", status: 200},
		{name: "denied HTTPS", url: "https://" + privateHost + "/v1/models", deny: true, status: 403},
		{name: "invalid private path", url: "https://" + privateHost + "/v10/models", status: 403},
		{name: "other private connection", url: "https://other.monitor/v1/models", status: 403},
		{name: "untrusted certificate", url: "https://" + privateHost + "/v1/models", untrusted: true},
		{name: "wrong certificate name", url: "https://" + privateHost + "/v1/models", wrongName: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			var server Server
			if err := json.Unmarshal([]byte(`{"enclave":"inference.tinfoil.sh","repo":"tinfoilsh/confidential-model-router"}`), &server); err != nil {
				t.Fatal(err)
			}
			var admitted, forwarded atomic.Bool
			var resolutions atomic.Int32
			secret := credential.Remote(true, func(context.Context) (string, error) {
				resolutions.Add(1)
				if !admitted.Load() {
					t.Error("credential resolved before policy admission")
				}
				return "saved-test-key", nil
			})
			secret.Placeholder = "tfm_test_key"
			server.Secrets["TINFOIL_API_KEY"] = secret
			server.transport = testTransport(func(r *http.Request) (*http.Response, error) {
				forwarded.Store(true)
				if !admitted.Load() || r.URL.String() != "https://"+enclave+"/v1/models" || r.Header.Get("Authorization") != "Bearer saved-test-key" {
					t.Error("upstream request did not use the admitted origin and saved key")
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"data":[]}`))}, nil
			})
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			clientConn, err := net.Dial("tcp", listener.Addr().String())
			if err != nil {
				t.Fatal(err)
			}
			serverConn, err := listener.Accept()
			if err != nil {
				clientConn.Close()
				t.Fatal(err)
			}
			stream := connector.NewStream(t.Context(), serverConn)
			stream.Name, stream.Host, stream.Port = "team-inference", test.channelHost, 443
			if strings.HasPrefix(test.url, "http:") {
				stream.Port = 80
			}
			stream.Gate = func(_ context.Context, request connector.Request) error {
				r := request.(*web.Request)
				if test.deny || r.Invalid != "" {
					return errors.New("refused by policy")
				}
				if r.HTTP.Origin != "https://"+enclave || r.HTTP.Host != enclave || len(r.HTTP.Secrets) != 1 || r.HTTP.Secrets[0] != "TINFOIL_API_KEY" {
					t.Error("policy did not receive upstream facts and credential use")
				}
				admitted.Store(true)
				return nil
			}
			done := make(chan struct{})
			go func() { defer close(done); server.Serve(stream, env) }()
			clientTLS := &tls.Config{RootCAs: roots}
			if test.untrusted {
				clientTLS.RootCAs = x509.NewCertPool()
			}
			if test.wrongName {
				clientTLS.ServerName = "wrong.monitor"
			}
			transport := &http.Transport{
				DialContext:     func(context.Context, string, string) (net.Conn, error) { return clientConn, nil },
				TLSClientConfig: clientTLS, DisableKeepAlives: true,
			}
			t.Cleanup(func() {
				transport.CloseIdleConnections()
				clientConn.Close()
				stream.Close()
				<-done
			})
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			request, err := http.NewRequestWithContext(t.Context(), "GET", test.url, nil)
			if err != nil {
				t.Fatal(err)
			}
			if test.authorization != "" {
				request.Header.Set("Authorization", test.authorization)
			}
			response, err := client.Do(request)
			if test.untrusted || test.wrongName {
				if err == nil {
					response.Body.Close()
					t.Fatal("TLS accepted an untrusted certificate or wrong hostname")
				}
				var verification *tls.CertificateVerificationError
				if !errors.As(err, &verification) {
					t.Fatalf("expected a certificate verification error, got %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				io.Copy(io.Discard, response.Body)
				response.Body.Close()
				if response.StatusCode != test.status {
					t.Fatalf("status = %d, want %d", response.StatusCode, test.status)
				}
			}
			allowed := test.status == http.StatusOK
			wantResolutions := int32(0)
			if allowed {
				wantResolutions = 1
			}
			if admitted.Load() != allowed || forwarded.Load() != allowed || resolutions.Load() != wantResolutions {
				t.Fatal("refused requests must neither resolve credentials nor reach upstream")
			}
		})
	}
}
