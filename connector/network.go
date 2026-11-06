package connector

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"code.dny.dev/ssrf"
)

const DialTimeout = 30 * time.Second

func (e *Env) Transport() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = e.Dialer.DialContext
	return transport
}

// Client is for requests the monitor makes itself, such as OAuth. A redirect could carry a credential elsewhere, so it fails.
func (e *Env) Client() *http.Client {
	return &http.Client{
		Transport:     e.Transport(),
		CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("redirects are refused") },
	}
}

// The guard checks the resolved address, so DNS cannot steer an upstream into a refused range.
func NewDialer(allowed []netip.Prefix) *net.Dialer {
	var v4, v6 []netip.Prefix
	for _, p := range allowed {
		if p.Addr().Is4() {
			v4 = append(v4, p)
		} else {
			v6 = append(v6, p)
		}
	}
	guard := ssrf.New(ssrf.WithAnyPort(), ssrf.WithAllowedV4Prefixes(v4...), ssrf.WithAllowedV6Prefixes(v6...))
	return &net.Dialer{Timeout: DialTimeout, Control: guard.Safe}
}

// ParseURL validates a destination whose password is supplied separately.
func ParseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme == "" || u.Host == "" {
		return nil, errors.New("destination requires a URL with a scheme and host")
	}
	if _, set := u.User.Password(); set || u.Query().Has("password") {
		return nil, errors.New("put the password in the connection's password credential, not the URL")
	}
	return u, nil
}

func address(u *url.URL, secure, port, securePort string) string {
	if u.Port() != "" {
		return u.Host
	}
	if u.Scheme == secure {
		port = securePort
	}
	return net.JoinHostPort(u.Hostname(), port)
}

func DialURL(ctx context.Context, d Dialer, u *url.URL, secure, port, securePort string) (net.Conn, error) {
	c, err := d.DialContext(ctx, "tcp", address(u, secure, port, securePort))
	if err != nil {
		return nil, err
	}
	if u.Scheme == secure {
		t := tls.Client(c, &tls.Config{ServerName: u.Hostname()})
		if err := t.HandshakeContext(ctx); err != nil {
			c.Close()
			return nil, err
		}
		return t, nil
	}
	return c, nil
}
