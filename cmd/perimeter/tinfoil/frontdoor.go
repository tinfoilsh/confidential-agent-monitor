package tinfoil

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/tinfoilsh/confidential-agent-monitor/core/netx"
	"github.com/tinfoilsh/confidential-agent-monitor/core/sshx"
	"golang.org/x/crypto/ssh"
)

const routesCapability = "routes"

var (
	// errDirectUnavailable is Direct's refusal when a route host cannot be dialled.
	errDirectUnavailable = fmt.Errorf("route %w", netx.ErrUnavailable)
	errLocked            = errors.New("the Perimeter is locked")
)

// Authenticate returns the reverse-tunnel publisher that user announces with key, or nil
// for any other user, after the host's owner/locked checks. Key probes never enroll or
// restore an identity. A nil Forwarder refuses publishers.
func (f *Forwarder) Authenticate(user string, key ssh.PublicKey) (*Publisher, error) {
	instance, publisher := strings.CutPrefix(user, bootstrapUser)
	if !publisher {
		return nil, nil
	}
	if f == nil {
		return nil, errors.New("this Perimeter does not serve routes")
	}
	if instance == "" {
		return nil, errors.New("a publisher instance is required")
	}
	return &Publisher{Name: routeName(ssh.FingerprintSHA256(key)), Alias: BootstrapRoute(instance)}, nil
}

// Publishers serves the publishers Authenticate accepts, once unlocked reports true.
func (f *Forwarder) Publishers(unlocked func() bool) sshx.Extension {
	return func(conn ssh.ConnMetadata, key ssh.PublicKey) (sshx.Session, error) {
		publisher, err := f.Authenticate(conn.User(), key)
		if publisher == nil || err != nil {
			return nil, err
		}
		if !unlocked() {
			return nil, errLocked
		}
		_, publisher.Trusted = f.Identities.Lookup(ssh.FingerprintSHA256(key))
		return func(conn *ssh.ServerConn, chans <-chan ssh.NewChannel, reqs <-chan *ssh.Request) {
			f.ServePublisher(conn, chans, reqs, *publisher)
		}, nil
	}
}

// Direct relays an identity that holds routesCapability straight to a reserved route host;
// every other stream goes to Next.
type Direct struct {
	Routes *Forwarder
	// Hold leases a capability of the identity ctx carries.
	Hold func(ctx context.Context, capability string) (context.Context, context.CancelFunc, bool)
	Next netx.Opener
}

// Open relays under the hold, not ctx, which ends when the stream's channel closes and would cut its drain.
func (d Direct) Open(ctx context.Context, host string, port uint32, accept func() (net.Conn, error)) error {
	if ReservedRoute(host) {
		if held, release, ok := d.Hold(context.WithoutCancel(ctx), routesCapability); ok {
			defer release()
			if err := netx.Dial(d.Routes).Open(held, host, port, accept); err != nil {
				return errDirectUnavailable
			}
			return nil
		}
	}
	return d.Next.Open(ctx, host, port, accept)
}
