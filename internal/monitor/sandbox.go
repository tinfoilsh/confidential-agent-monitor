package monitor

import (
	"context"
	"errors"
	"net"
	"net/http"

	"github.com/tinfoilsh/monitor/internal/ownerauth"
	"github.com/tinfoilsh/monitor/internal/sandbox"
	"github.com/tinfoilsh/monitor/internal/sandboxroute"
	"golang.org/x/crypto/ssh"
)

var errSandboxSSHDisabled = errors.New("browser terminals and sandbox setup are disabled; enable them in Monitor Settings")

// sandboxHandler gates the entire SSH path, including request decoding and setup.
func (m *monitor) sandboxHandler(next http.HandlerFunc) http.HandlerFunc {
	return m.authenticated(func(w http.ResponseWriter, r *http.Request) {
		if !m.live.Load().Config.AllowSandboxSSH {
			responseError(w, errSandboxSSHDisabled)
			return
		}
		next(w, r)
	})
}

func (m *monitor) enrollSandbox(r *http.Request, in sandbox.EnrollInput) (any, error) {
	if err := m.sandboxes.Enroll(r.Context(), r.PathValue("name"), in); err != nil {
		return nil, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.view(nil)
}

func (m *monitor) shellSandbox(r *http.Request, in sandbox.ShellInput) (any, error) {
	session, _ := ownerauth.FromContext(r.Context())
	return m.sandboxes.Shell(r.Context(), session.ID, r.PathValue("name"), in)
}

// sandboxMonitor is the Monitor as the sandbox package sees it.
type sandboxMonitor struct{ m *monitor }

func (s sandboxMonitor) Boot(name string) sandbox.Boot {
	return s.m.live.Load().Config.Identities[name].Sandbox
}

func (s sandboxMonitor) HostKey() ssh.Signer { return s.m.live.Load().HostKey }

func (s sandboxMonitor) DialSSH(hostKey ssh.PublicKey) (net.Conn, error) {
	return s.m.routes.Dial(sandboxroute.Name(hostKey), 22)
}

func (s sandboxMonitor) DialBootstrap(user string) (net.Conn, error) {
	return s.m.routes.Dial(sandboxroute.Bootstrap(user), 443)
}

func (s sandboxMonitor) CheckIdentity(name, key string, boot sandbox.Boot) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	_, err := s.m.enrollmentChanges(map[string]identityEnrollment{name: {Key: key, Sandbox: boot}})
	return err
}

func (s sandboxMonitor) AddIdentity(ctx context.Context, name, key string, boot sandbox.Boot) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	changes, err := s.m.enrollmentChanges(map[string]identityEnrollment{name: {Key: key, Sandbox: boot}})
	if err != nil {
		return err
	}
	return s.m.editPolicy(ctx, changes)
}
