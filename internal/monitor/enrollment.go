package monitor

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/tinfoilsh/monitor/internal/config"
	"github.com/tinfoilsh/monitor/internal/tinfoil/ownerauth"
	"github.com/tinfoilsh/monitor/internal/tinfoil/sandbox"
	"golang.org/x/crypto/ssh"
)

type identityEnrollment struct {
	Key     string `json:"key"`
	Routes  bool   `json:"routes"`
	Restore bool   `json:"restore"`
	// Sandbox names the boots the Monitor may attest and log in to for shells.
	Sandbox config.Boot `json:"sandbox,omitzero"`
}

// enrollmentChanges adds new identities; a revoked key or route access returns only when restored.
// The caller holds mu.
func (m *monitor) enrollmentChanges(input map[string]identityEnrollment) ([]config.Change, error) {
	var changes []config.Change
	for name, id := range input {
		key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(id.Key))
		if err != nil {
			return nil, err
		}
		fingerprint := ssh.FingerprintSHA256(key)
		var boot map[string]any
		if id.Sandbox != (config.Boot{}) {
			if err := id.Sandbox.Validate(); err != nil {
				return nil, err
			}
			boot = map[string]any{"source": id.Sandbox.Source, "instance_id": id.Sandbox.InstanceID}
		}
		if existing, ok := m.live.Load().Principals[fingerprint]; ok {
			if id.Routes && !existing.Routes {
				if !id.Restore {
					return nil, errors.New("device route access was revoked")
				}
				changes = append(changes, config.Change{Path: []string{"identities", existing.Name, "routes"}, Value: true})
			}
			if boot != nil && id.Sandbox != existing.Sandbox {
				changes = append(changes, config.Change{Path: []string{"identities", existing.Name, "sandbox"}, Value: boot})
			}
			continue
		}
		if m.store.Doc.Enrolled[fingerprint] && !id.Restore {
			return nil, errors.New("identity was revoked; restore access explicitly in Monitor")
		}
		if _, exists := m.live.Load().Config.Identities[name]; exists {
			return nil, errors.New("identity name belongs to another key")
		}
		value := map[string]any{"key": id.Key, "routes": id.Routes}
		if boot != nil {
			value["sandbox"] = boot
		}
		changes = append(changes, config.Change{Path: []string{"identities", name}, Value: value})
	}
	return changes, nil
}

// Owner unlock may restore its device; ordinary enrollment still honors revocation.
// The caller holds mu after authenticating and unlocking the state.
func (m *monitor) restoreDevice(ctx context.Context, public string) error {
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(public))
	if err != nil {
		return fmt.Errorf("device public key: %w", err)
	}
	st := m.live.Load()
	if existing, ok := st.Principals[ssh.FingerprintSHA256(key)]; ok {
		if existing.Routes {
			return nil
		}
		return m.editPolicy(ctx, []config.Change{{Path: []string{"identities", existing.Name, "routes"}, Value: true}})
	}
	public = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key)))
	digest := sha256.Sum256([]byte(public))
	name := fmt.Sprintf("device-%x", digest[:8])
	if _, exists := st.Config.Identities[name]; exists {
		return errors.New("device identity name belongs to another key")
	}
	return m.editPolicy(ctx, []config.Change{{Path: []string{"identities", name}, Value: map[string]any{"key": public, "routes": true}}})
}

var errSandboxSSHDisabled = errors.New("browser terminals and sandbox setup are disabled; enable them in Monitor Settings")

// sandboxHandler gates the entire SSH path, including request decoding and setup.
func (m *monitor) sandboxHandler(next http.HandlerFunc) http.HandlerFunc {
	return m.ownerOnly(func(w http.ResponseWriter, r *http.Request) {
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

func (s sandboxMonitor) Boot(name string) config.Boot {
	return s.m.live.Load().Config.Identities[name].Sandbox
}

func (s sandboxMonitor) HostKey() ssh.Signer { return s.m.live.Load().HostKey }

func (s sandboxMonitor) CheckIdentity(name, key string, boot config.Boot) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	_, err := s.m.enrollmentChanges(map[string]identityEnrollment{name: {Key: key, Sandbox: boot}})
	return err
}

func (s sandboxMonitor) AddIdentity(ctx context.Context, name, key string, boot config.Boot) error {
	s.m.mu.Lock()
	defer s.m.mu.Unlock()
	changes, err := s.m.enrollmentChanges(map[string]identityEnrollment{name: {Key: key, Sandbox: boot}})
	if err != nil {
		return err
	}
	return s.m.editPolicy(ctx, changes)
}
