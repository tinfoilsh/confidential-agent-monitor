// Package monitor owns authorization transactions, connection runtime and the owner and agent APIs.
package monitor

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"sync"
	"sync/atomic"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/internal/audit"
	"github.com/tinfoilsh/monitor/internal/config"
	"github.com/tinfoilsh/monitor/internal/store"
	"github.com/tinfoilsh/monitor/internal/supervisor"
	"github.com/tinfoilsh/monitor/internal/tinfoil/sandbox"
	"github.com/tinfoilsh/monitor/internal/tinfoil/sandboxroute"
	"github.com/tinfoilsh/monitor/internal/worker"
	"gocloud.dev/blob"
	"golang.org/x/crypto/ssh"
)

// state is the atomically published configuration and policy snapshot.
// Connections own their runtime lifecycle; mutable device labels live in the committed document.
type state struct {
	*config.Snapshot
	connections map[string]*connection
	connector.Env
}

type Options struct {
	Bucket         *blob.Bucket
	BucketURL      string
	OwnerPublicKey ed25519.PublicKey
	HostKey        ssh.Signer
	Connectors     map[string]connector.Definition
	Workers        worker.Launcher
	EmbeddedFiles  http.Handler // Serves /app/ assets, including over owner SSH.
}

type monitor struct {
	workers worker.Launcher
	kinds   map[string]connector.Definition
	live    atomic.Pointer[state]
	mu      sync.Mutex
	store   store.Store
	running map[string]*supervisor.Conn
	audit   audit.Log[*record]

	ownerPublicKey ed25519.PublicKey
	sshHostKey     ssh.Signer
	embeddedFiles  http.Handler
	ownerAPI       http.Handler
	// bucket is the storage URL that binds owner RPC envelopes to this Monitor.
	bucket    string
	sandboxes *sandbox.Service

	routes sandboxroute.Table

	// mu owns authorization transactions, including documents, records and streams.
	streams map[*connector.Stream]string
	records []*record
	// signIns holds the finish of each started sign-in, keyed by its state.
	signIns sync.Map
}

func New(o Options) *monitor {
	if o.EmbeddedFiles == nil {
		o.EmbeddedFiles = http.NotFoundHandler()
	}
	m := &monitor{store: store.Store{Bucket: o.Bucket}, audit: audit.Log[*record]{Bucket: o.Bucket}, ownerPublicKey: o.OwnerPublicKey, sshHostKey: o.HostKey, bucket: o.BucketURL, kinds: o.Connectors, workers: o.Workers, embeddedFiles: o.EmbeddedFiles}
	m.sandboxes = sandbox.New(sandboxMonitor{m}, &m.routes, sandbox.Verify)
	m.ownerAPI = m.ownerHandler(true, nil)
	return m
}

func (m *monitor) generation() (uint64, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.store.Doc.Generation, m.live.Load() != nil
}

// The first unlock of an empty store makes its secret the owner's.
func (m *monitor) unlock(ctx context.Context, key []byte, minimum uint64, initialize bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.ownerPublicKey != nil && len(key) != store.OwnerKeyBytes {
		return store.ErrOwner
	}
	if m.live.Load() != nil {
		if !m.store.IsOwner(key) {
			return store.ErrOwner
		}
		if m.store.Doc.Generation < minimum {
			return fmt.Errorf("live generation %d is older than %d", m.store.Doc.Generation, minimum)
		}
		return nil
	}
	next, err := m.store.Load(ctx, key, minimum, initialize)
	if err != nil {
		return err
	}
	var env connector.Env
	if env.TLS, err = connectionTLS(&next.Doc.Keys); err != nil {
		return err
	}
	env.HostKey = m.sshHostKey
	if env.HostKey == nil {
		if env.HostKey, err = next.Doc.Keys.HostSigner(); err != nil {
			return err
		}
	}
	s, err := m.build(ctx, &next.Doc, env, nil)
	if err != nil {
		return err
	}
	previous := m.store
	m.store = next
	m.audit.SealWith(next.Sealer)
	if err := m.activate(ctx, next.Doc, s); err != nil {
		m.store = previous
		return err
	}
	return nil
}

// activate persists a candidate prepared under the same lock, then publishes it.
func (m *monitor) activate(ctx context.Context, next store.Document, s *state) error {
	old := m.live.Load()
	next.Enrolled = maps.Clone(next.Enrolled)
	if next.Enrolled == nil {
		next.Enrolled = map[string]bool{}
	}
	for key := range s.Principals {
		next.Enrolled[key] = true
	}
	next.Labels = maps.Clone(next.Labels)
	maps.DeleteFunc(next.Labels, func(key string, _ facts.Label) bool { _, ok := s.Principals[key]; return !ok })
	if err := m.store.Commit(ctx, next); err != nil {
		return err
	}
	if !s.Config.AllowSandboxSSH {
		m.sandboxes.CloseShells()
	}
	if old == nil {
		m.streams, m.running = map[*connector.Stream]string{}, map[string]*supervisor.Conn{}
	}
	for stream, key := range m.streams {
		if !s.sameStreamAuthority(old, key, stream) {
			stream.Close()
		}
	}
	m.reconcile(s)
	m.live.Store(s)
	// Pending decisions belong to the configuration that requested them.
	m.refusePending(errChanged)
	return nil
}

var errLocked = errors.New("the monitor is locked")
