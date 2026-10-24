package monitor

import (
	"cmp"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/facts"
	"github.com/tinfoilsh/monitor/internal/config"
	"github.com/tinfoilsh/monitor/internal/ownerauth"
	"github.com/tinfoilsh/monitor/internal/sandbox"
	"github.com/tinfoilsh/monitor/internal/store"
)

const maxDocumentBytes = 16 << 20

type unlockInput struct {
	Initialize bool   `json:"initialize,omitempty"`
	Generation uint64 `json:"generation"`
	StorageKey []byte `json:"storage_key,omitempty"`
	DeviceKey  string `json:"device_key,omitempty"`
}

type sourceInput struct {
	Source string `json:"source"`
}

type editsInput struct {
	Generation *uint64         `json:"generation,omitempty"`
	Changes    []config.Change `json:"changes"`
}

// Handler serves the owner API on the local listener; a nil file handler uses embedded assets.
func (m *monitor) Handler(files http.Handler) http.Handler { return m.ownerHandler(false, files) }

// A nil file handler uses embedded assets. Owner SSH always uses embedded assets.
func (m *monitor) ownerHandler(overSSH bool, files http.Handler) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", jsonHandler(0, func(_ *http.Request, _ struct{}) (any, error) {
		return struct {
			Locked bool `json:"locked"`
		}{Locked: m.live.Load() == nil}, nil
	}))
	if m.ownerPublicKey != nil && !overSSH {
		// Base64 inflates the signed request by a third.
		mux.Handle("POST /owner/rpc", &ownerauth.Handler{Key: m.ownerPublicKey, Monitor: m.bucket, MaxBytes: 2 * maxDocumentBytes, API: m.ownerHandler(true, nil), Generation: m.generation})
		return mux
	}
	mux.Handle("POST /unlock", jsonHandler(maxDocumentBytes, func(r *http.Request, req unlockInput) (any, error) {
		key := req.StorageKey
		if m.ownerPublicKey != nil {
			session, ok := ownerauth.FromContext(r.Context())
			if !ok {
				return nil, store.ErrOwner
			}
			req.Generation = max(req.Generation, session.Minimum)
		} else {
			var err error
			key, err = bearerKey(r)
			if err != nil {
				return nil, err
			}
		}
		defer clear(key)
		err := m.unlock(r.Context(), key, req.Generation, req.Initialize || m.ownerPublicKey == nil)
		m.mu.Lock()
		defer m.mu.Unlock()
		if err == nil && req.DeviceKey != "" {
			err = m.restoreDevice(r.Context(), req.DeviceKey)
		}
		return m.view(err)
	}))
	mux.Handle("GET /{$}", owned(m, func(_ *http.Request, _ struct{}) (any, error) { return m.view(nil) }))
	mux.Handle("POST /enroll", owned(m, func(r *http.Request, input map[string]identityEnrollment) (any, error) {
		changes, err := m.enrollmentChanges(input)
		if err != nil {
			return nil, err
		}
		return m.view(m.editPolicy(r.Context(), changes))
	}))
	mux.Handle("POST /sandboxes/{name}/enroll", m.sandboxHandler(jsonHandler(sandbox.MaxRequestBytes, m.enrollSandbox)))
	mux.Handle("POST /sandboxes/{name}/shell", m.sandboxHandler(jsonHandler(sandbox.MaxRequestBytes, m.shellSandbox)))
	mux.Handle("GET /presets/{name}", owned(m, func(r *http.Request, _ struct{}) (any, error) {
		preset := m.live.Load().Config.Resolved[r.PathValue("name")]
		if preset == nil {
			return nil, errors.New("unknown preset")
		}
		return preset, nil
	}))
	mux.Handle("POST /labels/{identity}", owned(m, func(r *http.Request, l facts.Label) (any, error) {
		var fingerprint string
		for key, p := range m.live.Load().Principals {
			if p.Name == r.PathValue("identity") {
				fingerprint = key
			}
		}
		if fingerprint == "" {
			return nil, fmt.Errorf("no identity %s", r.PathValue("identity"))
		}
		if !l.Valid() {
			return nil, fmt.Errorf("a label needs trust in %v and audience in %v", facts.Trusts, facts.Audiences)
		}
		old := m.currentLabel(fingerprint)
		l.Because = map[string]string{}
		if l.Trust != cleanLabel.Trust {
			l.Because["trust"] = cmp.Or(old.Because["trust"], "the owner")
		}
		if l.Audience != cleanLabel.Audience {
			l.Because["audience"] = cmp.Or(old.Because["audience"], "the owner")
		}
		return m.view(m.observe(r.Context(), fingerprint, l, nil))
	}))
	mux.Handle("POST /accounts/{account}/sign-in", m.authenticated(jsonHandler(maxDocumentBytes, m.startSignIn)))
	mux.Handle("POST /sign-in/{state}", m.authenticated(jsonHandler(maxDocumentBytes, m.finishSignIn)))
	mux.Handle("/connections/{name}/{control...}", m.authenticated(m.connectionControl))
	mux.Handle("GET /requests", owned(m, func(r *http.Request, _ struct{}) (any, error) {
		records := m.records
		if r.URL.Query().Has("summary") {
			newest := make([]recordSummary, 0, len(records))
			for _, r := range slices.Backward(records) {
				newest = append(newest, r.summary())
			}
			return newest, nil
		}
		newest := make([]record, 0, len(records))
		for _, r := range slices.Backward(records) {
			newest = append(newest, *r)
		}
		return newest, nil
	}))
	mux.Handle("GET /audit", m.authenticated(jsonHandler(0, func(r *http.Request, _ struct{}) (any, error) {
		return m.readAuditPage(r.Context(), r.URL.Query().Get("before"))
	})))
	mux.Handle("GET /audit/{segment}/{id}", m.authenticated(jsonHandler(0, func(r *http.Request, _ struct{}) (any, error) {
		return m.readAuditRecord(r.Context(), r.PathValue("segment"), r.PathValue("id"))
	})))
	mux.Handle("GET /requests/{id}", owned(m, func(r *http.Request, _ struct{}) (any, error) {
		if record := m.findRecord(r.PathValue("id")); record != nil {
			return *record, nil
		}
		return nil, errRecordGone
	}))
	mux.Handle("POST /requests/{id}", owned(m, func(r *http.Request, req approvalInput) (any, error) {
		return nil, m.answerRequest(r.Context(), "owner", r.PathValue("id"), req)
	}))
	mux.Handle("GET /policy", owned(m, func(r *http.Request, _ struct{}) (any, error) {
		result := map[string]any{"source": m.store.Doc.Policy}
		var err error
		if r.URL.Query().Has("effective") {
			result["effective"], err = m.live.Load().Config.Effective()
		}
		return result, err
	}))
	mux.Handle("POST /policy/preview", owned(m, func(r *http.Request, input sourceInput) (any, error) {
		next, st, err := m.prepareCandidate(r.Context(), input.Source, nil)
		if err != nil {
			return nil, err
		}
		return m.policyPreview(next, st)
	}))
	mux.Handle("POST /policy", owned(m, func(r *http.Request, input sourceInput) (any, error) {
		next, st, err := m.prepareCandidate(r.Context(), input.Source, nil)
		if err == nil {
			err = m.activate(r.Context(), next, st)
		}
		return m.view(err)
	}))
	mux.Handle("POST /policy/edits", owned(m, func(r *http.Request, input editsInput) (any, error) {
		if input.Generation != nil && *input.Generation != m.store.Doc.Generation {
			return nil, errPolicyConflict
		}
		return m.view(m.editPolicy(r.Context(), input.Changes))
	}))
	mux.Handle("GET /app/auth.json", jsonHandler(0, func(_ *http.Request, _ struct{}) (any, error) {
		mode := "bearer"
		if overSSH {
			mode = "ssh"
		}
		return map[string]string{"mode": mode}, nil
	}))
	localFiles := files != nil && !overSSH
	if !localFiles {
		files = m.embeddedFiles
	}
	mux.HandleFunc("GET /app/", func(w http.ResponseWriter, r *http.Request) {
		// Owner SSH always serves the embedded assets. Local development can reload files.
		w.Header().Set("Cache-Control", "no-store")
		if localFiles {
			r.Header.Del("If-Modified-Since")
			r.Header.Del("If-None-Match")
		}
		files.ServeHTTP(w, r)
	})
	return mux
}

func (m *monitor) connectionControl(w http.ResponseWriter, r *http.Request) {
	c := m.live.Load().connections[r.PathValue("name")]
	if c == nil {
		http.NotFound(w, r)
		return
	}
	if status := c.status(); status.State != "ready" {
		http.Error(w, "the connector is "+status.State, http.StatusConflict)
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	defer cancel()
	stop := context.AfterFunc(c.ctx, cancel)
	defer stop()
	r.Body = http.MaxBytesReader(w, r.Body, maxDocumentBytes)
	if err := c.dispatch(ctx, func(service connector.Server, _ *connector.Env) {
		http.StripPrefix("/connections/"+c.Name, connector.Control(service)).ServeHTTP(w, r.WithContext(ctx))
	}); err != nil {
		http.Error(w, err.Error(), http.StatusServiceUnavailable)
	}
}

// owned runs each owner request as one transaction; reading the body and writing the response stay outside it.
func owned[T any](m *monitor, fn func(*http.Request, T) (any, error)) http.HandlerFunc {
	return m.authenticated(jsonHandler(maxDocumentBytes, func(r *http.Request, input T) (any, error) {
		m.mu.Lock()
		defer m.mu.Unlock()
		return fn(r, input)
	}))
}

// authenticated serves the owner without the monitor's lock, for calls that wait on the network.
func (m *monitor) authenticated(next http.HandlerFunc) http.HandlerFunc {
	if m.ownerPublicKey != nil {
		return func(w http.ResponseWriter, r *http.Request) {
			if _, ok := ownerauth.FromContext(r.Context()); !ok {
				responseError(w, store.ErrOwner)
				return
			}
			if m.live.Load() == nil {
				responseError(w, errLocked)
				return
			}
			next(w, r)
		}
	}

	return func(w http.ResponseWriter, r *http.Request) {
		key, err := bearerKey(r)
		// owner is set before live is published and never changes after.
		if err == nil && m.live.Load() == nil {
			err = errLocked
		}
		if err == nil && !m.store.IsOwner(key) {
			err = store.ErrOwner
		}
		if err != nil {
			responseError(w, err)
			return
		}
		next(w, r)
	}
}

// bearerKey reads the owner secret of a request without an owner public key.
func bearerKey(r *http.Request) ([]byte, error) {
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || len(token) > base64.StdEncoding.EncodedLen(store.MaxOwnerKeyBytes) {
		return nil, store.ErrOwner
	}
	key, err := base64.StdEncoding.Strict().DecodeString(token)
	if err != nil || len(key) < store.MinOwnerKeyBytes || len(key) > store.MaxOwnerKeyBytes {
		return nil, store.ErrOwner
	}
	return key, nil
}
