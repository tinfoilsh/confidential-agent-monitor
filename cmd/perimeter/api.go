package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/klauspost/compress/gzhttp"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/config"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/connections"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/format"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/sandbox"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/credential"
	"github.com/tinfoilsh/confidential-agent-monitor/core"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/tomledit"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/netx"
	"golang.org/x/crypto/ssh"
)

const (
	maxDocumentBytes = 16 << 20
	maxCallBytes     = 2 * maxDocumentBytes
	maxAgentBytes    = 96 << 10
	adminPrefix      = "/admin"
	agentHost        = config.AgentConnection + connections.Domain
	agentPort        = 80
)

var errLocked = httpError{errors.New("the Perimeter is locked"), http.StatusLocked}

var errOAuthLoopback = errors.New("this service only accepts sign-ins from a loopback address; open this Perimeter on your own computer to sign in")

type caller struct {
	Name          string
	Key           string
	MinGeneration uint64
	Acknowledge   func() error
	Session       string
	StorageKey    []byte
}

type callerKey struct{}

func withCaller(ctx context.Context, c caller) context.Context {
	return context.WithValue(ctx, callerKey{}, c)
}

func callerFrom(ctx context.Context) (caller, bool) {
	c, ok := ctx.Value(callerKey{}).(caller)
	return c, ok
}

func jsonHandler[T any](limit int64, fn func(*http.Request, T) (any, error)) http.HandlerFunc {
	return gzhttp.GzipHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		var req T
		if r.Method == http.MethodPost {
			raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
			if err == nil {
				err = facts.DecodeNumbers(raw, &req)
			}
			if err != nil {
				fail(w, err)
				return
			}
		}
		value, err := fn(r, req)
		var response []byte
		if err == nil {
			response, err = json.Marshal(value)
		}
		if c, ok := callerFrom(r.Context()); ok && c.Acknowledge != nil && err == nil {
			err = c.Acknowledge()
		}
		if err != nil {
			fail(w, err)
			return
		}
		if r.Method == http.MethodGet {
			tag := fmt.Sprintf(`W/"%x"`, sha256.Sum256(response))
			w.Header().Set("ETag", tag)
			for _, known := range strings.Split(r.Header.Get("If-None-Match"), ",") {
				known = strings.TrimSpace(known)
				if known == "*" || strings.TrimPrefix(known, "W/") == strings.TrimPrefix(tag, "W/") {
					w.WriteHeader(http.StatusNotModified)
					return
				}
			}
		}
		w.Header().Set("Content-Type", "application/json")
		w.Write(response)
	}))
}

func fail(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	var specific interface{ HTTPStatus() int }
	if errors.As(err, &specific) {
		status = specific.HTTPStatus()
	}
	http.Error(w, err.Error(), status)
}

type httpError struct {
	error
	status int
}

func (e httpError) HTTPStatus() int { return e.status }

type unlockInput struct {
	Generation uint64 `json:"generation"`
	StorageKey []byte `json:"storage_key,omitempty"`
	DeviceKey  string `json:"device_key,omitempty"`
}

type sourceInput struct {
	Revision *uint64 `json:"revision,omitempty"`
	Source   string  `json:"source"`
}

type editsInput struct {
	Revision    *uint64           `json:"revision,omitempty"`
	Changes     []tomledit.Change `json:"changes"`
	Credentials format.Secrets    `json:"credentials,omitempty"`
}

type answerInput struct {
	Answer
	Revision uint64 `json:"revision"`
}

func (s *state) adminAPI(owner bool) http.Handler {
	m := adminMount{s, owner}
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", jsonHandler(0, func(r *http.Request, _ struct{}) (any, error) {
		var health struct {
			State string `json:"state,omitempty"`
		}
		if _, authenticated := callerFrom(r.Context()); owner && authenticated {
			present, err := format.Exists(r.Context(), s.bucket)
			if err != nil {
				return nil, httpError{err, http.StatusServiceUnavailable}
			}
			health.State = map[bool]string{false: "absent", true: "present"}[present]
		}
		return health, nil
	}))
	mux.Handle("POST /unlock", jsonHandler(maxDocumentBytes, func(r *http.Request, req unlockInput) (any, error) {
		c, err := requestCaller(r)
		if err != nil {
			return nil, err
		}
		key := req.StorageKey
		if len(key) == 0 {
			key = c.StorageKey
		}
		req.Generation = max(req.Generation, c.MinGeneration)
		defer clear(key)
		ctx := withCaller(r.Context(), c)
		initialized, err := s.unlock(ctx, key, req.Generation)
		if err == nil && req.DeviceKey != "" {
			err = s.restoreDevice(ctx, req.DeviceKey)
		}
		view, err := s.viewAfter(r, err)
		view.Initialized = initialized
		return view, err
	}))
	// The overview includes the whole policy, so reading it needs policy.read as well.
	overview := func(adminMount, *http.Request, any) ([]facts.Observation, error) {
		return []facts.Observation{perimeterCall("overview.read", map[string]any{}), perimeterCall(config.PolicyRead, map[string]any{})}, nil
	}
	mux.Handle("GET /{$}", authorizedLockedHandler(m, overview, func(h held, r *http.Request, _ struct{}) (any, error) { return h.view(r) }))

	mux.Handle("GET /policy", authorizedLockedHandler(m, pathAction(config.PolicyRead), func(h held, r *http.Request, _ struct{}) (any, error) {
		doc := h.doc
		result := map[string]any{"source": doc.Policy, "revision": doc.Revision}
		var err error
		if r.URL.Query().Has("effective") {
			result["effective"], err = s.settings.Load().Config.Effective()
		}
		return result, err
	}))
	mux.Handle("GET /explain", authorizedLockedHandler(m, pathAction("explain", "identity"), held.explainIdentity))
	mux.Handle("POST /policy/preview", authorizedHandler(m, maxDocumentBytes, pathAction("policy.preview"), func(r *http.Request, input sourceInput) (any, error) {
		return withWriteLock(s, func(base format.Document, before *settings) (*policyDiff, error) {
			if !owner {
				if err := fetchesUnchanged(base.Policy, input.Source); err != nil {
					return nil, err
				}
			}
			return s.previewPolicy(r.Context(), base, before, input.Source)
		})
	}))
	mux.Handle("POST /policy", authorizedHandler(m, maxDocumentBytes, policyWriteActions, func(r *http.Request, input sourceInput) (any, error) {
		return s.viewAfter(r, s.writeSettings(r.Context(), settingsWrite{source: &input.Source, check: reviewed(input.Revision)}))
	}))
	mux.Handle("POST /policy/edits", authorizedHandler(m, maxDocumentBytes, policyEditActions, func(r *http.Request, input editsInput) (any, error) {
		for _, values := range input.Credentials {
			for name, raw := range values {
				if bytes.Equal(raw, []byte("null")) {
					values[name] = nil
				}
			}
		}
		err := s.writeSettings(r.Context(), settingsWrite{changes: input.Changes, credentials: input.Credentials, check: reviewed(input.Revision)})
		return s.viewAfter(r, err)
	}))

	mux.Handle("POST /enroll", authorizedHandler(m, maxDocumentBytes, enrollActions, func(r *http.Request, input map[string]config.Enrollment) (any, error) {
		_, err := s.enroll(r.Context(), input)
		return s.viewAfter(r, err)
	}))
	mux.Handle("POST /labels/{identity}", authorizedLockedHandler(m, bodyAction("labels.write", "identity"), held.setLabel))

	mux.Handle("POST /connections/{connection}/sign-in", authorizedHandler(m, maxDocumentBytes, pathAction("credentials.write", "connection"), s.startSignIn))
	mux.Handle("POST /sign-in/{state}", authorizedHandler(m, maxDocumentBytes, pathAction("credentials.write"), s.finishSignIn))
	mux.Handle("/connections/{connection}/{control...}", s.requireUnlocked(func(w http.ResponseWriter, r *http.Request) {
		// The owner's use of a connection's controls is not audited.
		if owner {
			s.connectionControl(w, r)
			return
		}
		if err := m.perform(r, pathAction("connections.control", "connection"), nil, func() error { s.connectionControl(w, r); return nil }); err != nil {
			fail(w, err)
		}
	}))
	mux.Handle(sandbox.RelayRoute, authorizedHandler(m, sandbox.MaxRelayBytes, bodyAction("bunkers.relay"), func(r *http.Request, in sandbox.RelayInput) (any, error) {
		return sandbox.Relay(r.Context(), s.relays, in)
	}))

	mux.Handle("GET /requests", authorizedList(m, config.RequestsRead, func(_ *http.Request, shows func(string) bool) (any, error) {
		newest := []recordSummary{}
		s.locked(func(h held) {
			for _, record := range slices.Backward(slices.Collect(h.records.All())) {
				if shows(record.subject().Principal.Name) {
					newest = append(newest, summarize(record))
				}
			}
		})
		return newest, nil
	}))
	mux.Handle("GET /requests/{id}", authorizedLockedHandler(m, subjectReadActions(config.RequestsRead, pendingRecordSubject), func(h held, r *http.Request, _ struct{}) (any, error) {
		if record := h.findRecord(r.PathValue("id")); record != nil {
			return *record, nil
		}
		return nil, errRecordGone
	}))
	mux.Handle("POST /requests/{id}", authorizedHandler(m, maxDocumentBytes, answerActions, func(r *http.Request, input answerInput) (any, error) {
		return s.viewAfter(r, s.answerRequest(r.Context(), r.PathValue("id"), input.Answer, input.Revision))
	}))

	mux.Handle("GET /catalogs/updates", authorizedHandler(m, 0, pathAction("catalogs.read"), func(r *http.Request, _ struct{}) (any, error) {
		return s.catalogUpdates(r.Context())
	}))
	mux.Handle("GET /audit", authorizedList(m, config.AuditRead, func(r *http.Request, shows func(string) bool) (any, error) {
		return s.readAuditPage(r.Context(), r.URL.Query().Get("before"), shows)
	}))
	mux.Handle("GET /audit/{segment}/{id}", authorizedHandler(m, 0, subjectReadActions(config.AuditRead, auditRecordSubject), func(r *http.Request, _ struct{}) (any, error) {
		return s.readAuditRecord(r.Context(), r.PathValue("segment"), r.PathValue("id"))
	}))
	return mux
}

func (s *state) connectionControl(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("connection")
	handler, setupCtx, release, ok := s.table.Control(name)
	if !ok {
		if _, installed := s.table.Connections()[name]; !installed {
			http.NotFound(w, r)
			return
		}
		http.Error(w, errChanged.Error(), http.StatusConflict)
		return
	}
	defer release()
	ctx, cancel := netx.Bind(r.Context(), setupCtx)
	defer cancel()
	r.Body = http.MaxBytesReader(w, r.Body, maxDocumentBytes)
	http.StripPrefix("/connections/"+name, handler).ServeHTTP(w, r.WithContext(ctx))
}

func (s held) setLabel(r *http.Request, l format.Label) (any, error) {
	identity := r.PathValue("identity")
	if s.identities.Keys(identity) == nil {
		return nil, fmt.Errorf("no identity %s", identity)
	}
	if !config.ValidLabel(l) {
		return nil, fmt.Errorf("a label needs trust in %v and audience in %v", config.Trusts, config.Audiences)
	}
	old := s.label(identity)
	l.Because = map[string]string{}
	if l.Trust != config.InitialLabel.Trust {
		l.Because["trust"] = cmp.Or(old.Because["trust"], "the owner")
	}
	if l.Audience != config.InitialLabel.Audience {
		l.Because["audience"] = cmp.Or(old.Because["audience"], "the owner")
	}
	if err := s.relabel(r.Context(), identity, l, nil); err != nil {
		return nil, err
	}
	return s.view(r)
}

func (s *state) viewAfter(r *http.Request, err error) (v ownerView, _ error) {
	if err != nil {
		return ownerView{}, err
	}
	s.locked(func(h held) { v, err = h.view(r) })
	return v, err
}

func requestCaller(r *http.Request) (caller, error) {
	if c, ok := callerFrom(r.Context()); ok {
		return c, nil
	}
	return caller{}, errOwner
}

type agentCatalogView struct {
	CatalogID  string                         `json:"catalog_id"`
	Presets    map[string]config.CatalogEntry `json:"presets"`
	Vocabulary map[string]config.Traits       `json:"vocabulary"`
}

func (s *state) agentAPI(fingerprint string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /connections", agentHandler(s, fingerprint, func(h held, _ *http.Request, _ struct{}, p facts.Principal) (any, error) {
		return h.listing(p), nil
	}))
	mux.HandleFunc("GET /policy", agentHandler(s, fingerprint, func(h held, _ *http.Request, _ struct{}, p facts.Principal) (any, error) {
		return h.agentPolicy(p)
	}))
	mux.HandleFunc("GET /explain", agentHandler(s, fingerprint, held.explainSelf))
	mux.HandleFunc("GET /catalog", agentHandler(s, fingerprint, func(held, *http.Request, struct{}, facts.Principal) (any, error) {
		st := s.settings.Load()
		return agentCatalogView{CatalogID: st.catalogID, Presets: st.catalog, Vocabulary: config.Vocabulary}, nil
	}))
	mux.HandleFunc("GET /policy/proposals/{id}", agentHandler(s, fingerprint, func(h held, r *http.Request, _ struct{}, p facts.Principal) (any, error) {
		record := h.findRecord(r.PathValue("id"))
		if record == nil || record.Changes == nil || !record.subject().Principal.Same(p) {
			return nil, errRecordGone
		}
		return receipt(record), nil
	}))
	mux.HandleFunc("POST /policy/proposals", jsonHandler(maxAgentBytes, func(r *http.Request, input config.Proposal) (any, error) {
		return s.proposePolicy(r.Context(), fingerprint, input)
	}))
	api := s.adminAPI(false)
	mux.Handle(adminPrefix+"/", http.StripPrefix(adminPrefix, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := s.identities.Lookup(fingerprint)
		switch {
		case !ok:
			fail(w, errNoAgent)
		case r.Host != agentHost || r.URL.Path == "/unlock":
			http.NotFound(w, r)
		default:
			api.ServeHTTP(w, r.WithContext(withCaller(r.Context(), caller{Name: p.Name, Key: fingerprint, Session: fingerprint})))
		}
	})))
	return mux
}

func agentHandler[T any](s *state, fingerprint string, fn func(held, *http.Request, T, facts.Principal) (any, error)) http.HandlerFunc {
	return jsonHandler(maxAgentBytes, func(r *http.Request, input T) (value any, err error) {
		s.locked(func(h held) {
			if p, ok := s.identities.Lookup(fingerprint); ok {
				value, err = fn(h, r, input, p)
			} else {
				err = errNoAgent
			}
		})
		return value, err
	})
}

type fieldMetadata struct {
	Name        string `json:"name"`
	Kind        string `json:"kind"`
	Placeholder string `json:"placeholder,omitempty"`
	Account     string `json:"account,omitempty"`
}

type ownerView struct {
	Generation  uint64                         `json:"generation"`
	Revision    uint64                         `json:"revision"`
	Config      map[string]any                 `json:"config"`
	HostKey     string                         `json:"host_key"`
	HostID      string                         `json:"host_id"`
	CA          string                         `json:"ca"`
	Fields      map[string][]fieldMetadata     `json:"fields"`
	Status      map[string]core.Status         `json:"status"`
	Labels      map[string]format.Label        `json:"labels"`
	CatalogID   string                         `json:"catalog_id"`
	Presets     map[string]config.CatalogEntry `json:"presets,omitempty"`
	Initialized bool                           `json:"initialized"`
}

func (s held) view(r *http.Request) (ownerView, error) {
	st, doc := s.settings.Load(), s.doc
	v := ownerView{Generation: doc.Generation, Revision: doc.Revision, HostKey: string(ssh.MarshalAuthorizedKey(st.hostKey.PublicKey())), HostID: s.hostID, CA: doc.Keys.CACert,
		Fields: map[string][]fieldMetadata{}, Status: map[string]core.Status{}, Labels: map[string]format.Label{},
		CatalogID: st.catalogID, Presets: st.catalog}
	if r.URL.Query().Get("catalog") == st.catalogID {
		v.Presets = nil
	}
	var err error
	if v.Config, err = st.Config.OwnerView(); err != nil {
		return ownerView{}, err
	}
	for name, status := range s.table.Connections() {
		v.Status[name] = status
		for secret, placeholder := range st.connections[name].placeholders {
			kind, account := credential.Describe(doc.Credentials.Get(format.SecretID{Connection: name, Name: secret}))
			v.Fields[name] = append(v.Fields[name], fieldMetadata{Name: secret, Kind: kind, Placeholder: placeholder, Account: account})
		}
	}
	for _, fields := range v.Fields {
		slices.SortFunc(fields, func(a, b fieldMetadata) int { return strings.Compare(a.Name, b.Name) })
	}
	for name := range st.Identities {
		v.Labels[name] = s.label(name)
	}
	return v, nil
}

type connectionListing struct {
	Name         string            `json:"name"`
	Protocol     string            `json:"kind"`
	Host         string            `json:"host"`
	State        string            `json:"state"`
	Resolved     config.Resolved   `json:"resolved"`
	Hosts        []string          `json:"hosts"`
	Slots        any               `json:"slots"`
	Placeholders map[string]string `json:"placeholders"`
	Credentials  map[string]string `json:"credentials,omitempty"`
}

func (s held) listing(p facts.Principal) any {
	st, doc := s.settings.Load(), s.doc
	result := struct {
		Identity    string              `json:"identity"`
		CA          string              `json:"ca"`
		Connections []connectionListing `json:"connections"`
	}{p.Name, doc.Keys.CACert, []connectionListing{}}
	status := s.table.Connections()
	for _, name := range slices.Sorted(maps.Keys(status)) {
		c, resolved := st.connections[name], st.Resolve(p.Name, p.Groups, name)
		if !resolved.Reaches {
			continue
		}
		l := connectionListing{Name: name, Protocol: c.Protocol, Host: name + connections.Domain,
			State: status[name].State, Resolved: resolved, Hosts: c.Discovery, Slots: c.Slots}
		if c.ListsPlaceholders {
			l.Placeholders = maps.Clone(c.placeholders)
		}
		if len(c.secrets) != 0 {
			l.Credentials = map[string]string{}
			for secret := range c.secrets {
				l.Credentials[secret], _ = credential.Describe(doc.Credentials.Get(format.SecretID{Connection: name, Name: secret}))
			}
		}
		result.Connections = append(result.Connections, l)
	}
	return result
}

func (s held) agentPolicy(p facts.Principal) (any, error) {
	st := s.settings.Load()
	var visible map[string]any
	var err error
	if st.wouldAllow(p, s.label(p.Name), perimeterCall(config.PolicyRead, nil)) != nil {
		visible, err = st.Config.OwnerView()
	} else {
		visible, err = st.Config.AgentView(p)
	}
	if err != nil {
		return nil, err
	}
	source, err := tomledit.Render(visible)
	return map[string]any{"identity": p.Name, "source": source}, err
}

type signInInput struct {
	Redirect   string          `json:"redirect"`
	Name       string          `json:"name"`
	Credential json.RawMessage `json:"credential"`
}

func (s *state) startSignIn(r *http.Request, req signInInput) (any, error) {
	raw, save, err := s.signInCredential(r.PathValue("connection"), req.Name)
	if err != nil {
		return nil, err
	}
	if req.Credential != nil {
		raw = req.Credential
	}
	from, _ := callerFrom(r.Context())
	sign, err := s.signIns.Start(r.Context(), s.settings.Load().guardedClient(), raw, req.Redirect, from.Session, save)
	if errors.Is(err, credential.ErrLoopback) {
		err = errOAuthLoopback
	}
	if err != nil {
		return nil, err
	}
	if sign.UserCode != "" {
		return map[string]any{"url": sign.URL, "state": sign.State, "user_code": sign.UserCode, "expires": sign.Expires}, nil
	}
	return map[string]string{"url": sign.URL}, nil
}

func (s *state) finishSignIn(r *http.Request, req credential.SignInResult) (any, error) {
	from, _ := callerFrom(r.Context())
	pending, err := s.signIns.Finish(r.Context(), r.PathValue("state"), from.Session, req)
	if pending {
		return map[string]bool{"pending": true}, nil
	}
	if err == nil && req.Cancel {
		return nil, nil
	}
	return s.viewAfter(r, err)
}
