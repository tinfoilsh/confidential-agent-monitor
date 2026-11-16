package main

import (
	"bytes"
	"cmp"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/klauspost/compress/gzhttp"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/config"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/connections"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/format"
	"github.com/tinfoilsh/confidential-agent-monitor/core"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/netx"
	"golang.org/x/crypto/ssh"
)

const (
	ownerName        = "owner"
	maxDocumentBytes = 16 << 20
	maxCallBytes     = 2 * maxDocumentBytes
	maxAgentBytes    = 96 << 10
	adminPrefix      = "/admin"
	agentHost        = config.AgentConnection + connections.Domain
	agentPort        = 80
)

var errLocked = httpError{errors.New("the Perimeter is locked"), http.StatusLocked}

type caller struct {
	Name        string
	Owner       bool
	Claims      map[string]any
	Minimum     uint64
	Acknowledge func() error
	ID          string
	Key         []byte
}

type callerKey struct{}

type routeKey struct{}

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

type refused string

func (r refused) Error() string { return string(r) }
func (refused) HTTPStatus() int { return http.StatusForbidden }

type unavailable struct{ error }

func (unavailable) HTTPStatus() int { return http.StatusServiceUnavailable }

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
	Revision    *uint64         `json:"revision,omitempty"`
	Changes     []format.Change `json:"changes"`
	Credentials format.Secrets  `json:"credentials,omitempty"`
}

func (s *state) adminAPI() http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /healthz", jsonHandler(0, func(r *http.Request, _ struct{}) (any, error) {
		var health struct {
			State string `json:"state,omitempty"`
		}
		if c, _ := callerFrom(r.Context()); c.Owner {
			present, err := stateExists(r.Context(), s.bucket)
			if err != nil {
				return nil, unavailable{err}
			}
			health.State = map[bool]string{false: "absent", true: "present"}[present]
		}
		return health, nil
	}))
	mux.Handle("POST /unlock", jsonHandler(maxDocumentBytes, func(r *http.Request, req unlockInput) (any, error) {
		c, err := requestCaller(r)
		key := req.StorageKey
		if err == nil && len(key) == 0 {
			key = c.Key
		}
		if err != nil {
			return nil, err
		}
		req.Generation = max(req.Generation, c.Minimum)
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
	mux.Handle("GET /{$}", ownerTx(s, func(r *http.Request, _ struct{}) (any, error) { return s.view(r) }))
	mux.Handle("POST /enroll", s.ownerOnly(jsonHandler(maxDocumentBytes, func(r *http.Request, input map[string]identityEnrollment) (any, error) {
		return s.viewAfter(r, s.enroll(r.Context(), input))
	})))
	for pattern, handler := range adminRoutes {
		mux.Handle(pattern, s.ownerOnly(handler.ServeHTTP))
	}
	mux.Handle("POST /labels/{identity}", ownerTx(s, func(r *http.Request, l format.Label) (any, error) {
		fingerprints := s.identities.Keys(r.PathValue("identity"))
		if fingerprints == nil {
			return nil, fmt.Errorf("no identity %s", r.PathValue("identity"))
		}
		if !config.ValidLabel(l) {
			return nil, fmt.Errorf("a label needs trust in %v and audience in %v", config.Trusts, config.Audiences)
		}
		var err error
		for _, fingerprint := range fingerprints {
			old := s.label(fingerprint)
			l.Because = map[string]string{}
			if l.Trust != config.InitialLabel.Trust {
				l.Because["trust"] = cmp.Or(old.Because["trust"], "the owner")
			}
			if l.Audience != config.InitialLabel.Audience {
				l.Because["audience"] = cmp.Or(old.Because["audience"], "the owner")
			}
			if err = s.relabel(r.Context(), fingerprint, l, nil); err != nil {
				break
			}
		}
		s.recordAdmin(r.Context(), "Set the label of "+r.PathValue("identity"), l, err)
		if err != nil {
			return nil, err
		}
		return s.view(r)
	}))
	mux.Handle("POST /connections/{name}/sign-in", s.ownerOnly(jsonHandler(maxDocumentBytes, s.startSignIn)))
	mux.Handle("POST /sign-in/{state}", s.ownerOnly(jsonHandler(maxDocumentBytes, s.finishSignIn)))
	mux.Handle("/connections/{name}/{control...}", s.ownerOnly(s.connectionControl))
	mux.Handle("GET /requests", ownerTx(s, func(*http.Request, struct{}) (any, error) {
		newest := []recordSummary{}
		for _, r := range slices.Backward(slices.Collect(s.records.All())) {
			newest = append(newest, summarize(r))
		}
		return newest, nil
	}))
	mux.Handle("GET /audit", s.ownerOnly(jsonHandler(0, func(r *http.Request, _ struct{}) (any, error) {
		return s.readAuditPage(r.Context(), r.URL.Query().Get("before"))
	})))
	mux.Handle("GET /audit/{segment}/{id}", s.ownerOnly(jsonHandler(0, func(r *http.Request, _ struct{}) (any, error) {
		return s.readAuditRecord(r.Context(), r.PathValue("segment"), r.PathValue("id"))
	})))
	mux.Handle("GET /requests/{id}", ownerTx(s, func(r *http.Request, _ struct{}) (any, error) {
		if record := s.findRecord(r.PathValue("id")); record != nil {
			return *record, nil
		}
		return nil, errRecordGone
	}))
	mux.Handle("POST /requests/{id}", s.ownerOnly(jsonHandler(maxDocumentBytes, func(r *http.Request, req struct {
		Answer
		Revision uint64 `json:"revision"`
	}) (any, error) {
		return s.viewAfter(r, s.answerRequest(r.Context(), r.PathValue("id"), req.Answer, req.Revision))
	})))
	mux.Handle("GET /policy", ownerTx(s, func(r *http.Request, _ struct{}) (any, error) {
		doc := s.doc
		result := map[string]any{"source": doc.Policy, "revision": doc.Revision}
		var err error
		if r.URL.Query().Has("effective") {
			result["effective"], err = s.settings.Load().Config.Effective()
		}
		return result, err
	}))
	mux.Handle("POST /policy/preview", s.ownerOnly(jsonHandler(maxDocumentBytes, func(r *http.Request, input sourceInput) (any, error) {
		return stable(s, func(base format.Document, before *settings) (*policyDiff, error) {
			return s.previewPolicy(r.Context(), base, before, input.Source)
		})
	})))
	mux.Handle("POST /policy", s.ownerOnly(jsonHandler(maxDocumentBytes, func(r *http.Request, input sourceInput) (any, error) {
		return s.viewAfter(r, s.writeSettings(r.Context(), settingsWrite{source: &input.Source, check: s.reviewed(input.Revision)}))
	})))
	mux.Handle("POST /policy/edits", s.ownerOnly(jsonHandler(maxDocumentBytes, func(r *http.Request, input editsInput) (any, error) {
		for _, values := range input.Credentials {
			for name, raw := range values {
				if bytes.Equal(raw, []byte("null")) {
					values[name] = nil
				}
			}
		}
		err := s.writeSettings(r.Context(), settingsWrite{changes: input.Changes, credentials: input.Credentials, check: s.reviewed(input.Revision)})
		return s.viewAfter(r, err)
	})))
	return mux
}

func (s *state) connectionControl(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
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

func (s *state) viewAfter(r *http.Request, err error) (v ownerView, _ error) {
	if err != nil {
		return ownerView{}, err
	}
	s.locked(func() { v, err = s.view(r) })
	return v, err
}

func ownerTx[T any](s *state, fn func(*http.Request, T) (any, error)) http.HandlerFunc {
	return s.ownerOnly(jsonHandler(maxDocumentBytes, func(r *http.Request, input T) (value any, err error) {
		s.locked(func() { value, err = fn(r, input) })
		return value, err
	}))
}

func (s *state) ownerOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		st := s.settings.Load()
		c, err := requestCaller(r)
		if err == nil && st == nil {
			err = errLocked
		}
		ctx := withCaller(context.WithValue(r.Context(), routeKey{}, r.Pattern), c)
		if err == nil {
			err = s.admitCall(ctx, st, adminCall{})
		}
		if err != nil {
			fail(w, err)
			return
		}
		next(w, r.WithContext(ctx))
	}
}

func (s *state) admitCall(ctx context.Context, st *settings, call adminCall) error {
	c, _ := callerFrom(ctx)
	call.Caller = policyCaller{Name: c.Name, Owner: c.Owner, Claims: c.Claims}
	call.Route, _ = ctx.Value(routeKey{}).(string)
	var deny []string
	err := st.policy.Eval(ctx, config.QueryAdmin, call, &deny)
	if err == nil && len(deny) != 0 {
		err = refused(strings.Join(deny, "; "))
	}
	return err
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
	Vocabulary map[string]config.Obligations  `json:"vocabulary"`
}

func (s *state) agentAPI(key string) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /connections", agentTx(s, key, func(_ *http.Request, _ struct{}, p facts.Principal) (any, error) {
		return s.listing(p), nil
	}))
	mux.HandleFunc("GET /policy", agentTx(s, key, func(_ *http.Request, _ struct{}, p facts.Principal) (any, error) {
		return s.agentPolicy(p)
	}))
	mux.HandleFunc("GET /catalog", agentTx(s, key, func(*http.Request, struct{}, facts.Principal) (any, error) {
		st := s.settings.Load()
		return agentCatalogView{CatalogID: st.catalogID, Presets: st.catalog, Vocabulary: config.Vocabulary}, nil
	}))
	mux.HandleFunc("GET /policy/proposals/{id}", agentTx(s, key, func(r *http.Request, _ struct{}, p facts.Principal) (any, error) {
		record := s.findRecord(r.PathValue("id"))
		if record == nil || record.Changes == nil || !summarize(record).Facts.Principal.Same(p) {
			return nil, errRecordGone
		}
		return receipt(record), nil
	}))
	mux.HandleFunc("POST /policy/proposals", jsonHandler(maxAgentBytes, func(r *http.Request, input proposalInput) (any, error) {
		return s.proposePolicy(r.Context(), key, input)
	}))
	api := s.adminAPI()
	mux.Handle(adminPrefix+"/", http.StripPrefix(adminPrefix, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p, ok := s.identities.Lookup(key)
		switch {
		case !ok:
			fail(w, errNoAgent)
		case p.Name == ownerName:
			fail(w, refused("an identity named owner cannot make admin calls"))
		case r.Host != agentHost || r.URL.Path == "/unlock":
			http.NotFound(w, r)
		default:
			c := caller{Name: p.Name, ID: key, Claims: map[string]any{"key": key, "groups": append([]string{}, p.Groups...)}}
			api.ServeHTTP(w, r.WithContext(withCaller(r.Context(), c)))
		}
	})))
	return mux
}

func agentTx[T any](s *state, key string, fn func(*http.Request, T, facts.Principal) (any, error)) http.HandlerFunc {
	return jsonHandler(maxAgentBytes, func(r *http.Request, input T) (value any, err error) {
		s.locked(func() {
			if p, ok := s.identities.Lookup(key); ok {
				value, err = fn(r, input, p)
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
	Vocabulary  map[string]config.Obligations  `json:"vocabulary"`
	Initialized bool                           `json:"initialized"`
}

func (s *state) view(r *http.Request) (ownerView, error) {
	st, doc := s.settings.Load(), s.doc
	block, _ := pem.Decode([]byte(doc.Keys.CACert))
	if block == nil {
		return ownerView{}, errors.New("Perimeter has no host certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return ownerView{}, err
	}
	key, err := jwk.Import(certificate.PublicKey)
	if err != nil {
		return ownerView{}, err
	}
	thumbprint, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return ownerView{}, err
	}
	v := ownerView{Generation: doc.Generation, Revision: doc.Revision, HostKey: string(ssh.MarshalAuthorizedKey(st.hostKey.PublicKey())), CA: doc.Keys.CACert,
		HostID: "urn:ietf:params:oauth:jwk-thumbprint:sha-256:" + base64.RawURLEncoding.EncodeToString(thumbprint),
		Fields: map[string][]fieldMetadata{}, Status: map[string]core.Status{}, Labels: map[string]format.Label{},
		CatalogID: st.catalogID, Presets: st.catalog, Vocabulary: config.Vocabulary}
	if r.URL.Query().Get("catalog") == st.catalogID {
		v.Presets = nil
	}
	if v.Config, err = st.Config.View(); err != nil {
		return ownerView{}, err
	}
	for name, status := range s.table.Connections() {
		v.Status[name] = status
		for secret, placeholder := range st.connections[name].placeholders {
			kind, account := describeCredential(doc.Credentials.Get(format.SecretID{Connection: name, Name: secret}))
			v.Fields[name] = append(v.Fields[name], fieldMetadata{Name: secret, Kind: kind, Placeholder: placeholder, Account: account})
		}
	}
	for _, fields := range v.Fields {
		slices.SortFunc(fields, func(a, b fieldMetadata) int { return strings.Compare(a.Name, b.Name) })
	}
	for key, name := range st.Principals {
		v.Labels[name] = s.label(key)
	}
	return v, nil
}

type connectionListing struct {
	Name         string            `json:"name"`
	Protocol     string            `json:"kind"`
	Host         string            `json:"host"`
	State        string            `json:"state"`
	Access       config.Access     `json:"access"`
	Hosts        []string          `json:"hosts"`
	Slots        any               `json:"slots"`
	Placeholders map[string]string `json:"placeholders"`
	Credentials  map[string]string `json:"credentials,omitempty"`
}

func (s *state) listing(p facts.Principal) any {
	st, doc := s.settings.Load(), s.doc
	result := struct {
		Identity    string              `json:"identity"`
		CA          string              `json:"ca"`
		Connections []connectionListing `json:"connections"`
	}{p.Name, doc.Keys.CACert, []connectionListing{}}
	status := s.table.Connections()
	for _, name := range slices.Sorted(maps.Keys(status)) {
		c := st.connections[name]
		if !st.Reaches(p.Name, name) {
			continue
		}
		l := connectionListing{Name: name, Protocol: c.Protocol, Host: name + connections.Domain,
			State: status[name].State, Access: st.Access(p.Name, name), Hosts: c.Discovery, Slots: c.Slots}
		if c.ListsPlaceholders {
			l.Placeholders = maps.Clone(c.placeholders)
		}
		if len(c.secrets) != 0 {
			l.Credentials = map[string]string{}
			for secret := range c.secrets {
				l.Credentials[secret], _ = describeCredential(doc.Credentials.Get(format.SecretID{Connection: name, Name: secret}))
			}
		}
		result.Connections = append(result.Connections, l)
	}
	return result
}

func (s *state) agentPolicy(p facts.Principal) (any, error) {
	st := s.settings.Load()
	var visible map[string]any
	var err error
	if st.capable(p, capabilityConfig) {
		visible, err = st.Config.View()
	} else {
		visible, err = st.Config.AgentView(p)
	}
	if err != nil {
		return nil, err
	}
	source, err := format.RenderTOML(visible)
	return map[string]any{"identity": p.Name, "source": source}, err
}
