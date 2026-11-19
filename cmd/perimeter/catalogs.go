package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/config"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/connections"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/format"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/catalog"
	"github.com/tinfoilsh/confidential-agent-monitor/core/sealedlog"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/netx"
)

const (
	catalogPrefix   = "catalogs/"
	catalogFormat   = 1
	catalogTimeout  = 5 * time.Minute
	maxCatalogBytes = 64 << 20

	// The Catalog workflow publishes connector/catalog/presets under its SHA-256 and as the latest version.
	tinfoilCatalog       = "tinfoil"
	tinfoilCatalogPin    = "be4acddc64188226ab1eb5163ee40071a2d9a2f068f5ce0704f3e0b44ada91da"
	tinfoilCatalogs      = "https://github.com/tinfoilsh/confidential-agent-monitor/releases/download/catalog/"
	tinfoilCatalogLatest = tinfoilCatalogs + "catalog.json"
)

var (
	catalogName   = regexp.MustCompile(`\A[a-z][a-z0-9_]*\z`)
	catalogDigest = regexp.MustCompile(`\A[0-9a-f]{64}\z`)
)

type library map[string]*catalog.Preset

// A catalog is one file holding every preset; its pin is that file's SHA-256.
type catalogFile struct {
	Format  int                        `json:"format"`
	Presets map[string]json.RawMessage `json:"presets"`
}

type catalogInput struct {
	URL      string `json:"url"`
	Pin      string `json:"pin"`
	Revision uint64 `json:"revision"`
}

type catalogReview struct {
	Pin      string              `json:"pin"`
	Presets  int                 `json:"presets"`
	Services map[string][]string `json:"services"`
}

// No credential travels with the request, so redirects are followed.
func fetchCatalog(ctx context.Context, allowed []netip.Prefix, source string) (pin string, raw []byte, err error) {
	if u, err := url.Parse(source); err != nil || u.Host == "" || (u.Scheme != "https" && !development) {
		return "", nil, errors.New("a catalog source is the https URL of its catalog file")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return "", nil, err
	}
	res, err := (&http.Client{Transport: netx.Transport(guardedDialer(allowed, "tcp").DialContext)}).Do(req)
	if err != nil {
		return "", nil, err
	}
	defer res.Body.Close()
	raw, err = io.ReadAll(io.LimitReader(res.Body, maxCatalogBytes+1))
	switch {
	case err != nil:
		return "", nil, err
	case res.StatusCode != http.StatusOK:
		return "", nil, fmt.Errorf("%s: %s", source, res.Status)
	case len(raw) > maxCatalogBytes:
		return "", nil, fmt.Errorf("%s is larger than %d bytes", source, maxCatalogBytes)
	}
	return fmt.Sprintf("%x", sha256.Sum256(raw)), raw, nil
}

func decodeCatalog(raw []byte) (map[string]*catalog.Preset, error) {
	var file catalogFile
	if err := json.Unmarshal(raw, &file); err != nil {
		return nil, err
	}
	if file.Format != catalogFormat {
		return nil, fmt.Errorf("catalog format %d needs another Perimeter version; this one reads format %d", file.Format, catalogFormat)
	}
	loaded := map[string]*catalog.Preset{}
	for name, preset := range file.Presets {
		if !catalogName.MatchString(name) {
			return nil, fmt.Errorf("preset name %q must be lowercase letters, digits and underscores", name)
		}
		var err error
		if loaded[name], err = catalog.Decode(preset); err != nil {
			return nil, fmt.Errorf("preset %s: %w", name, err)
		}
	}
	return loaded, nil
}

func (s *state) readCatalog(ctx context.Context, sealer sealedlog.Sealer, pin string) (map[string]*catalog.Preset, error) {
	if !catalogDigest.MatchString(pin) {
		return nil, errors.New("pin must be a SHA-256 digest")
	}
	sealed, err := s.bucket.ReadAll(ctx, catalogPrefix+pin)
	if err != nil {
		return nil, fmt.Errorf("pin %s is not stored; fetch the catalog again", pin)
	}
	raw, err := sealer.Open(pin, sealed)
	if err != nil {
		return nil, err
	}
	return decodeCatalog(raw)
}

func presetPrefix(source string) string {
	if source == tinfoilCatalog {
		return ""
	}
	return source + "/"
}

// A state without Tinfoil's catalog starts at the version this build pins; the owner reviews later ones like any other source's.
func (s *state) pinTinfoilCatalog(ctx context.Context, sealer sealedlog.Sealer, doc *format.Document) error {
	if _, pinned := doc.Catalogs[tinfoilCatalog]; pinned {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, catalogTimeout)
	defer cancel()
	pin, raw, err := fetchCatalog(ctx, nil, tinfoilCatalogs+tinfoilCatalogPin+".json")
	if err == nil && pin != tinfoilCatalogPin {
		err = errors.New("the published file does not match the digest this build pins")
	}
	if err == nil {
		err = s.bucket.WriteAll(ctx, catalogPrefix+pin, sealer.Seal(pin, raw), nil)
	}
	if err != nil {
		return fmt.Errorf("the Tinfoil catalog: %w", err)
	}
	if doc.Catalogs == nil {
		doc.Catalogs = map[string]format.Catalog{}
	}
	doc.Catalogs[tinfoilCatalog] = format.Catalog{URL: tinfoilCatalogLatest, Pin: pin}
	return nil
}

func (s *state) loadLibrary(ctx context.Context, sealer sealedlog.Sealer, catalogs map[string]format.Catalog) (library, error) {
	lib := library{}
	for _, name := range slices.Sorted(maps.Keys(catalogs)) {
		loaded, err := s.readCatalog(ctx, sealer, catalogs[name].Pin)
		if err == nil {
			err = config.AddCatalog(presetPrefix(name), loaded, lib)
		}
		if err != nil {
			return nil, fmt.Errorf("catalog %s: %w", name, err)
		}
	}
	return lib, nil
}

func credentialSlots(set any) (list []string) {
	raw, _ := json.Marshal(set)
	var each []json.RawMessage
	json.Unmarshal(raw, &each)
	for _, slot := range each {
		list = append(list, string(slot))
	}
	return list
}

func missing(label string, from, in []string) (changes []string) {
	for _, item := range from {
		if !slices.Contains(in, item) {
			changes = append(changes, label+item)
		}
	}
	return changes
}

func setupChanges(before, after *connections.Setup) []string {
	was, now := credentialSlots(before.Slots), credentialSlots(after.Slots)
	changes := slices.Concat(missing("+ host ", after.Hosts, before.Hosts), missing("- host ", before.Hosts, after.Hosts),
		missing("+ credential ", now, was), missing("- credential ", was, now))
	for id, op := range after.Operations {
		old, had := before.Operations[id]
		effects := strings.Join(op.Effects, ", ")
		if !had {
			changes = append(changes, fmt.Sprintf("+ %s: %s", id, effects))
		} else if old.Action != op.Action || !slices.Equal(old.Effects, op.Effects) {
			changes = append(changes, fmt.Sprintf("~ %s: %s, was %s", id, effects, strings.Join(old.Effects, ", ")))
		}
	}
	for id := range before.Operations {
		if _, kept := after.Operations[id]; !kept {
			changes = append(changes, "- "+id)
		}
	}
	if len(changes) == 0 && !bytes.Equal(before.Definition, after.Definition) {
		changes = append(changes, "~ how requests are recognized")
	}
	slices.Sort(changes)
	return changes
}

func (s *state) reviewCatalog(r *http.Request, in catalogInput) (any, error) {
	name := r.PathValue("name")
	if !catalogName.MatchString(name) {
		return nil, errors.New("a catalog name is lowercase letters, digits and underscores")
	}
	ctx, cancel := context.WithTimeout(r.Context(), catalogTimeout)
	defer cancel()
	var doc format.Document
	var sealer sealedlog.Sealer
	s.locked(func(h held) { doc, sealer = h.doc, h.sealer })
	st := s.settings.Load()
	pin, raw, err := fetchCatalog(ctx, st.AllowNetworks, in.URL)
	var loaded map[string]*catalog.Preset
	if err == nil {
		loaded, err = decodeCatalog(raw)
	}
	if err == nil {
		err = s.bucket.WriteAll(ctx, catalogPrefix+pin, sealer.Seal(pin, raw), nil)
	}
	if err != nil {
		return nil, err
	}
	catalogs := maps.Clone(doc.Catalogs)
	if catalogs == nil {
		catalogs = map[string]format.Catalog{}
	}
	catalogs[name] = format.Catalog{URL: in.URL, Pin: pin}
	lib, err := s.loadLibrary(ctx, sealer, catalogs)
	if err != nil {
		return nil, err
	}
	review := catalogReview{Pin: pin, Presets: len(loaded), Services: map[string][]string{}}
	cfg, err := config.Load(doc.Policy, lib)
	if err != nil {
		return nil, err
	}
	for service, c := range cfg.Connections {
		before := st.connections[service]
		if before == nil || !strings.HasPrefix(c.Preset, presetPrefix(name)) {
			continue
		}
		spec, err := cfg.Spec(service)
		var after *connections.Setup
		if err == nil {
			after, err = connections.Parse(spec)
		}
		if err != nil {
			return nil, fmt.Errorf("service %s: %w", service, err)
		}
		if changes := setupChanges(before.Setup, after); len(changes) != 0 {
			review.Services[service] = changes
		}
	}
	return review, nil
}

func (s *state) pinCatalog(ctx context.Context, name string, in catalogInput) error {
	if !catalogName.MatchString(name) {
		return errors.New("a catalog name is lowercase letters, digits and underscores")
	}
	var doc format.Document
	var sealer sealedlog.Sealer
	s.locked(func(h held) { doc, sealer = h.doc, h.sealer })
	catalogs := maps.Clone(doc.Catalogs)
	if catalogs == nil {
		catalogs = map[string]format.Catalog{}
	}
	if in.URL == "" && name == tinfoilCatalog {
		return errors.New("the Tinfoil catalog cannot be removed")
	}
	if in.URL == "" {
		delete(catalogs, name)
	} else {
		catalogs[name] = format.Catalog{URL: in.URL, Pin: in.Pin}
	}
	lib, err := s.loadLibrary(ctx, sealer, catalogs)
	if err == nil {
		err = s.writeSettings(ctx, settingsWrite{lib: lib, catalogs: catalogs, check: reviewed(&in.Revision)})
	}
	s.locked(func(h held) { h.recordAdmin(ctx, "Set catalog "+name, catalogs[name], err) })
	if err != nil {
		return err
	}
	pinned := map[string]bool{}
	for _, c := range catalogs {
		pinned[catalogPrefix+c.Pin] = true
	}
	stored, _ := format.Storage(s.bucket).List(ctx, catalogPrefix, "")
	for _, key := range stored {
		if !pinned[key] {
			s.bucket.Delete(ctx, key)
		}
	}
	return nil
}
