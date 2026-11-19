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
	"net/url"
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/config"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/connections"
	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/format"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/catalog"
	"github.com/tinfoilsh/confidential-agent-monitor/core/sealedlog"
	"golang.org/x/sync/errgroup"
)

const (
	catalogPrefix     = "catalogs/"
	catalogFormat     = 1
	catalogTimeout    = 5 * time.Minute
	catalogFetchers   = 8
	maxCatalogIndex   = 1 << 20
	maxCatalogPreset  = 8 << 20
	maxCatalogPresets = 4096
)

var (
	catalogName   = regexp.MustCompile(`\A[a-z][a-z0-9_]*\z`)
	catalogDigest = regexp.MustCompile(`\A[0-9a-f]{64}\z`)
)

type library struct {
	presets  map[string]*catalog.Preset
	defaults map[string]json.RawMessage
}

// A pin is the SHA-256 of a source's index.json; the bundle stored under it holds every preset that index lists.
type catalogBundle struct {
	Digests map[string]string          `json:"digests"`
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
	Added    []string            `json:"added"`
	Changed  []string            `json:"changed"`
	Removed  []string            `json:"removed"`
	Services map[string][]string `json:"services"`
}

func digestOf(raw []byte) string { return fmt.Sprintf("%x", sha256.Sum256(raw)) }

func (s *state) readBundle(ctx context.Context, sealer sealedlog.Sealer, pin string) (b catalogBundle, err error) {
	if !catalogDigest.MatchString(pin) {
		return b, errors.New("pin must be a SHA-256 digest")
	}
	sealed, err := s.bucket.ReadAll(ctx, catalogPrefix+pin)
	if err != nil {
		return b, fmt.Errorf("pin %s is not stored; fetch the catalog again", pin)
	}
	plain, err := sealer.Open(pin, sealed)
	if err == nil {
		err = json.Unmarshal(plain, &b)
	}
	return b, err
}

func (s *state) loadLibrary(ctx context.Context, sealer sealedlog.Sealer, catalogs map[string]format.Catalog) (library, error) {
	lib := library{maps.Clone(presets), maps.Clone(presetDefaults)}
	for _, name := range slices.Sorted(maps.Keys(catalogs)) {
		bundle, err := s.readBundle(ctx, sealer, catalogs[name].Pin)
		loaded := map[string]*catalog.Preset{}
		for preset, raw := range bundle.Presets {
			if loaded[preset], err = catalog.Decode(raw); err != nil {
				err = fmt.Errorf("preset %s.json: %w", preset, err)
				break
			}
		}
		if err == nil {
			err = config.AddCatalog(name+"/", loaded, lib.presets, lib.defaults)
		}
		if err != nil {
			return lib, fmt.Errorf("catalog %s: %w", name, err)
		}
	}
	return lib, nil
}

func fetchLimited(ctx context.Context, client *http.Client, from string, limit int) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, from, nil)
	if err != nil {
		return nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, int64(limit)+1))
	switch {
	case err != nil:
		return nil, err
	case res.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%s: %s", from, res.Status)
	case len(raw) > limit:
		return nil, fmt.Errorf("%s is larger than %d bytes", from, limit)
	}
	return raw, nil
}

// Presets the previous pin already holds under the same digest are not downloaded again.
func (s *state) fetchCatalog(ctx context.Context, client *http.Client, sealer sealedlog.Sealer, source string, previous catalogBundle) (string, catalogBundle, error) {
	bundle := catalogBundle{Presets: map[string]json.RawMessage{}}
	index, err := url.Parse(source)
	if err != nil || index.Host == "" || (index.Scheme != "https" && !development) {
		return "", bundle, errors.New("a catalog source is the https URL of its index.json")
	}
	raw, err := fetchLimited(ctx, client, source, maxCatalogIndex)
	if err != nil {
		return "", bundle, err
	}
	var listed struct {
		Format  int               `json:"format"`
		Presets map[string]string `json:"presets"`
	}
	if err := json.Unmarshal(raw, &listed); err != nil {
		return "", bundle, fmt.Errorf("%s: %w", source, err)
	}
	if listed.Format != catalogFormat {
		return "", bundle, fmt.Errorf("catalog format %d needs another Perimeter version; this one reads format %d", listed.Format, catalogFormat)
	}
	if len(listed.Presets) > maxCatalogPresets {
		return "", bundle, fmt.Errorf("a catalog holds at most %d presets", maxCatalogPresets)
	}
	pin := digestOf(raw)
	bundle.Digests = listed.Presets
	var mu sync.Mutex
	group, fetching := errgroup.WithContext(ctx)
	group.SetLimit(catalogFetchers)
	for name, digest := range listed.Presets {
		if !catalogName.MatchString(name) || !catalogDigest.MatchString(digest) {
			return "", bundle, fmt.Errorf("catalog entry %q must be a lowercase name with a SHA-256 digest", name)
		}
		if previous.Digests[name] == digest {
			bundle.Presets[name] = previous.Presets[name]
			continue
		}
		group.Go(func() error {
			from := index.ResolveReference(&url.URL{Path: name + ".json"}).String()
			preset, err := fetchLimited(fetching, client, from, maxCatalogPreset)
			if err == nil && digestOf(preset) != digest {
				err = fmt.Errorf("%s does not match the digest in the index", from)
			}
			mu.Lock()
			defer mu.Unlock()
			bundle.Presets[name] = preset
			return err
		})
	}
	if err := group.Wait(); err != nil {
		return "", bundle, err
	}
	plain, err := json.Marshal(bundle)
	if err == nil {
		err = s.bucket.WriteAll(ctx, catalogPrefix+pin, sealer.Seal(pin, plain), nil)
	}
	return pin, bundle, err
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
	var previous catalogBundle
	if pinned, ok := doc.Catalogs[name]; ok {
		var err error
		if previous, err = s.readBundle(ctx, sealer, pinned.Pin); err != nil {
			return nil, err
		}
	}
	pin, bundle, err := s.fetchCatalog(ctx, st.client(), sealer, in.URL, previous)
	if err != nil {
		return nil, err
	}
	review := catalogReview{Pin: pin, Presets: len(bundle.Presets), Added: []string{}, Changed: []string{}, Removed: []string{}, Services: map[string][]string{}}
	for preset, digest := range bundle.Digests {
		if old, had := previous.Digests[preset]; !had {
			review.Added = append(review.Added, preset)
		} else if old != digest {
			review.Changed = append(review.Changed, preset)
		}
	}
	for preset := range previous.Digests {
		if _, kept := bundle.Digests[preset]; !kept {
			review.Removed = append(review.Removed, preset)
		}
	}
	slices.Sort(review.Added)
	slices.Sort(review.Changed)
	slices.Sort(review.Removed)

	catalogs := maps.Clone(doc.Catalogs)
	if catalogs == nil {
		catalogs = map[string]format.Catalog{}
	}
	catalogs[name] = format.Catalog{URL: in.URL, Pin: pin}
	lib, err := s.loadLibrary(ctx, sealer, catalogs)
	if err != nil {
		return nil, err
	}
	cfg, err := config.Load(doc.Policy, lib.presets)
	if err != nil {
		return nil, err
	}
	for service, c := range cfg.Connections {
		before := st.connections[service]
		if before == nil || !strings.HasPrefix(c.Preset, name+"/") {
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
	if in.URL == "" {
		delete(catalogs, name)
	} else {
		catalogs[name] = format.Catalog{URL: in.URL, Pin: in.Pin}
	}
	lib, err := s.loadLibrary(ctx, sealer, catalogs)
	if err == nil {
		err = s.writeSettings(ctx, settingsWrite{lib: &lib, catalogs: catalogs, check: reviewed(&in.Revision)})
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
