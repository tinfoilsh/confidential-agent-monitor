package main

import (
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
	"time"

	"github.com/tinfoilsh/confidential-agent-monitor/cmd/perimeter/config"
	"github.com/tinfoilsh/confidential-agent-monitor/connector/catalog"
	"github.com/tinfoilsh/confidential-agent-monitor/core/sealedlog"
	"github.com/tinfoilsh/confidential-agent-monitor/core/transport/netx"
)

const (
	catalogPrefix   = "catalogs/"
	catalogTimeout  = 5 * time.Minute
	maxCatalogBytes = 64 << 20

	// The Catalog workflow publishes connector/catalog/presets under its SHA-256.
	tinfoilCatalogPin = "c29f5b4cab294ce2ebe9a882d720d72f8d10d8e48ca4368d6439eedcc25524e0"
	tinfoilCatalogs   = "https://github.com/tinfoilsh/confidential-agent-monitor/releases/download/catalog/"
)

var (
	presetName    = regexp.MustCompile(`\A[a-z][a-z0-9_]*\z`)
	catalogDigest = regexp.MustCompile(`\A[0-9a-f]{64}\z`)
)

// No credential travels with the request, so redirects are followed.
func fetchCatalog(ctx context.Context, allowed []netip.Prefix, source string) ([]byte, error) {
	if u, err := url.Parse(source); err != nil || u.Host == "" || (u.Scheme != "https" && !development) {
		return nil, errors.New("a catalog is fetched from the https URL of its file")
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return nil, err
	}
	res, err := (&http.Client{Transport: netx.Transport(guardedDialer(allowed, "tcp").DialContext)}).Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(res.Body, maxCatalogBytes+1))
	switch {
	case err != nil:
		return nil, err
	case res.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%s: %s", source, res.Status)
	case len(raw) > maxCatalogBytes:
		return nil, fmt.Errorf("%s is larger than %d bytes", source, maxCatalogBytes)
	}
	return raw, nil
}

// A catalog is one file of presets by name; once fetched it is kept under its SHA-256.
func (s *state) readCatalog(ctx context.Context, sealer sealedlog.Sealer, allowed []netip.Prefix, pin, source string) ([]byte, error) {
	if !catalogDigest.MatchString(pin) {
		return nil, errors.New("a catalog is listed under its SHA-256 digest")
	}
	if sealed, err := s.bucket.ReadAll(ctx, catalogPrefix+pin); err == nil {
		return sealer.Open(pin, sealed)
	}
	raw, err := fetchCatalog(ctx, allowed, source)
	if err == nil && fmt.Sprintf("%x", sha256.Sum256(raw)) != pin {
		err = fmt.Errorf("%s does not have this digest", source)
	}
	if err == nil {
		err = s.bucket.WriteAll(ctx, catalogPrefix+pin, sealer.Seal(pin, raw), nil)
	}
	return raw, err
}

// A policy that lists no catalogs uses the one this build pins.
func (s *state) library(ctx context.Context, sealer sealedlog.Sealer) config.Library {
	return func(cfg *config.Config) (map[string]*catalog.Preset, error) {
		if st := s.settings.Load(); st != nil && maps.Equal(st.Catalogs, cfg.Catalogs) {
			return st.Presets, nil
		}
		sources := cfg.Catalogs
		if len(sources) == 0 {
			sources = map[string]string{tinfoilCatalogPin: tinfoilCatalogs + tinfoilCatalogPin + ".json"}
		}
		ctx, cancel := context.WithTimeout(ctx, catalogTimeout)
		defer cancel()
		presets := map[string]*catalog.Preset{}
		for pin, source := range sources {
			raw, err := s.readCatalog(ctx, sealer, cfg.AllowNetworks, pin, source)
			var file map[string]json.RawMessage
			if err == nil {
				err = json.Unmarshal(raw, &file)
			}
			for name, preset := range file {
				if presets[name] != nil || !presetName.MatchString(name) {
					err = errors.New("a name is lowercase letters, digits and underscores, and belongs to one catalog")
				} else {
					presets[name], err = catalog.Decode(preset)
				}
				if err != nil {
					err = fmt.Errorf("preset %s: %w", name, err)
					break
				}
			}
			if err != nil {
				return nil, fmt.Errorf("catalog %s: %w", pin, err)
			}
		}
		return presets, config.Compose(presets)
	}
}
