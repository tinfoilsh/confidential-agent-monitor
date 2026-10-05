package main

import (
	"embed"
	"encoding/json/jsontext"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"sync"

	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/web"
)

//go:embed presets/*.json
var presetFiles embed.FS

// A preset is a reviewed service record shipped with the monitor, with the catalog entry that sets up its accounts.
// The catalog is setup metadata only; policy reads the record from data.presets.
type preset struct {
	service
	record  map[string]any
	catalog map[string]any
}

var presets = sync.OnceValues(func() (map[string]preset, error) {
	files, _ := fs.Glob(presetFiles, "presets/*.json")
	records, catalogs := map[string]any{}, map[string]map[string]any{}
	for _, file := range files {
		src, _ := presetFiles.ReadFile(file)
		// encoding/json keeps the last of repeated names, which could silently drop a condition.
		if !jsontext.Value(src).IsValid() {
			return nil, fmt.Errorf("%s is not valid JSON or repeats a name", file)
		}
		var p map[string]any
		if err := connector.DecodeNumbers(src, &p); err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		name := strings.TrimSuffix(path.Base(file), ".json")
		catalogs[name], _ = p["catalog"].(map[string]any)
		delete(p, "catalog")
		records[name] = p
	}
	services, err := parseServices(records)
	if err != nil {
		return nil, err
	}
	out := map[string]preset{}
	for name, s := range services {
		out[name] = preset{s, records[name].(map[string]any), catalogs[name]}
	}
	return out, nil
})

// apiService returns the record an api account names: an owner record in data.services or a preset.
// A record whose origin is tenantOrigin needs the account's own origin, and only such a record may have one.
func apiService(services map[string]service, o policyOptions) (service, error) {
	builtin, err := presets()
	if err != nil {
		return service{}, err
	}
	s, owned := services[o.Service]
	p, shipped := builtin[o.Preset]
	if owned == shipped || (owned && o.Preset != "") || (shipped && o.Service != "") {
		return service{}, fmt.Errorf("names neither exactly one record in data.services nor one preset")
	}
	if shipped {
		s = p.service
	}
	tenant := false
	for _, op := range s.Operations {
		tenant = tenant || op.Origin == tenantOrigin
	}
	if tenant != (o.Origin != "") || (tenant && !web.ValidOrigin(o.Origin)) {
		return service{}, fmt.Errorf("needs an https origin in policy_options.origin exactly when its record uses %s", tenantOrigin)
	}
	return s, nil
}
