package main

import (
	"context"
	"embed"
	"encoding/json/jsontext"
	"fmt"
	"io/fs"
	"path"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/tinfoilsh/monitor/connector"
)

//go:embed presets/*.json
var presetFiles embed.FS

// A preset is a reviewed service record shipped with the monitor, with the catalog entry that sets up its accounts.
// The catalog is setup metadata only; policy reads the record from data.presets.
type preset struct {
	record  map[string]any
	catalog map[string]any
}

var presets = sync.OnceValues(func() (map[string]preset, error) {
	files, _ := fs.Glob(presetFiles, "presets/*.json")
	out, records := map[string]preset{}, map[string]any{}
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
		catalog, _ := p["catalog"].(map[string]any)
		delete(p, "catalog")
		out[name], records[name] = preset{p, catalog}, p
	}
	store := inmem.NewFromObject(map[string]any{"presets": records})
	rs, err := rego.New(append(templateModules(), rego.Query("data.templates.api.malformed"), rego.Store(store))...).Eval(context.Background())
	if err != nil {
		return nil, err
	}
	if bad := rs[0].Expressions[0].Value.([]any); len(bad) > 0 {
		return nil, fmt.Errorf("malformed preset operations: %v", bad)
	}
	return out, nil
})
