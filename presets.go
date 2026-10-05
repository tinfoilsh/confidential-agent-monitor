package main

import (
	"context"
	"embed"
	"encoding/json"
	"encoding/json/jsontext"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/open-policy-agent/opa/v1/storage/inmem"
	"github.com/tinfoilsh/monitor/connector"
)

//go:embed presets/*.json
var presetFiles embed.FS

// A preset is a reviewed service record, shipped with the monitor or the owner's, with the catalog entry that sets up its accounts.
// The catalog is setup metadata only; policy reads the record from data.presets.
type preset struct {
	record  map[string]any
	catalog map[string]any
}

// A preset reads {MONITOR_X} only if MONITOR_X_PRESETS lists its name.
var envRef = regexp.MustCompile(`\{(MONITOR_\w+)\}`)

var presets = sync.OnceValues(func() (map[string]preset, error) {
	files, _ := fs.Glob(presetFiles, "presets/*.json")
	shipped := map[string]map[string]any{}
	for _, file := range files {
		name := strings.TrimSuffix(path.Base(file), ".json")
		src, _ := presetFiles.ReadFile(file)
		src = withEnv(name, src)
		// encoding/json keeps the last of repeated names, which could silently drop a condition.
		if !jsontext.Value(src).IsValid() {
			return nil, fmt.Errorf("%s is not valid JSON or repeats a name", file)
		}
		var p map[string]any
		if err := connector.DecodeNumbers(src, &p); err != nil {
			return nil, fmt.Errorf("%s: %w", file, err)
		}
		shipped[name] = p
	}
	return checked(map[string]preset{}, shipped)
})

func withEnv(name string, src []byte) []byte {
	return envRef.ReplaceAllFunc(src, func(ref []byte) []byte {
		key := string(ref[1 : len(ref)-1])
		if !slices.Contains(strings.Split(os.Getenv(key+"_PRESETS"), ","), name) {
			return nil
		}
		quoted, _ := jsontext.AppendQuote(nil, os.Getenv(key))
		return quoted[1 : len(quoted)-1]
	})
}

// withOwned returns the shipped presets with the owner's in place of any of the same name.
// An owner's preset reads the environment as a shipped one of its name would.
func withOwned(owned map[string]map[string]any) (map[string]preset, error) {
	shipped, err := presets()
	if err != nil || len(owned) == 0 {
		return shipped, err
	}
	files := map[string]map[string]any{}
	for name, file := range owned {
		raw, _ := json.Marshal(file)
		var p map[string]any
		if err := connector.DecodeNumbers(withEnv(name, raw), &p); err != nil {
			return nil, fmt.Errorf("preset %s: %w", name, err)
		}
		files[name] = p
	}
	return checked(maps.Clone(shipped), files)
}

// checked adds presets in the file format to out, refusing a template's name or a malformed operation.
func checked(out map[string]preset, files map[string]map[string]any) (map[string]preset, error) {
	records := map[string]any{}
	for name, file := range files {
		catalog, ok := file["catalog"].(map[string]any)
		if _, err := fs.Stat(templates, templateDir+"/"+name+".rego"); name == "" || err == nil || !ok {
			return nil, fmt.Errorf("preset %q needs a catalog and a name no template has", name)
		}
		p := maps.Clone(file)
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
}
