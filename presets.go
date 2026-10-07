package main

import (
	"context"
	"embed"
	"encoding/json"
	"encoding/json/jsontext"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"maps"
	"os"
	"path"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/open-policy-agent/opa/v1/rego"
	"github.com/tinfoilsh/monitor/connector"
)

//go:embed presets/*.json
var presetFiles embed.FS

// A preset is a reviewed service record, shipped with the monitor or the owner's, with the catalog entry that sets up its accounts.
// Policy reads the full record, including action effects in its catalog, from data.presets.
type preset struct {
	record  map[string]any
	catalog map[string]any
}

// A preset reads {MONITOR_X} only if MONITOR_X_PRESETS lists its name.
var envRef = regexp.MustCompile(`\{(MONITOR_\w+)\}`)

// draftFiles holds unreviewed presets a dev monitor loads from disk with -drafts; they are never embedded.
var draftFiles fs.FS

var presets = sync.OnceValues(func() (map[string]preset, error) {
	files, _ := fs.Glob(presetFiles, "presets/*.json")
	shipped := map[string]map[string]any{}
	for _, file := range files {
		name, p, err := presetFile(presetFiles, file)
		if err != nil {
			return nil, err
		}
		shipped[name] = p
	}
	out, err := checked(map[string]preset{}, shipped)
	if err != nil || draftFiles == nil {
		return out, err
	}
	// Each draft is checked alone, so a malformed one is skipped rather than stopping the monitor.
	drafts, _ := fs.Glob(draftFiles, "*.json")
	for _, file := range drafts {
		name, p, err := presetFile(draftFiles, file)
		if _, ok := out[name]; ok && err == nil {
			err = errors.New("a shipped preset has this name")
		}
		if err == nil {
			var next map[string]preset
			if next, err = checked(maps.Clone(out), map[string]map[string]any{name: p}); err == nil {
				out = next
				continue
			}
		}
		log.Printf("draft %s: %v", file, err)
	}
	return out, nil
})

func presetFile(fsys fs.FS, file string) (string, map[string]any, error) {
	name := strings.TrimSuffix(path.Base(file), ".json")
	src, err := fs.ReadFile(fsys, file)
	if err != nil {
		return "", nil, err
	}
	src = withEnv(name, src)
	// encoding/json keeps the last of repeated names, which could silently drop a condition.
	if !jsontext.Value(src).IsValid() {
		return "", nil, fmt.Errorf("%s is not valid JSON or repeats a name", file)
	}
	var p map[string]any
	if err := connector.DecodeNumbers(src, &p); err != nil {
		return "", nil, fmt.Errorf("%s: %w", file, err)
	}
	return name, p, nil
}

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

var malformedQuery = sync.OnceValues(func() (rego.PreparedEvalQuery, error) {
	return rego.New(append(policyModules(), rego.Query("data.monitor.api.malformed with data.presets as input"))...).PrepareForEval(context.Background())
})

// checked adds complete preset records, validating their action effects and operations.
func checked(out map[string]preset, files map[string]map[string]any) (map[string]preset, error) {
	records := map[string]any{}
	for name, file := range files {
		catalog, ok := file["catalog"].(map[string]any)
		if name == "" || !ok {
			return nil, fmt.Errorf("preset %q needs a catalog and a name", name)
		}
		p := maps.Clone(file)
		out[name], records[name] = preset{p, catalog}, p
	}
	query, err := malformedQuery()
	if err != nil {
		return nil, err
	}
	rs, err := query.Eval(context.Background(), rego.EvalInput(records))
	if err != nil {
		return nil, err
	}
	if bad := rs[0].Expressions[0].Value.([]any); len(bad) > 0 {
		return nil, fmt.Errorf("malformed preset operations: %v", bad)
	}
	return out, nil
}
