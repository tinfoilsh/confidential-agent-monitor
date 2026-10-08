package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"time"
)

// check verifies inventory accounting and reproducibility. --reviewed also
// requires all operations to have shipped definitions and no recorded gaps.
func check(only []string, reviewed bool, maxAge time.Duration) error {
	sources, err := load[map[string]source](sourcesPath)
	if err != nil {
		return err
	}
	lock, err := load[lockFile](lockPath)
	if err != nil {
		return err
	}
	for _, name := range only {
		found := false
		for key, src := range sources {
			if key == name || slices.Contains(strings.Split(src.Preset, ","), name) {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("unknown service %q", name)
		}
	}
	digest, err := generatorDigest()
	if err != nil {
		return err
	}
	var failed []error
	selected := 0
	for _, name := range sortedKeys(sources) {
		src := sources[name]
		if src.Preset == "" {
			continue
		}
		if len(only) > 0 && !slices.Contains(only, name) && !slices.ContainsFunc(strings.Split(src.Preset, ","), func(p string) bool { return slices.Contains(only, p) }) {
			continue
		}
		selected++
		r, err := load[generationReport](filepath.Join(coverageDir, name+".json"))
		if err != nil {
			failed = append(failed, fmt.Errorf("%s: %w", name, err))
			continue
		}
		if err = checkReport(r, src, lock[name], digest, reviewed); err != nil {
			failed = append(failed, fmt.Errorf("%s: %w", name, err))
		} else if err = checkFreshness(lock[name], maxAge, time.Now()); err != nil {
			failed = append(failed, fmt.Errorf("%s: %w", name, err))
		} else {
			fmt.Printf("%s: inventory accounted for; %d source variants, %d descriptors\n", name, len(r.Operations), r.Counts["descriptors"])
		}
	}
	if selected == 0 {
		return fmt.Errorf("no configured shipped providers selected")
	}
	return errors.Join(failed...)
}

func checkReport(r generationReport, src source, locked []lockEntry, digest string, reviewed bool) error {
	if r.Error != "" {
		return errors.New(r.Error)
	}
	if !reflect.DeepEqual(r.Definition, src) {
		return fmt.Errorf("source definition changed; regenerate candidates")
	}
	if r.GeneratorSHA256 != digest {
		return fmt.Errorf("generator changed; regenerate candidates")
	}
	if !reflect.DeepEqual(r.Sources, locked) {
		return fmt.Errorf("source lock changed; regenerate candidates")
	}
	overrideHash, err := shippedDigest(strings.Split(src.Preset, ","))
	if err != nil {
		return err
	}
	if overrideHash != r.ShippedSHA256 {
		return fmt.Errorf("shipped presets changed; regenerate candidates")
	}
	p, err := load[map[string]any](filepath.Join(candidatesDir, r.Service+".json"))
	if err != nil {
		return err
	}
	b, _ := json.Marshal(p)
	sum := sha256.Sum256(b)
	if hex.EncodeToString(sum[:]) != r.CandidateSHA256 {
		return fmt.Errorf("candidate changed without a matching coverage report")
	}
	ops, ok := p["operations"].([]any)
	if !ok {
		return fmt.Errorf("candidate operations is not an array")
	}
	ids := map[string]bool{}
	for _, raw := range ops {
		op, ok := raw.(map[string]any)
		if !ok {
			return fmt.Errorf("candidate operation is not an object")
		}
		id, _ := op["id"].(string)
		if id == "" || ids[id] {
			return fmt.Errorf("missing or repeated descriptor id %q", id)
		}
		ids[id] = true
	}
	if len(r.Operations) == 0 {
		return fmt.Errorf("source inventory is empty")
	}
	counts := map[string]int{}
	for _, op := range r.Operations {
		if op.ID == "" || op.Source.URL == "" || op.Source.SHA256 == "" {
			return fmt.Errorf("operation lacks stable identity or provenance")
		}
		switch op.Status {
		case "shipped_override", "needs_review", "archived_schema":
			if len(op.Descriptors) == 0 {
				return fmt.Errorf("%s has no descriptor mapping", op.ID)
			}
		case "unsupported":
			if op.Reason == "" {
				return fmt.Errorf("%s has no explanation for missing support", op.ID)
			}
		default:
			return fmt.Errorf("%s has unknown status %q", op.ID, op.Status)
		}
		for _, id := range op.Descriptors {
			if !ids[id] {
				return fmt.Errorf("%s refers to missing descriptor %s", op.ID, id)
			}
		}
		counts[op.Status]++
		if len(op.MissingParams) > 0 {
			counts["parameter_gaps"]++
		}
	}
	for _, status := range []string{"shipped_override", "needs_review", "unsupported", "archived_schema", "parameter_gaps"} {
		if r.Counts[status] != counts[status] {
			return fmt.Errorf("incorrect %s count", status)
		}
	}
	if r.Counts["conflicts"] != len(r.Conflicts) {
		return fmt.Errorf("incorrect conflict count")
	}
	if r.Counts["unmapped_shipped"] != len(r.UnmappedShipped) {
		return fmt.Errorf("incorrect unmapped shipped count")
	}
	for _, id := range r.UnmappedShipped {
		if !ids[id] {
			return fmt.Errorf("unmapped shipped descriptor %s is missing", id)
		}
	}
	for _, pair := range r.Conflicts {
		if !ids[pair[0]] || !ids[pair[1]] || pair[0] == pair[1] {
			return fmt.Errorf("invalid conflict mapping %v", pair)
		}
	}
	if r.Counts["source_variants"] != len(r.Operations) || r.Counts["descriptors"] != len(ops) {
		return fmt.Errorf("incorrect inventory totals")
	}
	if reviewed && (counts["needs_review"]+counts["unsupported"]+counts["archived_schema"]+r.Counts["parameter_gaps"] > 0 || len(r.Conflicts) > 0 || len(r.Warnings) > 0) {
		return fmt.Errorf("incomplete: %d need semantic review, %d unsupported, %d archived schemas, %d parameter gaps, %d conflicts, %d source warnings", counts["needs_review"], counts["unsupported"], counts["archived_schema"], r.Counts["parameter_gaps"], len(r.Conflicts), len(r.Warnings))
	}
	return nil
}

func checkFreshness(locked []lockEntry, maxAge time.Duration, now time.Time) error {
	if maxAge == 0 {
		return nil
	}
	for _, e := range locked {
		checked, err := time.Parse(time.RFC3339, e.CheckedAt)
		if err != nil {
			return fmt.Errorf("source %s has no valid checked_at; refresh it", e.Source)
		}
		if checked.After(now.Add(5*time.Minute)) || now.Sub(checked) > maxAge {
			return fmt.Errorf("source %s last checked %s, outside freshness limit %s", e.Source, e.CheckedAt, maxAge)
		}
	}
	return nil
}
