package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// The index summarizes saved reports; check validates that they are current.
func writeCoverageIndex(sources map[string]source) error {
	var out strings.Builder
	out.WriteString("# Generated preset coverage\n\n")
	out.WriteString("These are candidate inventories for the configured sources and filters. They are not a claim of complete vendor API coverage or verified permissions. Run `check` to detect stale artifacts and `check --reviewed` to require resolution of recorded review gaps. See [the workflow](../README.md).\n\n")
	out.WriteString("A source variant is one operation and request encoding. Several source variants can map to one descriptor. Shipped definitions preserve existing contracts, including deliberate restrictions. Their presence does not establish an independent semantic review. Archived schemas only have historical request definitions. Parameter gaps count variants whose shipped definition omits documented query parameters.\n\n")
	out.WriteString("| Provider | Source variants | Descriptors | Needs review | Unsupported | Archived schemas | Parameter gaps | Overlaps | Source warnings |\n")
	out.WriteString("| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n")
	var missing []string
	totals := map[string]int{}
	generated := 0
	for _, name := range sortedKeys(sources) {
		if sources[name].Preset == "" {
			continue
		}
		r, err := load[generationReport](filepath.Join(coverageDir, name+".json"))
		if err != nil {
			missing = append(missing, fmt.Sprintf("- `%s`: report unavailable.\n", name))
			continue
		}
		if r.Error != "" {
			missing = append(missing, fmt.Sprintf("- [%s](%s.json): %s\n", name, name, r.Error))
			continue
		}
		generated++
		for key, count := range r.Counts {
			totals[key] += count
		}
		fmt.Fprintf(&out, "| [%s](%s.json) | %d | %d | %d | %d | %d | %d | %d | %d |\n", name, name, r.Counts["source_variants"], r.Counts["descriptors"], r.Counts["needs_review"], r.Counts["unsupported"], r.Counts["archived_schema"], r.Counts["parameter_gaps"], len(r.Conflicts), len(r.Warnings))
	}
	fmt.Fprintf(&out, "\n%d provider source groups produced %d descriptors from %d source variants. %d variants need semantic review; %d have unsupported requests; %d use archived schemas.\n", generated, totals["descriptors"], totals["source_variants"], totals["needs_review"], totals["unsupported"], totals["archived_schema"])
	if len(missing) > 0 {
		out.WriteString("\nMissing or failed inventories:\n\n")
		for _, item := range missing {
			out.WriteString(item)
		}
	}
	return os.WriteFile(filepath.Join(coverageDir, "README.md"), []byte(out.String()), 0o644)
}
