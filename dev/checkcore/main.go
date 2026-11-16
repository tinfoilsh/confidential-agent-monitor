package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

type report struct {
	Root  string `json:"root"`
	Scope string `json:"scope"`
	inventory
	Compiled map[string][]string `json:"compiled_dependencies"`
	Base     string              `json:"base,omitempty"`
	Changes  *changes            `json:"changes,omitempty"`
}

type changes struct {
	Lines   map[string]int `json:"line_delta"`
	Added   []string       `json:"added_packages"`
	Removed []string       `json:"removed_packages"`
	Edges   difference     `json:"dependencies"`
	Exports difference     `json:"exports"`
	Globals difference     `json:"globals"`
}

type difference struct {
	Added   []string `json:"added"`
	Removed []string `json:"removed"`
}

func ignored(name string) bool {
	for _, part := range strings.Split(filepath.ToSlash(name), "/") {
		if slices.Contains([]string{".git", ".dev", "node_modules", "vendor", "dist", "dist-hosted", "dist-static"}, part) {
			return true
		}
	}
	return false
}

func sourceFile(name string) bool {
	return !ignored(name) && (strings.HasSuffix(name, ".go") || strings.HasSuffix(name, ".rego") || filepath.Base(name) == "go.mod")
}

func git(root string, args ...string) ([]byte, error) {
	cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
	data, err := cmd.Output()
	if failure := new(exec.ExitError); errors.As(err, &failure) {
		return nil, fmt.Errorf("git %s: %s", args[0], strings.TrimSpace(string(failure.Stderr)))
	}
	return data, err
}

func readSources(root string, tracked bool, revision string) (map[string][]byte, error) {
	var names []string
	if tracked || revision != "" {
		args := []string{"ls-files", "-z"}
		if revision != "" {
			args = []string{"ls-tree", "-r", "--name-only", "-z", revision}
		}
		raw, err := git(root, args...)
		if err != nil {
			return nil, err
		}
		names = strings.Split(strings.TrimSuffix(string(raw), "\x00"), "\x00")
	} else {
		err := filepath.WalkDir(root, func(name string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			relative, err := filepath.Rel(root, name)
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if ignored(relative) {
					return filepath.SkipDir
				}
			} else {
				names = append(names, filepath.ToSlash(relative))
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	files := map[string][]byte{}
	for _, name := range names {
		if !sourceFile(name) {
			continue
		}
		var data []byte
		var err error
		if revision != "" {
			data, err = git(root, "show", revision+":"+name)
		} else {
			data, err = os.ReadFile(filepath.Join(root, filepath.FromSlash(name)))
			if tracked && errors.Is(err, fs.ErrNotExist) {
				continue
			}
		}
		if err != nil {
			return nil, err
		}
		files[name] = data
	}
	return files, nil
}

func diff(before, after []string) difference {
	d := difference{}
	for _, item := range after {
		if !slices.Contains(before, item) {
			d.Added = append(d.Added, item)
		}
	}
	for _, item := range before {
		if !slices.Contains(after, item) {
			d.Removed = append(d.Removed, item)
		}
	}
	d.Added, d.Removed = unique(d.Added), unique(d.Removed)
	return d
}

func symbols(in inventory, selectValues func(*packageInfo) []string) []string {
	var values []string
	for name, p := range in.Packages {
		for _, value := range selectValues(p) {
			values = append(values, name+" -> "+value)
		}
	}
	return unique(values)
}

func compare(before, after inventory) *changes {
	packages := diff(slices.Collect(maps.Keys(before.Packages)), slices.Collect(maps.Keys(after.Packages)))
	c := &changes{Lines: map[string]int{}, Added: packages.Added, Removed: packages.Removed}
	for metric, total := range after.Totals {
		c.Lines[metric] = total - before.Totals[metric]
	}
	c.Edges = diff(symbols(before, func(p *packageInfo) []string { return p.Imports }), symbols(after, func(p *packageInfo) []string { return p.Imports }))
	c.Exports = diff(symbols(before, func(p *packageInfo) []string { return p.Exports }), symbols(after, func(p *packageInfo) []string { return p.Exports }))
	c.Globals = diff(symbols(before, func(p *packageInfo) []string { return p.Globals }), symbols(after, func(p *packageInfo) []string { return p.Globals }))
	return c
}

func run(root string, tracked bool, base string) (report, error) {
	root, err := filepath.Abs(root)
	if err == nil {
		root, err = filepath.EvalSymlinks(root)
	}
	if err != nil {
		return report{}, err
	}
	files, err := readSources(root, tracked, "")
	if err != nil {
		return report{}, err
	}
	r := report{Root: root, Scope: "filesystem including ignored source", inventory: inspect(files, packages)}
	if tracked {
		r.Scope = "tracked source"
	}
	r.Violations = append(r.Violations, validateRules(packages)...)
	var compiledErrors []string
	r.Compiled, compiledErrors = checkCompiled(root, r.Modules, packages)
	r.Violations = unique(append(r.Violations, compiledErrors...))
	if base != "" {
		sha, err := git(root, "rev-parse", "--verify", "--end-of-options", base+"^{commit}")
		if err != nil {
			return report{}, err
		}
		r.Base = strings.TrimSpace(string(sha))
		files, err := readSources(root, false, r.Base)
		if err != nil {
			return report{}, err
		}
		previous := inspect(files, nil)
		if len(previous.Violations) != 0 {
			return report{}, fmt.Errorf("cannot measure base %s: %s", r.Base, strings.Join(previous.Violations, "; "))
		}
		r.Changes = compare(previous, r.inventory)
	}
	return r, nil
}

func printReport(r report) {
	fmt.Printf("%s (%s)\n", r.Root, r.Scope)
	for _, metric := range []string{"production_runtime_go", "core", "protocols", "application", "tooling", "tests", "generated_go", "policy"} {
		fmt.Printf("%-24s %7d", metric, r.Totals[metric])
		if r.Changes != nil {
			fmt.Printf(" (%+d)", r.Changes.Lines[metric])
		}
		fmt.Println()
	}
	fmt.Println("Packages (handwritten production lines; exported names include fields and methods):")
	for _, name := range slices.Sorted(maps.Keys(r.Packages)) {
		p := r.Packages[name]
		fmt.Printf("  %-34s %5d lines  %3d imports  %3d exports  %3d globals  [%s]\n", name, p.Lines, len(p.Imports), len(p.Exports), len(p.Globals), p.Category)
	}
	if c := r.Changes; c != nil {
		fmt.Println("Changes from", r.Base)
		for _, section := range []struct {
			name string
			diff difference
		}{{"packages", difference{c.Added, c.Removed}}, {"dependencies", c.Edges}, {"exports", c.Exports}, {"globals", c.Globals}} {
			fmt.Printf("  %s: +%d -%d\n", section.name, len(section.diff.Added), len(section.diff.Removed))
			for _, value := range section.diff.Added {
				fmt.Println("    +", value)
			}
			for _, value := range section.diff.Removed {
				fmt.Println("    -", value)
			}
		}
	}
	fmt.Printf("Compiled modules checked: %d\nBoundary violations: %d\n", len(r.Compiled), len(r.Violations))
	for _, violation := range r.Violations {
		fmt.Println(violation)
	}
}

func main() {
	tracked := flag.Bool("tracked", false, "inspect tracked source only")
	jsonOutput := flag.Bool("json", false, "emit the complete report as JSON")
	base := flag.String("base", "", "compare package growth against this explicit Git revision")
	args := os.Args[1:]
	if len(args) != 0 && !strings.HasPrefix(args[0], "-") {
		args = append(slices.Clone(args[1:]), args[0])
	}
	flag.CommandLine.Parse(args)
	root := "."
	if flag.NArg() > 1 {
		fmt.Fprintln(os.Stderr, "usage: check-core.py [--tracked] [--json] [--base REF] [root]")
		os.Exit(2)
	}
	if flag.NArg() == 1 {
		root = flag.Arg(0)
	}
	r, err := run(root, *tracked, *base)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if *jsonOutput {
		encoder := json.NewEncoder(os.Stdout)
		encoder.SetIndent("", "  ")
		if err := encoder.Encode(r); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	} else {
		printReport(r)
	}
	if len(r.Violations) != 0 {
		os.Exit(1)
	}
}
