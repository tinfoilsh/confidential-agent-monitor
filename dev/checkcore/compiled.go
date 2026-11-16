package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
)

type compiledPackage struct {
	ImportPath, Dir string
	Imports, Deps   []string
	Incomplete      bool
	Error           *struct{ Err string }
	DepsErrors      []struct{ Err string }
}

func compiledViolations(p compiledPackage, rules map[string]rule) []string {
	name, local := localPackage(p.ImportPath)
	if !local {
		return nil
	}
	var violations []string
	if _, known := rules[name]; !known {
		violations = append(violations, "compiled package is outside the approved graph: "+p.ImportPath)
	}
	if p.Incomplete || p.Error != nil || len(p.DepsErrors) != 0 {
		violations = append(violations, "cannot verify incomplete compiled package "+p.ImportPath)
	}
	for _, dependency := range p.Imports {
		if reason := checkImport(name, dependency, rules); reason != "" {
			violations = append(violations, p.ImportPath+": "+reason)
		}
	}
	for _, dependency := range p.Deps {
		if reason := fence(name, dependency, rules); reason != "" {
			violations = append(violations, p.ImportPath+": transitive "+reason)
		}
		if target, local := localPackage(dependency); name == "cmd/other" && local && !slices.Contains(cedarPackages, target) {
			violations = append(violations, "cmd/other: forbidden transitive dependency "+dependency)
		}
	}
	return violations
}

func checkCompiled(root string, foundModules []string, rules map[string]rule) (map[string][]string, []string) {
	compiled := map[string][]string{}
	var violations []string
	for _, dir := range foundModules {
		if !slices.Contains(modules, dir) {
			violations = append(violations, "unlisted Go module "+dir)
		}
	}
	for _, dir := range modules {
		if !slices.Contains(foundModules, dir) {
			violations = append(violations, "missing approved Go module "+dir)
			continue
		}
		cmd := exec.Command("go", "list", "-mod=readonly", "-deps", "-json=ImportPath,Dir,Imports,Deps,Incomplete,Error,DepsErrors", "./...")
		cmd.Dir = filepath.Join(root, filepath.FromSlash(dir))
		cmd.Env = append(os.Environ(), "GOWORK=off")
		var stderr bytes.Buffer
		cmd.Stderr = &stderr
		data, err := cmd.Output()
		if err != nil {
			violations = append(violations, fmt.Sprintf("%s: cannot verify compiled dependencies: %v: %s", dir, err, strings.TrimSpace(stderr.String())))
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		count := 0
		for {
			var p compiledPackage
			if err := decoder.Decode(&p); errors.Is(err, io.EOF) {
				break
			} else if err != nil {
				violations = append(violations, fmt.Sprintf("%s: invalid go list output: %v", dir, err))
				break
			}
			count++
			if relative, err := filepath.Rel(root, p.Dir); p.Dir != "" && err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !ignored(relative) {
				expected := module
				if relative != "." {
					expected += "/" + filepath.ToSlash(relative)
				}
				if p.ImportPath != expected {
					violations = append(violations, fmt.Sprintf("%s: local package %s uses unexpected import path %s", dir, relative, p.ImportPath))
				}
			}
			for _, reason := range compiledViolations(p, rules) {
				violations = append(violations, dir+": "+reason)
			}
			if name, local := localPackage(p.ImportPath); local {
				compiled[dir] = append(compiled[dir], name)
			}
		}
		if count == 0 {
			violations = append(violations, dir+": go list returned no packages")
		}
		compiled[dir] = unique(compiled[dir])
	}
	return compiled, violations
}
