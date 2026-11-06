// Command presets drafts monitor presets from public API specs.
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	sourcesPath = "sources.json"
	lockPath    = "sources.lock.json"
	cacheDir    = ".cache"
	shippedDir  = "../../presets"
)

var camel = regexp.MustCompile(`([a-z0-9])([A-Z])`)

func snake(s string) string {
	return strings.ToLower(camel.ReplaceAllString(s, "${1}_${2}"))
}

func load[T any](path string) (T, error) {
	var v T
	src, err := os.ReadFile(path)
	if err == nil {
		err = json.Unmarshal(src, &v)
	}
	return v, err
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: presets update|fetch|group|generate|check [service...]; group regroups shipped operations; update --all refreshes every source; check --reviewed requires complete review")
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "fetch", "update":
		var sources map[string]source
		var lock lockFile
		if sources, err = load[map[string]source](sourcesPath); err != nil {
			break
		}
		if lock, err = load[lockFile](lockPath); errors.Is(err, os.ErrNotExist) {
			lock, err = lockFile{}, nil
		}
		if err != nil {
			break
		}
		if os.Args[1] == "fetch" {
			if len(os.Args) > 2 {
				selected := map[string]source{}
				for _, name := range os.Args[2:] {
					src, ok := sources[name]
					if !ok {
						err = fmt.Errorf("unknown source %q", name)
						break
					}
					selected[name] = src
				}
				if err != nil {
					break
				}
				sources = selected
			}
			err = fetch(sources, lock)
			break
		}
		names := os.Args[2:]
		if slices.Contains(names, "--all") {
			names = sortedKeys(sources)
		}
		if err = update(sources, lock, names); err == nil {
			err = writeJSON(lockPath, lock)
		}
	case "generate":
		err = generate(os.Args[2:])
	case "group":
		err = groupShipped(os.Args[2:])
	case "check":
		var names []string
		var reviewed bool
		var maxAge time.Duration
		for _, arg := range os.Args[2:] {
			switch {
			case arg == "--reviewed":
				reviewed = true
			case strings.HasPrefix(arg, "--max-age="):
				maxAge, err = time.ParseDuration(strings.TrimPrefix(arg, "--max-age="))
				if err == nil && maxAge <= 0 {
					err = fmt.Errorf("max-age must be positive")
				}
			default:
				names = append(names, arg)
			}
			if err != nil {
				break
			}
		}
		if err == nil {
			err = check(names, reviewed, maxAge)
		}
	default:
		err = fmt.Errorf("unknown command %s", os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
