package main

import (
	"bytes"
	"cmp"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode"

	"sigs.k8s.io/yaml"
)

const (
	userAgent     = "Mozilla/5.0 (X11; Linux x86_64) presets-importer"
	acceptAny     = "*/*"
	updateWorkers = 16
	segmentValue  = "[^/]+"
	restValue     = ".+"
)

var (
	gzipMagic = []byte{0x1f, 0x8b}
	commitSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

type lockEntry struct {
	Source    string          `json:"source"`
	URL       string          `json:"url"`
	Commit    string          `json:"commit,omitempty"`
	Revision  string          `json:"revision,omitempty"`
	SHA256    string          `json:"sha256"`
	Bytes     int             `json:"bytes"`
	CheckedAt string          `json:"checked_at,omitempty"`
	Files     []documentStamp `json:"files,omitempty"`
}

type lockFile map[string][]lockEntry

func (l lockFile) entry(service string, ref specRef) (lockEntry, error) {
	for _, e := range l[service] {
		if e.Source == ref.source() {
			return e, nil
		}
	}
	return lockEntry{}, fmt.Errorf("%s has no lock entry; run update %s", ref.source(), service)
}

func cached(sum string) string { return filepath.Join(cacheDir, sum) }

func download(url string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", acceptAny)
	for key, value := range headers {
		req.Header.Set(key, value)
	}
	resp, err := (&http.Client{Timeout: 45 * time.Second}).Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%s: HTTP %d", url, resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

func store(src []byte) (string, error) {
	h := sha256.Sum256(src)
	sum := hex.EncodeToString(h[:])
	return sum, os.WriteFile(cached(sum), src, 0o644)
}

var remoteRefs sync.Map

func refs(repo string) (map[string]string, error) {
	f, _ := remoteRefs.LoadOrStore(repo, sync.OnceValues(func() (map[string]string, error) {
		out, err := exec.Command("git", "ls-remote", "--heads", "--tags", "https://github.com/"+repo).Output()
		refs := map[string]string{}
		for _, line := range strings.Split(string(out), "\n") {
			if sha, name, ok := strings.Cut(line, "\t"); ok {
				refs[name] = sha
			}
		}
		return refs, err
	}))
	return f.(func() (map[string]string, error))()
}

func resolve(ref specRef, old lockEntry) (lockEntry, []byte, error) {
	e := lockEntry{Source: ref.source(), URL: ref.URL}
	if ref.GitHub != "" {
		e.Commit = ref.Ref
		if !commitSHA.MatchString(ref.Ref) {
			all, err := refs(ref.GitHub)
			if err != nil {
				return e, nil, err
			}
			for _, name := range []string{"refs/heads/" + ref.Ref, "refs/tags/" + ref.Ref + "^{}", "refs/tags/" + ref.Ref} {
				if e.Commit = all[name]; e.Commit != "" {
					break
				}
			}
			if e.Commit == "" {
				return e, nil, fmt.Errorf("github %s has no branch or tag %s", ref.GitHub, ref.Ref)
			}
		}
		e.URL = fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s", ref.GitHub, e.Commit, ref.File)
		if old.Commit == e.Commit {
			if src, err := os.ReadFile(cached(old.SHA256)); err == nil {
				old.CheckedAt = time.Now().UTC().Format(time.RFC3339)
				old.Files, err = referencedFiles(ref, old.URL, src)
				return old, nil, err
			}
		}
	}
	src, err := sourceBytes(ref, e.URL)
	if err != nil {
		return e, nil, err
	}
	if ref.Format == "discovery" {
		var doc struct{ Revision string }
		json.Unmarshal(src, &doc)
		e.Revision = doc.Revision
	}
	e.SHA256, err = store(src)
	e.Bytes = len(src)
	e.CheckedAt = time.Now().UTC().Format(time.RFC3339)
	if err == nil {
		e.Files, err = referencedFiles(ref, e.URL, src)
	}
	if err == nil {
		if _, err = parseSpec(ref, src, e, nil); err != nil {
			err = fmt.Errorf("%s does not parse as %s: %w", e.URL, ref.Format, err)
		}
	}
	if err == nil && (ref.Format == "slack" || ref.Format == "airtable") {
		err = os.MkdirAll("snapshots", 0o755)
		if err == nil {
			err = os.WriteFile(filepath.Join("snapshots", e.SHA256), src, 0o644)
		}
	}
	return e, src, err
}

func referencedFiles(ref specRef, location string, src []byte) ([]documentStamp, error) {
	if ref.Format != "openapi" {
		return nil, nil
	}
	var files []documentStamp
	seen := map[string]bool{location: true}
	var visit func(location string, src []byte) error
	visit = func(location string, src []byte) error {
		src, err := inflate(src)
		var doc any
		if err == nil && json.Unmarshal(src, &doc) != nil {
			err = yaml.Unmarshal(src, &doc)
		}
		if err != nil {
			return fmt.Errorf("%s: %w", location, err)
		}
		base, err := url.Parse(location)
		if err != nil {
			return err
		}
		for _, target := range relativeRefs(doc, "") {
			u, err := base.Parse(target)
			if err != nil {
				return err
			}
			u.Fragment = ""
			if seen[u.String()] {
				continue
			}
			seen[u.String()] = true
			b, err := download(u.String(), ref.Headers)
			if err != nil {
				return err
			}
			sum, err := store(b)
			if err != nil {
				return err
			}
			files = append(files, documentStamp{u.String(), sum})
			if err := visit(u.String(), b); err != nil {
				return err
			}
		}
		return nil
	}
	err := visit(location, src)
	slices.SortFunc(files, func(a, b documentStamp) int { return strings.Compare(a.URL, b.URL) })
	return files, err
}

func relativeRefs(v any, name string) []string {
	var refs []string
	switch x := v.(type) {
	case map[string]any:
		if ref, ok := x["$ref"].(string); ok && !strings.HasPrefix(ref, "#") && !strings.Contains(ref, "://") {
			refs = append(refs, ref)
		}
		for key, child := range x {
			if !annotation(name, key) {
				refs = append(refs, relativeRefs(child, key)...)
			}
		}
	case []any:
		for _, child := range x {
			refs = append(refs, relativeRefs(child, "")...)
		}
	}
	return refs
}

func fetchFiles(files []documentStamp, headers map[string]string) error {
	for _, f := range files {
		if _, err := os.Stat(cached(f.SHA256)); err == nil {
			continue
		}
		src, err := download(f.URL, headers)
		if err != nil {
			return err
		}
		sum, err := store(src)
		if err != nil {
			return err
		}
		if sum != f.SHA256 {
			os.Remove(cached(sum))
			return fmt.Errorf("%s no longer serves the locked content; run update", f.URL)
		}
	}
	return nil
}

func lockedFiles(e lockEntry) (map[string][]byte, error) {
	files := map[string][]byte{}
	for _, f := range e.Files {
		src, err := os.ReadFile(cached(f.SHA256))
		if err != nil {
			return nil, fmt.Errorf("%s is not cached; run fetch", f.URL)
		}
		if h := sha256.Sum256(src); hex.EncodeToString(h[:]) != f.SHA256 {
			return nil, fmt.Errorf("cached %s does not match the lock", f.URL)
		}
		files[f.URL] = src
	}
	return files, nil
}

func fetch(sources map[string]source, lock lockFile) error {
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return err
	}
	var failed []string
	for _, name := range sortedKeys(sources) {
		for _, ref := range sources[name].Specs {
			e, err := lock.entry(name, ref)
			if err == nil {
				err = fetchFiles(e.Files, ref.Headers)
			}
			if err == nil {
				if _, statErr := os.Stat(cached(e.SHA256)); statErr == nil {
					continue
				}
				if src, snapshotErr := os.ReadFile(filepath.Join("snapshots", e.SHA256)); snapshotErr == nil {
					h := sha256.Sum256(src)
					if hex.EncodeToString(h[:]) != e.SHA256 {
						failed = append(failed, name+": snapshot hash mismatch")
						continue
					}
					if _, err := store(src); err != nil {
						failed = append(failed, name+": "+err.Error())
					}
					continue
				}
				var src []byte
				if src, err = sourceBytes(ref, e.URL); err == nil {
					var sum string
					if sum, err = store(src); err == nil && sum != e.SHA256 {
						os.Remove(cached(sum))
						err = fmt.Errorf("%s no longer serves the locked content; run update %s", e.URL, name)
					}
				}
			}
			if err != nil {
				failed = append(failed, name+": "+err.Error())
			}
		}
	}
	if len(failed) > 0 {
		return errors.New(strings.Join(failed, "\n"))
	}
	return nil
}

func (l lockFile) dirty(name string, src source) bool {
	for _, ref := range src.Specs {
		if _, err := l.entry(name, ref); err != nil {
			return true
		}
	}
	return len(l[name]) != len(src.Specs)
}

func update(sources map[string]source, lock lockFile, only []string) error {
	if err := os.MkdirAll(cacheDir, 0o755); err != nil {
		return err
	}
	for _, name := range only {
		if _, ok := sources[name]; !ok {
			return fmt.Errorf("unknown source %q", name)
		}
	}
	var names []string
	for _, name := range sortedKeys(sources) {
		if len(only) == 0 && lock.dirty(name, sources[name]) || slices.Contains(only, name) {
			names = append(names, name)
		}
	}
	entries, logs := make([][]lockEntry, len(names)), make([]string, len(names))
	errs := make([]error, len(names))
	var wg sync.WaitGroup
	slots := make(chan struct{}, updateWorkers)
	for i, name := range names {
		wg.Go(func() {
			slots <- struct{}{}
			defer func() { <-slots }()
			entries[i], logs[i], errs[i] = updateService(name, sources[name], lock)
		})
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			fmt.Print(logs[i])
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	for name := range lock {
		if len(sources[name].Specs) == 0 {
			delete(lock, name)
		}
	}
	for i, name := range names {
		fmt.Print(logs[i])
		if len(entries[i]) > 0 {
			lock[name] = entries[i]
		} else {
			delete(lock, name)
		}
	}
	return nil
}

func updateService(name string, src source, lock lockFile) ([]lockEntry, string, error) {
	var entries []lockEntry
	var log strings.Builder
	var failures []error
	for _, ref := range src.Specs {
		old, oldErr := lock.entry(name, ref)
		e, after, err := resolve(ref, old)
		if err != nil {
			failures = append(failures, fmt.Errorf("%s: %w", name, err))
			fmt.Fprintf(&log, "%s: %v\n", name, err)
			if oldErr == nil {
				entries = append(entries, old)
			}
			continue
		}
		entries = append(entries, e)
		if oldErr != nil || old.SHA256 == e.SHA256 {
			continue
		}
		before, _ := os.ReadFile(cached(old.SHA256))
		added, removed := routeDiff(ref, old, e, before, after)
		fmt.Fprintf(&log, "%s: %s %s -> %s: %d routes added, %d removed\n", name, ref.source(), short(old), short(e), len(added), len(removed))
		for _, r := range added {
			fmt.Fprintln(&log, "  +", r)
		}
		for _, r := range removed {
			fmt.Fprintln(&log, "  -", r)
		}
	}
	return entries, log.String(), errors.Join(failures...)
}

func short(e lockEntry) string {
	if e.Commit != "" {
		return e.Commit[:12]
	}
	if e.Revision != "" {
		return e.Revision
	}
	return e.SHA256[:12]
}

func routeDiff(ref specRef, old, e lockEntry, before, after []byte) (added, removed []string) {
	routes := func(src []byte, e lockEntry) []string {
		var out []string
		p, err := parseSpec(ref, src, e, nil)
		if err != nil {
			return nil
		}
		include := regexp.MustCompile(ref.Include)
		for _, o := range p.Ops {
			if include.MatchString(o.Path) {
				out = append(out, routeShape(strings.ToUpper(o.Method), o.Path)+graphqlField(o))
			}
		}
		return out
	}
	b, a := routes(before, old), routes(after, e)
	for _, r := range a {
		if !slices.Contains(b, r) {
			added = append(added, r)
		}
	}
	for _, r := range b {
		if !slices.Contains(a, r) {
			removed = append(removed, r)
		}
	}
	return added, removed
}

func graphqlField(o specOp) string {
	if o.GraphQL == nil {
		return ""
	}
	return " " + strings.Join(o.GraphQL, " ")
}

func sortedKeys[V any](m map[string]V) []string {
	return slices.Sorted(func(yield func(string) bool) {
		for k := range m {
			if !yield(k) {
				return
			}
		}
	})
}

var parsedCache = map[string]parsed{}

func read(ref specRef, e lockEntry, encodings []string) (parsed, error) {
	key := strings.Join([]string{e.SHA256, ref.Format, ref.Origin, ref.Path, e.URL, strings.Join(encodings, ","), fmt.Sprint(ref.Variables, ref.Captures)}, "\x00")
	if p, ok := parsedCache[key]; ok {
		return p, nil
	}
	src, err := os.ReadFile(cached(e.SHA256))
	if errors.Is(err, os.ErrNotExist) {
		src, err = os.ReadFile(filepath.Join("snapshots", e.SHA256))
	}
	if err != nil {
		return parsed{}, fmt.Errorf("%s is not cached; run fetch", ref.source())
	}
	if h := sha256.Sum256(src); hex.EncodeToString(h[:]) != e.SHA256 {
		return parsed{}, fmt.Errorf("cached %s does not match the lock", ref.source())
	}
	p, err := parseSpec(ref, src, e, encodings)
	if err == nil {
		parsedCache[key] = p
	}
	return p, err
}

func inflate(src []byte) ([]byte, error) {
	if !bytes.HasPrefix(src, gzipMagic) {
		return src, nil
	}
	r, err := gzip.NewReader(bytes.NewReader(src))
	if err != nil {
		return nil, err
	}
	return io.ReadAll(r)
}

func parseSpec(ref specRef, src []byte, e lockEntry, encodings []string) (parsed, error) {
	src, err := inflate(src)
	if err != nil {
		return parsed{}, err
	}
	switch ref.Format {
	case "openapi", "swagger", "airtable":
		files, err := lockedFiles(e)
		if err != nil {
			return parsed{}, err
		}
		return parseOpenAPI(src, ref.Format == "swagger", e.URL, ref.Path, files, encodings)
	case "slack":
		return parseDocumentation(src)
	case "discovery":
		return parseDiscovery(src)
	case "graphql":
		return parseGraphQL(src, ref.Origin, ref.Path)
	case "botocore":
		return parseBotocore(src)
	case "postman":
		return parsePostman(src, ref)
	}
	return parsed{}, fmt.Errorf("unknown format %s", ref.Format)
}

func specOps(name string, src source, lock lockFile, origins map[string]any) (parsed, error) {
	var out parsed
	usedGroups, usedEffects, usedOpaque, usedExclusions, usedWildcards := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	reviewed, opaque := map[string][]string{}, map[string]bool{}
	known := map[string]bool{}
	for list, ids := range src.Effects {
		effects := strings.Split(list, ",")
		for _, id := range ids {
			if reviewed[id] != nil || slices.ContainsFunc(effects, func(e string) bool { return !slices.Contains(effectOrder, e) }) {
				return out, fmt.Errorf("%s: effects %q for %s repeat the operation or name an unknown effect", name, list, id)
			}
			reviewed[id] = effects
		}
	}
	for _, id := range src.Opaque {
		opaque[id] = true
	}
	for i, param := range src.Params {
		if param == "" || slices.Contains(src.Params[:i], param) {
			return out, fmt.Errorf("%s: params name an empty or repeated query parameter %q", name, param)
		}
	}
	for i, body := range src.Encodings {
		if body != "json" && body != "form" || slices.Contains(src.Encodings[:i], body) {
			return out, fmt.Errorf("%s: encodings name an unknown or repeated body encoding %q", name, body)
		}
	}
	for _, ref := range src.Specs {
		e, err := lock.entry(name, ref)
		if err != nil {
			return out, err
		}
		p, err := read(ref, e, src.Encodings)
		if err != nil {
			return out, err
		}
		markRoutes(p.Ops)
		out.Warnings = append(out.Warnings, p.Warnings...)
		if ref.Group != "" && !groupPath.MatchString(ref.Group) {
			return out, fmt.Errorf("%s: invalid resource group %q for %s", name, ref.Group, ref.source())
		}
		if p.EndpointPrefix != "" && ref.Origin == "" {
			if len(lock[awsEndpoints]) == 0 {
				return out, fmt.Errorf("%s has no lock entry; run update %s", awsEndpoints, awsEndpoints)
			}
			endpoints, err := read(specRef{Format: ref.Format, URL: lock[awsEndpoints][0].Source}, lock[awsEndpoints][0], nil)
			if err != nil {
				return out, err
			}
			if out.Origins == nil {
				out.Origins = map[string][]string{}
			}
			for set, hosts := range endpoints.Partition.origins(p.EndpointPrefix) {
				out.Origins[set] = append(out.Origins[set], hosts...)
			}
		}
		include := regexp.MustCompile(ref.Include)
		var ids []string
		for _, o := range p.Ops {
			if known[o.ID] && p.Version != "" {
				o.ID = p.Version + "." + o.ID
			}
			ids = append(ids, o.ID)
			if ref.Origin != "" && !o.Server {
				o.Origin = ref.Origin
			}
			last := o.Path[strings.LastIndex(o.Path, "/")+1:]
			if wildcard := strings.Trim(last, "{}"); "{"+wildcard+"}" == last && slices.Contains(src.Wildcards, wildcard) {
				o.Path = strings.TrimSuffix(o.Path, "}") + "*}"
				usedWildcards[wildcard] = true
			}
			if o.SourceID == "" {
				o.SourceID = o.ID
				if o.SourceID == "" {
					o.SourceID = o.Method + " " + o.Path
				}
			}
			if o.SourceURL == "" {
				o.SourceURL = e.URL
				o.SourceHash = e.SHA256
			}
			if key, ok := sourceKey(src.Exclusions, o); ok {
				usedExclusions[key] = true
				if include.MatchString(o.Path) {
					out.Excluded = append(out.Excluded, o)
				}
				continue
			}
			if !include.MatchString(o.Path) {
				continue
			}
			for _, param := range src.Params {
				if !slices.Contains(o.Params, param) {
					o.Params = slices.Concat(o.Params, []string{param})
				}
			}
			if ref.Group != "" {
				o.Resource = ref.Group + "." + actionResource(o)
			}
			if key, ok := sourceKey(src.Groups, o); ok {
				group := src.Groups[key]
				o.Resource = group
				usedGroups[key] = true
			}
			if key, ok := sourceKey(reviewed, o); ok {
				o.Effects, o.Reviewed = reviewed[key], true
				usedEffects[key] = true
			}
			if key, ok := sourceKey(opaque, o); ok {
				o.Body, o.Unsupported, o.Opaque = "any", "", true
				usedOpaque[key] = true
			}
			if o.Server && strings.HasPrefix(o.Origin, "https://") {
				if set := originSet(origins, o.Origin); set != "" {
					o.Origin = set
				} else if strings.Contains(o.Origin, "{") {
					o.Unsupported = "no origin set of the preset covers " + o.Origin
				}
			}
			out.Ops = append(out.Ops, o)
		}
		for _, id := range ids {
			known[id] = true
		}
		if out.Auth == nil {
			out.Auth = p.Auth
		}
	}
	for id := range src.Exclusions {
		if !usedExclusions[id] {
			return out, fmt.Errorf("%s: exclusions name unknown source operation %q", name, id)
		}
	}
	for id, group := range src.Groups {
		if !groupPath.MatchString(group) {
			return out, fmt.Errorf("%s: invalid resource group %q for %s", name, group, id)
		}
		if !usedGroups[id] && !slices.ContainsFunc(strings.Split(src.Preset, ","), func(preset string) bool {
			record, _ := load[map[string]any](filepath.Join(shippedDir, preset+".json"))
			spec, _ := record["http"].(map[string]any)
			ops, _ := spec["operations"].(map[string]any)
			return ops[id] != nil
		}) {
			return out, fmt.Errorf("%s: resource group names unknown or excluded source operation or shipped descriptor %q", name, id)
		}
	}
	for id := range reviewed {
		if !usedEffects[id] {
			return out, fmt.Errorf("%s: effects name unknown or excluded source operation %q", name, id)
		}
	}
	for i, id := range src.Opaque {
		if !usedOpaque[id] || slices.Contains(src.Opaque[:i], id) {
			return out, fmt.Errorf("%s: opaque names unknown, excluded, or repeated source operation %q", name, id)
		}
	}
	for i, wildcard := range src.Wildcards {
		if !usedWildcards[wildcard] || slices.Contains(src.Wildcards[:i], wildcard) {
			return out, fmt.Errorf("%s: wildcards name an unknown or repeated final path parameter %q", name, wildcard)
		}
	}
	return out, nil
}

// sourceKey returns the key naming the operation in a review table: its method and path, or else its source operation ID.
func sourceKey[V any](table map[string]V, o specOp) (string, bool) {
	for _, key := range []string{o.Method + " " + o.Path, o.SourceID} {
		if _, ok := table[key]; ok {
			return key, true
		}
	}
	return "", false
}

func originSet(origins map[string]any, origin string) string {
	labels := strings.Split(strings.TrimPrefix(origin, "https://"), ".")
	for _, name := range sortedKeys(origins) {
		templates, _ := origins[name].([]any)
		for _, value := range templates {
			template, _ := value.(string)
			parts := strings.Split(strings.TrimPrefix(template, "https://"), ".")
			covers := strings.HasPrefix(template, "https://") && len(parts) == len(labels)
			for i := 0; covers && i < len(parts); i++ {
				covers, _ = regexp.MatchString(`\A`+segmentExpr(parts[i], nil)+`\z`, labels[i])
			}
			if covers {
				return "{" + name + "}"
			}
		}
	}
	return ""
}

type drafted struct {
	op      specOp
	effect  string
	effects []string
	action  string
	scope   map[string]any
}

func segmentsOverlap(a, b specOp) bool {
	as, bs := strings.Split(a.Path, "/"), strings.Split(b.Path, "/")
	star := func(s []string) bool { return strings.HasSuffix(s[len(s)-1], "*}") }
	if len(as) != len(bs) && !(star(as) && len(bs) >= len(as)) && !(star(bs) && len(as) >= len(bs)) {
		return false
	}
	for i := 0; i < min(len(as), len(bs)); i++ {
		x, y := as[i], bs[i]
		if strings.HasSuffix(x, "*}") || strings.HasSuffix(y, "*}") {
			return intersect(pathExpr(as[i:], a.PathPatterns), pathExpr(bs[i:], b.PathPatterns))
		}
		if !segmentOverlap(x, y) {
			return false
		}
		if len(a.PathPatterns)+len(b.PathPatterns) > 0 && !intersect(segmentExpr(x, a.PathPatterns), segmentExpr(y, b.PathPatterns)) {
			return false
		}
	}
	return true
}

func segmentOverlap(x, y string) bool {
	px, _, sx, okx := paramParts(x)
	py, _, sy, oky := paramParts(y)
	switch {
	case !okx && !oky:
		return x == y
	case okx && !oky:
		return strings.HasPrefix(y, px) && strings.HasSuffix(y, sx) && len(y) > len(px)+len(sx)
	case !okx && oky:
		return segmentOverlap(y, x)
	}
	return (strings.HasPrefix(px, py) || strings.HasPrefix(py, px)) && (strings.HasSuffix(sx, sy) || strings.HasSuffix(sy, sx))
}

func paramParts(s string) (prefix, name, suffix string, ok bool) {
	i, j := strings.Index(s, "{"), strings.Index(s, "}")
	if i < 0 || j < i {
		return "", "", "", false
	}
	return s[:i], s[i+1 : j], s[j+1:], true
}

func segmentExpr(s string, patterns map[string]string) string {
	prefix, name, suffix, ok := paramParts(s)
	if !ok {
		return regexp.QuoteMeta(s)
	}
	value := segmentValue
	if name, ok = strings.CutSuffix(name, "*"); ok {
		value = restValue
	}
	return regexp.QuoteMeta(prefix) + "(?:" + cmp.Or(patterns[name], value) + ")" + regexp.QuoteMeta(suffix)
}

func pathExpr(segments []string, patterns map[string]string) string {
	exprs := make([]string, len(segments))
	for i, s := range segments {
		exprs[i] = segmentExpr(s, patterns)
	}
	return strings.Join(exprs, "/")
}

func literalPrefix(pattern string) string {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return ""
	}
	prefix, _ := re.LiteralPrefix()
	return prefix
}

// within reports whether every value of segment s, known to overlap segment t, also matches t.
func within(s, t string, sPatterns, tPatterns map[string]string) bool {
	tPrefix, tName, tSuffix, capture := paramParts(t)
	prefix, _, suffix, ok := paramParts(s)
	if !capture || !ok {
		return s == t || capture
	}
	return strings.HasPrefix(prefix, tPrefix) && strings.HasSuffix(suffix, tSuffix) && (tPatterns[tName] == "" || segmentExpr(s, sPatterns) == segmentExpr(t, tPatterns))
}

var programs = map[string]*syntax.Prog{}

// intersect reports whether some string matches both expressions entirely. It treats assertions and case folding as matching anything.
func intersect(x, y string) bool {
	if x == y {
		return true
	}
	var progs [2]*syntax.Prog
	for i, expr := range []string{x, y} {
		p, ok := programs[expr]
		if !ok {
			re, err := syntax.Parse(expr, syntax.Perl)
			if err == nil {
				p, _ = syntax.Compile(re.Simplify())
			}
			programs[expr] = p
		}
		if p == nil {
			return true
		}
		progs[i] = p
	}
	a, b := progs[0], progs[1]
	closure := func(p *syntax.Prog, pc uint32) []uint32 {
		var out []uint32
		seen := make([]bool, len(p.Inst))
		var visit func(uint32)
		visit = func(pc uint32) {
			if seen[pc] {
				return
			}
			seen[pc] = true
			switch i := p.Inst[pc]; i.Op {
			case syntax.InstAlt, syntax.InstAltMatch:
				visit(i.Out)
				visit(i.Arg)
			case syntax.InstCapture, syntax.InstEmptyWidth, syntax.InstNop:
				visit(i.Out)
			case syntax.InstMatch, syntax.InstRune, syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
				out = append(out, pc)
			}
		}
		visit(pc)
		return out
	}
	runes := func(i syntax.Inst) []rune {
		switch {
		case i.Op == syntax.InstRuneAny || i.Op == syntax.InstRuneAnyNotNL || syntax.Flags(i.Arg)&syntax.FoldCase != 0:
			return []rune{0, unicode.MaxRune}
		case len(i.Rune) == 1:
			return []rune{i.Rune[0], i.Rune[0]}
		}
		return i.Rune
	}
	type state struct{ a, b uint32 }
	seen := map[state]bool{}
	var pending []state
	follow := func(pa, pb uint32) {
		for _, i := range closure(a, pa) {
			for _, j := range closure(b, pb) {
				if s := (state{i, j}); !seen[s] {
					seen[s] = true
					pending = append(pending, s)
				}
			}
		}
	}
	follow(uint32(a.Start), uint32(b.Start))
	for len(pending) > 0 {
		s := pending[len(pending)-1]
		pending = pending[:len(pending)-1]
		i, j := a.Inst[s.a], b.Inst[s.b]
		if i.Op == syntax.InstMatch || j.Op == syntax.InstMatch {
			if i.Op == j.Op {
				return true
			}
			continue
		}
		r, t := runes(i), runes(j)
	shared:
		for m := 0; m < len(r); m += 2 {
			for n := 0; n < len(t); n += 2 {
				if r[m] <= t[n+1] && t[n] <= r[m+1] {
					follow(i.Out, j.Out)
					break shared
				}
			}
		}
	}
	return false
}

func bodiesOverlap(a, b string) bool {
	return a == b || a == "any" || b == "any"
}

func draftOps(p parsed, ai bool) []drafted {
	var out []drafted
	for _, o := range p.Ops {
		if o.Method == "" || o.Path == "" {
			continue
		}
		o.Method = strings.ToUpper(o.Method)
		d := drafted{op: o, effect: draftEffect(o, ai), scope: map[string]any{}}
		d.effects = slices.Clone(o.Effects)
		if len(d.effects) == 0 {
			d.effects = []string{d.effect}
			if ai && d.effect == "generate" {
				d.effects = []string{"generate", "pay", "send"}
			}
		} else {
			d.effect = d.effects[0]
		}
		d.action = groupedAction(o, d.effect)
		for _, m := range pathParam.FindAllStringSubmatch(o.Path, -1) {
			name := strings.TrimSuffix(m[1], "*")
			if d.scope[name] == nil {
				d.scope[name] = map[string]any{"from": "path", "at": name}
			}
		}
		for _, r := range o.Required {
			if r.From == "body" && o.Body != "json" || r.From == "form" && o.Body != "form" {
				continue
			}
			name := r.Name
			if d.scope[name] != nil {
				name = r.From + "." + name
			}
			if d.scope[name] != nil {
				continue
			}
			at := r.Name
			if r.From == "body" || r.From == "argument" || r.From == "header_json" {
				at = "/" + r.Name
			}
			spec := map[string]any{"from": r.From, "at": at}
			if r.From == "header_json" {
				spec["header"] = o.ArgHeader
			}
			if r.Type != "string" {
				spec["type"] = r.Type
			}
			if r.Optional {
				spec["optional"] = true
			}
			d.scope[name] = spec
		}
		if len(o.Params) > 0 || len(o.Query) > 0 {
			bind(d.scope, "query", map[string]any{"from": "query", "at": "", "type": "object"})
		}
		if o.Body == "json" {
			typ := o.BodyType
			if typ == "" {
				typ = "object"
			}
			bind(d.scope, "request", map[string]any{"from": "body", "at": "", "type": typ})
		}
		if o.Body == "form" {
			bind(d.scope, "request", map[string]any{"from": "form", "at": "", "type": "object"})
		}
		if o.Body == "graphql" {
			bind(d.scope, "arguments", map[string]any{"from": "argument", "at": "", "type": "object"})
		}
		if o.ArgHeader != "" {
			bind(d.scope, "arguments", map[string]any{"from": "header_json", "header": o.ArgHeader, "at": "", "type": "object"})
		}
		o.Params = slices.DeleteFunc(o.Params, func(q string) bool { _, ok := o.Query[q]; return ok })
		d.op = o
		out = append(out, d)
	}
	return out
}

func bind(scope map[string]any, name string, spec map[string]any) {
	for scope[name] != nil {
		name = "request." + name
	}
	scope[name] = spec
}

func operationObj(d drafted, id string) map[string]any {
	o := d.op
	op := map[string]any{"id": id, "action": d.action, "effects": jsonStrings(d.effects), "method": o.Method, "origin": o.Origin, "path": o.Path}
	if len(o.Query) > 0 {
		op["query"] = o.Query
	}
	if len(o.Headers) > 0 {
		op["headers"] = o.Headers
	}
	if len(o.Fields) > 0 {
		op["fields"] = o.Fields
	}
	if len(o.Params) > 0 && o.GraphQL == nil {
		op["params"] = jsonStrings(o.Params)
	}
	if o.Body != "none" {
		op["body"] = o.Body
	}
	if o.GraphQL != nil {
		op["graphql"] = map[string]any{"operation": o.GraphQL[0], "field": o.GraphQL[1]}
	}
	// Route separation does not narrow rest captures, so they keep their source pattern.
	for name, pattern := range o.PathPatterns {
		if strings.Contains(o.Path, "{"+name+"*}") {
			op["path_patterns"] = map[string]any{name: pattern}
		}
	}
	scope := d.scope
	if scope == nil {
		scope = map[string]any{}
	}
	op["scope"] = scope
	return op
}

func jsonStrings(values []string) []any {
	out := make([]any, len(values))
	for i, value := range values {
		out[i] = value
	}
	return out
}

var paramSeg = regexp.MustCompile(`\{[^}]*\}`)

func routeShape(method, path string) string {
	return method + " " + paramSeg.ReplaceAllString(path, "{}")
}
