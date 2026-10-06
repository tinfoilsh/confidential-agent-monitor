package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"
)

// Some docs sites rate-limit clients that do not look like a browser.
const (
	userAgent     = "Mozilla/5.0 (X11; Linux x86_64) presets-importer"
	updateWorkers = 16
)

var (
	gzipMagic = []byte{0x1f, 0x8b}
	commitSHA = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

// A lockEntry is what update resolved a spec to: an immutable URL where the source has one, and the content's hash.
type lockEntry struct {
	Source   string `json:"source"`
	URL      string `json:"url"`
	Commit   string `json:"commit,omitempty"`
	Revision string `json:"revision,omitempty"`
	SHA256   string `json:"sha256"`
	Bytes    int    `json:"bytes"`
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

// cached holds specs by content hash, so a lock entry always names the bytes it was resolved to.
func cached(sum string) string { return filepath.Join(cacheDir, sum) }

func download(url string) ([]byte, error) {
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	req.Header.Set("User-Agent", userAgent)
	resp, err := http.DefaultClient.Do(req)
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

// remoteRefs lists a GitHub repository's branches and tags once per run.
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

// resolve pins a GitHub spec to the commit its ref names now, reusing the locked bytes when that commit is unchanged.
func resolve(ref specRef, old lockEntry) (lockEntry, []byte, error) {
	e := lockEntry{Source: ref.source(), URL: ref.URL}
	if ref.GitHub != "" {
		e.Commit = ref.Ref
		if !commitSHA.MatchString(ref.Ref) {
			all, err := refs(ref.GitHub)
			if err != nil {
				return e, nil, err
			}
			// A branch wins over a tag, and a tag's commit is its peeled ^{} line.
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
			if _, err := os.Stat(cached(old.SHA256)); err == nil {
				return old, nil, nil
			}
		}
	}
	src, err := download(e.URL)
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
	return e, src, err
}

// fetch downloads every locked spec missing from the cache, refusing content that is not what the lock names.
func fetch(sources map[string]source, lock lockFile) error {
	var failed []string
	for _, name := range sortedKeys(sources) {
		for _, ref := range sources[name].Specs {
			e, err := lock.entry(name, ref)
			if err == nil {
				if _, statErr := os.Stat(cached(e.SHA256)); statErr == nil {
					continue
				}
				var src []byte
				if src, err = download(e.URL); err == nil {
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

// dirty says whether a service's specs differ from what the lock resolved.
func (l lockFile) dirty(name string, src source) bool {
	for _, ref := range src.Specs {
		if _, err := l.entry(name, ref); err != nil {
			return true
		}
	}
	return len(l[name]) != len(src.Specs)
}

// update resolves the named services' specs, or else only the dirty ones, in parallel,
// and prints the routes each change adds and removes.
func update(sources map[string]source, lock lockFile, only []string) error {
	for name := range lock {
		if len(sources[name].Specs) == 0 {
			delete(lock, name)
		}
	}
	var names []string
	for _, name := range sortedKeys(sources) {
		if len(only) == 0 && lock.dirty(name, sources[name]) || slices.Contains(only, name) {
			names = append(names, name)
		}
	}
	entries, logs := make([][]lockEntry, len(names)), make([]string, len(names))
	var wg sync.WaitGroup
	slots := make(chan struct{}, updateWorkers)
	for i, name := range names {
		wg.Go(func() {
			slots <- struct{}{}
			defer func() { <-slots }()
			entries[i], logs[i] = updateService(name, sources[name], lock)
		})
	}
	wg.Wait()
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

func updateService(name string, src source, lock lockFile) ([]lockEntry, string) {
	var entries []lockEntry
	var log strings.Builder
	for _, ref := range src.Specs {
		old, oldErr := lock.entry(name, ref)
		e, after, err := resolve(ref, old)
		if err != nil {
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
	return entries, log.String()
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
	routes := func(src []byte, location string) []string {
		var out []string
		p, err := parseSpec(ref, src, location)
		if err != nil {
			return nil
		}
		include := regexp.MustCompile(ref.Include)
		for _, o := range p.Ops {
			if include.MatchString(o.Path) {
				out = append(out, routeShape(strings.ToUpper(o.Method), o.Path, nil)+graphqlField(o))
			}
		}
		return out
	}
	b, a := routes(before, old.URL), routes(after, e.URL)
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

// read parses a locked spec from the cache, refusing bytes that do not match the lock.
func read(ref specRef, e lockEntry) (parsed, error) {
	key := e.SHA256 + ref.Origin + ref.Path
	if p, ok := parsedCache[key]; ok {
		return p, nil
	}
	src, err := os.ReadFile(cached(e.SHA256))
	if err != nil {
		return parsed{}, fmt.Errorf("%s is not cached; run fetch", ref.source())
	}
	if h := sha256.Sum256(src); hex.EncodeToString(h[:]) != e.SHA256 {
		return parsed{}, fmt.Errorf("cached %s does not match the lock", ref.source())
	}
	p, err := parseSpec(ref, src, e.URL)
	parsedCache[key] = p
	return p, err
}

// location is where src was fetched, so relative $refs resolve against the same pinned commit.
func parseSpec(ref specRef, src []byte, location string) (parsed, error) {
	if bytes.HasPrefix(src, gzipMagic) {
		r, err := gzip.NewReader(bytes.NewReader(src))
		if err != nil {
			return parsed{}, err
		}
		if src, err = io.ReadAll(r); err != nil {
			return parsed{}, err
		}
	}
	switch ref.Format {
	case "openapi", "swagger":
		return parseOpenAPI(src, ref.Format == "swagger", location)
	case "discovery":
		return parseDiscovery(src)
	case "graphql":
		return parseGraphQL(src, ref.Origin, ref.Path)
	case "botocore":
		return parseBotocore(src)
	case "postman":
		return parsePostman(src)
	}
	return parsed{}, fmt.Errorf("unknown format %s", ref.Format)
}

// specOps reads a service's specs, keeping the paths each one's include selects and applying its origin.
func specOps(name string, src source, lock lockFile) (parsed, error) {
	var out parsed
	for _, ref := range src.Specs {
		e, err := lock.entry(name, ref)
		if err != nil {
			return out, err
		}
		p, err := read(ref, e)
		if err != nil {
			return out, err
		}
		include := regexp.MustCompile(ref.Include)
		for _, o := range p.Ops {
			if !include.MatchString(o.Path) {
				continue
			}
			if ref.Origin != "" {
				o.Origin = ref.Origin
			}
			out.Ops = append(out.Ops, o)
		}
		if out.Auth == nil {
			out.Auth = p.Auth
		}
	}
	return out, nil
}

type drafted struct {
	op     specOp
	effect string
	action string
	scope  obj
	grant  []string
	merged int
}

// segmentsOverlap says whether some request path could match both patterns.
func segmentsOverlap(a, b string) bool {
	as, bs := strings.Split(a, "/"), strings.Split(b, "/")
	star := func(s []string) bool { return strings.HasSuffix(s[len(s)-1], "*}") }
	if len(as) != len(bs) && !(star(as) && len(bs) >= len(as)) && !(star(bs) && len(as) >= len(bs)) {
		return false
	}
	for i := 0; i < min(len(as), len(bs)); i++ {
		x, y := as[i], bs[i]
		if strings.HasSuffix(x, "*}") || strings.HasSuffix(y, "*}") {
			return true
		}
		if !segmentOverlap(x, y) {
			return false
		}
	}
	return true
}

func segmentOverlap(x, y string) bool {
	px, sx, okx := paramParts(x)
	py, sy, oky := paramParts(y)
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

func paramParts(s string) (prefix, suffix string, ok bool) {
	i, j := strings.Index(s, "{"), strings.Index(s, "}")
	if i < 0 || j < i {
		return "", "", false
	}
	return s[:i], s[j+1:], true
}

func literals(p string) int {
	n := 0
	for _, s := range strings.Split(p, "/") {
		if !strings.Contains(s, "{") {
			n++
		}
	}
	return n
}

func sameMap(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func bodiesOverlap(a, b string) bool {
	return a == b || a == "any" || b == "any"
}

func overlaps(a, b specOp) bool {
	if a.Method != b.Method || a.Origin != b.Origin || !bodiesOverlap(a.Body, b.Body) ||
		!sameMap(a.Query, b.Query) || !sameMap(a.Headers, b.Headers) || !sameMap(a.Fields, b.Fields) {
		return false
	}
	if a.GraphQL != nil || b.GraphQL != nil {
		return a.GraphQL != nil && b.GraphQL != nil && a.GraphQL[0] == b.GraphQL[0] && a.GraphQL[1] == b.GraphQL[1]
	}
	return segmentsOverlap(a.Path, b.Path)
}

// draftOps drafts every operation, folding each one a more general route would also match into that route,
// since the monitor refuses a request two operations match.
func draftOps(p parsed, ai bool, credQuery string) []drafted {
	var out []drafted
	for _, o := range p.Ops {
		if o.Method == "" || o.Path == "" {
			continue
		}
		o.Method = strings.ToUpper(o.Method)
		d := drafted{op: o, effect: draftEffect(o, ai)}
		d.action = d.effect
		if r := resource(o); d.effect != "read" && r != "" {
			d.action = d.effect + "." + r
		}
		var keys []string
		for _, m := range pathParam.FindAllStringSubmatch(o.Path, -1) {
			name := strings.TrimSuffix(m[1], "*")
			if d.scope.get(name) == nil {
				d.scope = append(d.scope, kv{name, obj{{"from", "path"}, {"at", name}}})
				keys = append(keys, name)
			}
		}
		for _, r := range o.Required {
			if d.scope.get(r.Name) != nil || (r.From == "body" && o.Body != "json") {
				continue
			}
			at := r.Name
			if r.From == "body" || r.From == "argument" {
				at = "/" + r.Name
			}
			spec := obj{{"from", r.From}, {"at", at}}
			if r.Type != "string" {
				spec = append(spec, kv{"type", r.Type})
			}
			d.scope = append(d.scope, kv{r.Name, spec})
			keys = append(keys, r.Name)
		}
		// An approval for something that discloses or pays shows the request; it is limited to the resource it names.
		if o.Body == "json" && slices.Contains([]string{"pay", "publish", "share", "send"}, d.effect) && d.scope.get("request") == nil {
			d.scope = append(d.scope, kv{"request", obj{{"from", "body"}, {"at", ""}, {"type", "object"}}})
			if len(keys) > 0 {
				d.grant = keys
			}
		}
		o.Params = slices.DeleteFunc(o.Params, func(q string) bool { _, ok := o.Query[q]; return ok || q == credQuery })
		d.op = o
		out = append(out, d)
	}
	// The more general of two overlapping routes keeps both effects; the more specific one is dropped.
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if !overlaps(out[i].op, out[j].op) {
				continue
			}
			keep, drop := i, j
			if literals(out[j].op.Path) < literals(out[i].op.Path) {
				keep, drop = j, i
			}
			k, dr := &out[keep], out[drop]
			if slices.Index(effectOrder, dr.effect) < slices.Index(effectOrder, k.effect) {
				k.effect, k.action = dr.effect, dr.action
			}
			for _, q := range dr.op.Params {
				if !slices.Contains(k.op.Params, q) {
					k.op.Params = append(k.op.Params, q)
				}
			}
			k.merged += dr.merged + 1
			out = slices.Delete(out, drop, drop+1)
			if drop == i {
				i--
				break
			}
			j--
		}
	}
	return out
}

func operationObj(d drafted, id string) obj {
	o := d.op
	op := obj{{"id", id}, {"action", d.action}, {"effects", []string{d.effect}}, {"method", o.Method}, {"origin", o.Origin}, {"path", o.Path}}
	if len(o.Query) > 0 {
		op = append(op, kv{"query", o.Query})
	}
	if len(o.Headers) > 0 {
		op = append(op, kv{"headers", o.Headers})
	}
	if len(o.Fields) > 0 {
		op = append(op, kv{"fields", o.Fields})
	}
	if len(o.Params) > 0 && o.GraphQL == nil {
		op = append(op, kv{"params", o.Params})
	}
	if o.Body != "none" {
		op = append(op, kv{"body", o.Body})
	}
	if o.GraphQL != nil {
		op = append(op, kv{"graphql", obj{{"operation", o.GraphQL[0]}, {"field", o.GraphQL[1]}}})
	}
	scope := d.scope
	if scope == nil {
		scope = obj{}
	}
	op = append(op, kv{"scope", scope})
	if d.grant != nil {
		op = append(op, kv{"grant", d.grant})
	}
	return op
}

// opID is the spec's operation id, else method and path; repeats get a numeric suffix.
func opID(d drafted, seen map[string]int) string {
	id := d.op.ID
	if id == "" || d.op.GraphQL == nil && strings.Contains(d.op.ID, " ") && d.op.Summary == d.op.ID {
		id = d.op.Method + " " + d.op.Path
	}
	seen[id]++
	if seen[id] > 1 {
		id = fmt.Sprintf("%s.%d", id, seen[id])
	}
	return id
}

// isAI says whether the service's own node is an AI one; a LangChain loader for a service does not make it one.
func isAI(s *service) bool {
	n := s.Nodes[0]
	return strings.HasPrefix(n.Name, "@n8n/n8n-nodes-langchain") || slices.Contains(n.Categories, "AI")
}

// draftAll writes a draft for every service with a spec and no shipped preset, and the report rows for all of them.
func draftAll(all []*service, only []string) error {
	sources, err := load[map[string]source](sourcesPath)
	if err != nil {
		return err
	}
	lock, err := load[lockFile](lockPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(draftsDir, 0o755); err != nil {
		return err
	}
	var results []result
	for _, s := range all {
		if len(only) > 0 && !slices.Contains(only, s.Name) {
			continue
		}
		src, ok := sources[s.Name]
		r := result{Service: s.Name, Note: src.Note, Effects: map[string]int{}}
		for _, ref := range src.Specs {
			r.Sources = append(r.Sources, ref.Kind+" "+ref.URL)
		}
		switch {
		case !ok:
			r.Status = "no source entry"
		case src.Native != "":
			r.Status = "native " + src.Native
		case len(src.Specs) == 0:
			r.Status = "no spec found"
		default:
			r.Status, r.Ops, r.Merged, r.Matched, r.Missing, r.Adds = draftService(s, src, lock, r.Effects, &r.Note)
		}
		results = append(results, r)
	}
	out, _ := json.MarshalIndent(results, "", "  ")
	return os.WriteFile(filepath.Join(cacheDir, "report.json"), out, 0o644)
}

func draftService(s *service, src source, lock lockFile, effects map[string]int, note *string) (status string, n, merged int, matched, missing, adds []string) {
	p, err := specOps(s.Name, src, lock)
	if err != nil {
		return "spec error: " + err.Error(), 0, 0, nil, nil, nil
	}
	credQuery := ""
	if src.Auth != nil {
		credQuery = src.Auth.Query
	}
	ops := draftOps(p, isAI(s), credQuery)
	for _, d := range ops {
		merged += d.merged
		effects[d.effect]++
	}
	matched, missing = crossCheck(s, ops)
	if src.Preset != "" {
		adds, err = shippedAdds(src.Preset, ops)
		if err != nil {
			return "shipped preset unreadable: " + err.Error(), len(ops), merged, matched, missing, nil
		}
		return "shipped as " + src.Preset, len(ops), merged, matched, missing, adds
	}
	if len(ops) == 0 {
		return "spec has no operations", 0, 0, matched, missing, nil
	}
	var fields, connections obj
	var catNote string
	if src.Specs[0].Format == "botocore" {
		fields, connections = awsCatalog()
	} else {
		fields, connections, catNote = catalogFor(s, src, p, ops)
	}
	if catNote != "" {
		*note = strings.TrimPrefix(*note+"; "+catNote, "; ")
	}
	if fields == nil {
		return "refused: no credential slot", len(ops), merged, matched, missing, nil
	}
	var actions obj
	var opObjs []obj
	seen := map[string]int{}
	for _, d := range ops {
		if actions.get(d.action) == nil {
			title := strings.ToUpper(d.action[:1]) + strings.ReplaceAll(strings.ReplaceAll(d.action[1:], ".", ": "), "_", " ")
			if d.action == "read" {
				title = "Read everything the account can see"
			}
			actions = append(actions, kv{d.action, obj{{"title", title}}})
		}
		opObjs = append(opObjs, operationObj(d, opID(d, seen)))
	}
	slices.SortStableFunc(actions, func(a, b kv) int {
		return strings.Compare(a.K, b.K)
	})
	title := src.Title
	if title == "" {
		title = s.Title
	}
	text := presetText(title, fields, actions, connections, defaults, opObjs)
	if err := os.WriteFile(filepath.Join(draftsDir, s.Name+".json"), []byte(text), 0o644); err != nil {
		return "write failed: " + err.Error(), len(ops), merged, matched, missing, nil
	}
	return "drafted", len(ops), merged, matched, missing, nil
}
