package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"regexp"
	"slices"
	"strings"
)

// A source is a service's entry in sources.json: where its specs are, or the native connector it maps to.
type source struct {
	Title      string            `json:"title,omitempty"`
	Preset     string            `json:"preset,omitempty"`
	Native     string            `json:"native,omitempty"`
	Specs      []specRef         `json:"specs"`
	Auth       *specAuth         `json:"auth,omitempty"`
	Note       string            `json:"note,omitempty"`
	Families   []string          `json:"families,omitempty"`
	Exclusions map[string]string `json:"exclusions,omitempty"`
	Groups     map[string]string `json:"groups,omitempty"` // source operation ID -> resource hierarchy
}

// A specRef is where a spec lives: a file at a GitHub ref, which update pins to a commit, or a plain URL, pinned only by hash.
type specRef struct {
	Format  string `json:"format"`
	GitHub  string `json:"github,omitempty"`
	Ref     string `json:"ref,omitempty"`
	File    string `json:"file,omitempty"`
	URL     string `json:"url,omitempty"`
	Kind    string `json:"kind"`
	Origin  string `json:"origin,omitempty"`
	Path    string `json:"path,omitempty"`
	Include string `json:"include,omitempty"`
}

func (r specRef) source() string {
	if r.GitHub != "" {
		return "github:" + r.GitHub + "@" + r.Ref + ":" + r.File
	}
	return r.URL
}

// The severity order for drafting: the first effect whose words an operation uses wins.
var effectOrder = []string{"pay", "publish", "share", "send", "delete", "admin", "execute", "generate", "write", "read"}

var (
	words       = regexp.MustCompile(`[A-Z]?[a-z]+|[A-Z]+(?:[^a-z]|$)|[0-9]+`)
	version     = regexp.MustCompile(`^(v[0-9][0-9a-z.]*|[0-9]{4}-[0-9]{2}-[0-9]{2}|api|rest|rpc)$`)
	httpMethods = regexp.MustCompile(`^(get|post|put|patch|delete|head|options)$`)
	readVerbs   = regexp.MustCompile(`^(get|list|search|query|find|count|describe|lookup|read|fetch|check|validate|batch_?get|export|download|preview|scan|retrieve|head|exists|test|verify|estimate|calculate)`)
	verbs       = map[string]*regexp.Regexp{
		"pay":      regexp.MustCompile(`^(pay|pays|charge|refund|payout|capture|purchase|transfer)$`),
		"publish":  regexp.MustCompile(`^(publish|unpublish|release|tweet|retweet|broadcast)$`),
		"share":    regexp.MustCompile(`^(share|unshare|invite|grant|revoke)$`),
		"send":     regexp.MustCompile(`^(send|notify|reply|forward|dm|resend|ping|call|dial)$`),
		"delete":   regexp.MustCompile(`^(delete|remove|trash|destroy|purge|erase|empty|clear)$`),
		"execute":  regexp.MustCompile(`^(run|rerun|execute|trigger|invoke|dispatch|deploy|build|exec|eval)$`),
		"generate": regexp.MustCompile(`^(generate|complete|completion|embed|transcribe|translate|predict|infer|rerank|synthesize|summarize|classify|detect|analyze|moderate|extract)$`),
	}
	// Lifecycle verbs execute only on a run, job or build; elsewhere they change state.
	lifecycle = regexp.MustCompile(`^(start|restart|stop|cancel|retry|reboot|resume|pause|abort)$`)
	// A trailing path segment that names an action acts on the collection before it.
	actionSegment = regexp.MustCompile(`^(cancel|confirm|decline|reassign|disconnect|connect|mark|refresh|reschedule|approve|reject|archive|unarchive|close|reopen|merge|lock|unlock|move|copy|rename|restore|assign|unassign|enable|disable|activate|deactivate|send|publish|unpublish|start|stop|restart|retry|resume|pause|abort|run|rerun|execute|trigger|invoke|dispatch|deploy|test|verify|validate|check|import|export|upload|download|accept|transfer|duplicate|clone|sync|subscribe|unsubscribe|follow|unfollow|star|unstar|pin|unpin|mute|unmute|block|unblock|join|leave|invite|share|unshare|revoke|grant|reset|regenerate|rotate|force|save)`)
	nouns         = map[string]*regexp.Regexp{
		"pay":      regexp.MustCompile(`^(payments?|charges?|refunds?|payouts?|transfers?|payment_intents?|captures?|purchases?)$`),
		"share":    regexp.MustCompile(`^(permissions?|acls?|collaborators?|invitations?|invites?|shares?|sharing|shared_links?|links?)$`),
		"send":     regexp.MustCompile(`^(messages?|comments?|replies|reply|mails?|emails?|sms|notifications?|reactions?|chats?|posts?|notes?|tweets?|send_mail|calls?|faxes?)$`),
		"admin":    regexp.MustCompile(`^(members?|memberships?|roles?|settings?|webhooks?|hooks?|keys?|tokens?|secrets?|users?|groups?|teams?|orgs?|organizations?|policies|policy|config|configs?|configuration|billing|subscriptions?|plans?|accounts?|workspaces?|apps?|integrations?|domains?|admins?)$`),
		"execute":  regexp.MustCompile(`^(runs?|jobs?|builds?|pipelines?|executions?|deployments?|dispatches|workflows?|actions?|functions?|invocations?|tasks_run)$`),
		"generate": regexp.MustCompile(`^(completions?|embeddings?|images?|generations?|speech|transcriptions?|translations?|predictions?|responses|audio|videos?|chat_completions?)$`),
	}
)

func tokens(s string) []string {
	var out []string
	for _, w := range words.FindAllString(s, -1) {
		out = append(out, strings.ToLower(strings.TrimRight(w, "_-./")))
	}
	return out
}

// resource is the last literal path segment, else the last tag, as a snake_case action suffix.
func resource(o specOp) string {
	if o.GraphQL != nil {
		return snake(o.GraphQL[1])
	}
	segs := strings.Split(o.Path, "/")
	skipAction := true
	for i := len(segs) - 1; i >= 0; i-- {
		s := segs[i]
		if s == "" || strings.Contains(s, "{") || version.MatchString(strings.ToLower(s)) {
			skipAction = skipAction && s == ""
			continue
		}
		if skipAction && i > 0 && actionSegment.MatchString(strings.ToLower(strings.ReplaceAll(snake(s), "_", ""))) && strings.Contains(o.Path[:strings.LastIndex(o.Path, "/"+s)], "{") {
			skipAction = false
			continue
		}
		s, _, _ = strings.Cut(s, ":")
		s, _, _ = strings.Cut(s, ".")
		return strings.Trim(snake(strings.ReplaceAll(s, "-", "_")), "_")
	}
	if len(o.Tags) > 0 {
		if tag := o.Tags[0]; tag != "do_not_render" {
			return snake(strings.ReplaceAll(tag, " ", "_"))
		}
	}
	return ""
}

// draftEffect picks one effect from the method, the operation's verbs and the resource it acts on.
func draftEffect(o specOp, ai bool) string {
	// Operation ids often name the HTTP method, and RPC paths name the verb in their last segment.
	idWords := slices.DeleteFunc(tokens(o.ID), func(w string) bool { return httpMethods.MatchString(w) })
	if segs := strings.Split(o.Path, "/"); len(segs) > 0 && !strings.Contains(segs[len(segs)-1], "{") {
		idWords = append(idWords, tokens(segs[len(segs)-1])...)
	}
	if o.GraphQL != nil {
		if o.GraphQL[0] == "query" {
			return "read"
		}
	} else if o.Method == "GET" || o.Method == "HEAD" || o.Method == "OPTIONS" {
		return "read"
	}
	if o.Method == "DELETE" {
		return "delete"
	}
	last := ""
	if len(idWords) > 0 {
		last = strings.Join(tokens(lastPart(o.ID)), "_")
	}
	if readVerbs.MatchString(last) && o.Method == "POST" {
		return "read"
	}
	for _, e := range effectOrder {
		if v := verbs[e]; v != nil && slices.ContainsFunc(idWords, v.MatchString) {
			return e
		}
	}
	res := resource(o)
	if slices.ContainsFunc(idWords, lifecycle.MatchString) && nouns["execute"].MatchString(res) {
		return "execute"
	}
	for _, e := range effectOrder {
		if n := nouns[e]; n != nil && n.MatchString(res) {
			// A message, payment or run is the effect only when one is created.
			if (e == "send" || e == "pay" || e == "execute" || e == "generate") && o.Method != "POST" {
				continue
			}
			return e
		}
	}
	if ai && o.Method == "POST" {
		return "generate"
	}
	return "write"
}

func lastPart(id string) string {
	if i := strings.LastIndexAny(id, "./"); i >= 0 {
		return id[i+1:]
	}
	return id
}

// kv keeps JSON members in the order presetText writes them.
type kv struct {
	K string
	V any
}
type obj []kv

func (o obj) get(k string) any {
	for _, e := range o {
		if e.K == k {
			return e.V
		}
	}
	return nil
}

func compact(v any) string {
	switch v := v.(type) {
	case obj:
		var parts []string
		for _, e := range v {
			parts = append(parts, quote(e.K)+": "+compact(e.V))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	case []any:
		var parts []string
		for _, x := range v {
			parts = append(parts, compact(x))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case []string:
		return compact(anys(v))
	case map[string]string:
		var o obj
		for _, k := range slices.Sorted(func(yield func(string) bool) {
			for k := range v {
				if !yield(k) {
					return
				}
			}
		}) {
			o = append(o, kv{k, v[k]})
		}
		return compact(o)
	case string:
		return quote(v)
	default:
		b, _ := json.Marshal(v)
		return string(b)
	}
}

func anys[T any](xs []T) []any {
	out := make([]any, len(xs))
	for i, x := range xs {
		out[i] = x
	}
	return out
}

// quote matches JSON.stringify, which leaves <, > and & unescaped.
func quote(s string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(s)
	return strings.TrimSpace(b.String())
}

// presetText writes a preset as the app's presetText does: one field, action and operation per line.
func presetText(title string, fields, actions obj, connections, defaults any, ops []obj) string {
	lines := func(items []string, indent string) string {
		if len(items) == 0 {
			return "[]"
		}
		return "[\n" + indent + "  " + strings.Join(items, ",\n"+indent+"  ") + "\n" + indent + "]"
	}
	var fs, as, os []string
	for _, f := range fields {
		fs = append(fs, compact(f.V))
	}
	for _, a := range actions {
		as = append(as, quote(a.K)+": "+compact(a.V))
	}
	for _, o := range ops {
		os = append(os, compact(o))
	}
	acts := "{}"
	if len(as) > 0 {
		acts = "{\n      " + strings.Join(as, ",\n      ") + "\n    }"
	}
	return fmt.Sprintf("{\n  \"title\": %s,\n  \"catalog\": {\n    \"group\": \"api\",\n    \"fields\": %s,\n    \"connections\": %s,\n    \"defaults\": %s,\n    \"actions\": %s\n  },\n  \"http\": {\n    \"operations\": %s\n  }\n}\n",
		quote(title), lines(fs, "    "), compact(connections), compact(defaults), acts, lines(os, "    "))
}
