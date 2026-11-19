package main

import (
	"cmp"
	"path"
	"regexp"
	"slices"
	"strings"
)

type source struct {
	Title      string              `json:"title,omitempty"`
	Preset     string              `json:"preset,omitempty"`
	Native     string              `json:"native,omitempty"`
	Specs      []specRef           `json:"specs"`
	Auth       *specAuth           `json:"auth,omitempty"`
	Note       string              `json:"note,omitempty"`
	Families   []string            `json:"families,omitempty"`
	Exclusions map[string]string   `json:"exclusions,omitempty"`
	Groups     map[string]string   `json:"groups,omitempty"`
	Effects    map[string][]string `json:"effects,omitempty"`
	Opaque     []string            `json:"opaque,omitempty"`
	Wildcards  []string            `json:"wildcards,omitempty"`
	Params     []string            `json:"params,omitempty"`
	Encodings  []string            `json:"encodings,omitempty"`
}

type specRef struct {
	Format  string            `json:"format"`
	GitHub  string            `json:"github,omitempty"`
	Ref     string            `json:"ref,omitempty"`
	File    string            `json:"file,omitempty"`
	URL     string            `json:"url,omitempty"`
	Kind    string            `json:"kind"`
	Origin  string            `json:"origin,omitempty"`
	Path    string            `json:"path,omitempty"`
	Include string            `json:"include,omitempty"`
	Group   string            `json:"group,omitempty"`
	Headers map[string]string `json:"headers,omitempty"`
	Pointer string            `json:"pointer,omitempty"`

	Variables map[string]string `json:"variables,omitempty"`
	Captures  map[string]string `json:"captures,omitempty"`
}

func (r specRef) source() string {
	if r.GitHub != "" {
		return "github:" + r.GitHub + "@" + r.Ref + ":" + r.File
	}
	return r.URL
}

var effectOrder = []string{"pay", "publish", "share", "send", "delete", "admin", "execute", "generate", "write", "read", "session"}

var (
	words       = regexp.MustCompile(`[A-Z]?[a-z]+|[A-Z]+(?:[^a-z]|$)|[0-9]+`)
	version     = regexp.MustCompile(`^(v[0-9][0-9a-z.]*|[0-9]{4}-[0-9]{2}-[0-9]{2}|api|rest|rpc)$`)
	httpMethods = regexp.MustCompile(`^(get|post|put|patch|delete|head|options)$`)
	readVerbs   = regexp.MustCompile(`^(get|list|search|query|find|count|describe|lookup|read|batch_?get|download|scan|retrieve|head|exists|estimate|calculate)(_|$)`)
	readSegment = regexp.MustCompile(`^(search|list|lookup|count)$`)
	elasticRead = regexp.MustCompile(`^_(search|count|msearch|mget)$`)
	verbs       = map[string]*regexp.Regexp{
		"pay":      regexp.MustCompile(`^(pay|pays|charge|refund|payout|capture|purchase|transfer)$`),
		"publish":  regexp.MustCompile(`^(publish|unpublish|release|tweet|retweet|broadcast)$`),
		"share":    regexp.MustCompile(`^(share|unshare|invite|grant|revoke)$`),
		"send":     regexp.MustCompile(`^(send|notify|reply|forward|dm|resend|ping|call|dial)$`),
		"delete":   regexp.MustCompile(`^(delete|remove|trash|destroy|purge|erase|empty|clear)$`),
		"execute":  regexp.MustCompile(`^(run|rerun|execute|trigger|invoke|dispatch|deploy|build|exec|eval)$`),
		"generate": regexp.MustCompile(`^(generate|complete|completion|embed|transcribe|translate|predict|infer|rerank|synthesize|summarize|classify|detect|analyze|moderate|extract)$`),
	}
	lifecycle     = regexp.MustCompile(`^(start|restart|stop|cancel|retry|reboot|resume|pause|abort)$`)
	inference     = regexp.MustCompile(`^(completions|embeddings|images|videos|speech|transcriptions|translations|responses|moderations|realtime|batches)$`)
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

func draftEffect(o specOp, ai bool) string {
	idWords := slices.DeleteFunc(tokens(o.ID), func(w string) bool { return o.GraphQL == nil && httpMethods.MatchString(w) })
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
		last = strings.Join(tokens(lastPart(cmp.Or(o.ID, o.Path))), "_")
	}
	seg := path.Base(o.Path)
	if o.Method == "POST" && o.GraphQL == nil && (readVerbs.MatchString(last) || elasticRead.MatchString(seg) || readSegment.MatchString(seg) && readVerbs.MatchString(strings.Join(tokens(o.Summary), "_"))) {
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
			if (e == "send" || e == "pay" || e == "execute" || e == "generate") && o.Method != "POST" {
				continue
			}
			return e
		}
	}
	if ai && o.Method == "POST" && slices.ContainsFunc(strings.Split(o.Path, "/"), inference.MatchString) && !slices.ContainsFunc(idWords, lifecycle.MatchString) {
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
