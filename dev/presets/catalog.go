package main

import (
	"fmt"
	"regexp"
	"slices"
	"strings"
)

const (
	exampleOrigin   = "https://example.com"
	microsoftCommon = "login.microsoftonline.com/common/"
	microsoftTenant = "login.microsoftonline.com/{tenant}/"
)

var (
	// n8n injects a credential with an expression such as "=Bearer {{$credentials.apiKey}}".
	credentialRef = regexp.MustCompile(`^=?([^{]*)\{\{\s*\$credentials\??\.(\w+)\s*\}\}$`)
	quotedRef     = regexp.MustCompile(`^=\{\{\s*["'\x60]([^"'\x60]*)["'\x60]\s*\+\s*\$credentials\??\.(\w+)\s*\}\}$`)
	// A credential with several secrets is placed by its API token or key, not a signing key or client secret.
	credentialName = regexp.MustCompile(`(?i)^(api_?)?(key|token|access_?token|api_?token|app_?api_?token)$|^apiKey$`)
	userName       = regexp.MustCompile(`(?i)^(user|username|email|user_?name|account_?sid)$`)
	defaults       = obj{{"contents", "team"}, {"strangers", true}, {"sends", "anyone"}}
)

type slotSpec struct {
	value, header, prefix, query, basic string
}

func valuePath(key string) []string { return []string{"connections", "", "http", "values", key} }

func secretField(key, label string) obj {
	return obj{{"key", key}, {"label", label}, {"secret", true}, {"path", valuePath(key)}}
}

// credentialSlots reads where n8n's authenticate block puts each credential field.
func credentialSlots(c *credential) ([]slotSpec, obj, string) {
	if c.Authenticate == nil {
		return nil, nil, ""
	}
	label := map[string]string{}
	for _, f := range c.Fields {
		label[f.Name] = f.Label
	}
	var slots []slotSpec
	var fields obj
	add := func(name string) string {
		key := snake(name)
		if fields.get(key) == nil {
			fields = append(fields, kv{key, secretField(key, label[name])})
		}
		return key
	}
	p := c.Authenticate.Properties
	if len(p.Body) > 0 {
		return nil, nil, c.Name + " puts the credential in the request body, which no slot supports"
	}
	for _, h := range sortedKeys(p.Headers) {
		tmpl, ok := p.Headers[h].(string)
		if !ok || !strings.Contains(tmpl, "$credentials") {
			continue
		}
		m := credentialRef.FindStringSubmatch(tmpl)
		if m == nil {
			m = quotedRef.FindStringSubmatch(tmpl)
		}
		if m == nil {
			return nil, nil, fmt.Sprintf("%s header %s is an expression no slot can place: %s", c.Name, h, tmpl)
		}
		slots = append(slots, slotSpec{value: add(m[2]), header: h, prefix: m[1]})
	}
	for _, q := range sortedKeys(p.Qs) {
		tmpl, _ := p.Qs[q].(string)
		m := credentialRef.FindStringSubmatch(tmpl)
		if m == nil || m[1] != "" {
			return nil, nil, fmt.Sprintf("%s query %s is an expression no slot can place: %s", c.Name, q, tmpl)
		}
		slots = append(slots, slotSpec{value: add(m[2]), query: q})
	}
	for _, part := range []string{"username", "password"} {
		tmpl, _ := p.Auth[part].(string)
		if tmpl == "" {
			continue
		}
		m := credentialRef.FindStringSubmatch(tmpl)
		if m == nil || m[1] != "" {
			return nil, nil, fmt.Sprintf("%s Basic %s is an expression no slot can place: %s", c.Name, part, tmpl)
		}
		slots = append(slots, slotSpec{value: add(m[2]), basic: map[string]string{"username": "user", "password": "password"}[part]})
	}
	if len(slots) == 0 {
		return nil, nil, ""
	}
	return slots, fields, ""
}

// hintSlots places a credential with no authenticate block where the spec or vendor docs say it goes.
func hintSlots(c *credential, hint *specAuth) ([]slotSpec, obj) {
	if hint == nil || c.Kind != "static" {
		return nil, nil
	}
	var secret, user, label, userLabel string
	for _, f := range c.Fields {
		switch {
		case f.Secret && (secret == "" || hint.Basic && f.Name == "password" || !hint.Basic && credentialName.MatchString(f.Name) && !credentialName.MatchString(secret)):
			secret, label = f.Name, f.Label
		case !f.Secret && userName.MatchString(f.Name):
			user, userLabel = f.Name, f.Label
		}
	}
	if secret == "" {
		return nil, nil
	}
	key := snake(secret)
	fields := obj{{key, secretField(key, label)}}
	switch {
	case hint.Basic && hint.User:
		return []slotSpec{{value: key, basic: "user"}}, fields
	case hint.Basic && user != "":
		u := snake(user)
		return []slotSpec{{value: u, basic: "user"}, {value: key, basic: "password"}}, append(obj{{u, secretField(u, userLabel)}}, fields...)
	case hint.Basic:
		return []slotSpec{{value: key, basic: "password"}}, fields
	case hint.Header != "":
		return []slotSpec{{value: key, header: hint.Header, prefix: hint.Prefix}}, fields
	case hint.Query != "":
		return []slotSpec{{value: key, query: hint.Query}}, fields
	}
	return nil, nil
}

// oauthField signs in with the n8n credential's provider and scopes, using the owner's client.
func oauthField(s *service, c *credential) (obj, string) {
	defaults := map[string]string{}
	for _, f := range c.Fields {
		if d, ok := f.Default.(string); ok {
			defaults[f.Name] = d
		}
	}
	// URLs and scopes are in the oauth block, else in the credential's field defaults; custom scopes default to enabledScopes.
	setting := func(key, field string) string {
		if v, _ := c.OAuth[key].(string); v != "" && !strings.Contains(v, "customScopes") {
			return v
		}
		return defaults[field]
	}
	authURL, tokenURL := setting("authUrl", "authUrl"), setting("accessTokenUrl", "accessTokenUrl")
	scope := setting("scope", "enabledScopes")
	if scope == "" {
		scope = defaults["scope"]
	}
	if strings.Contains(authURL+tokenURL+scope, "{{") || !strings.HasPrefix(authURL, "https://") {
		return nil, c.Name + " builds its OAuth URLs or scopes from an expression; the draft takes a pasted token"
	}
	client := obj{{"client_id", obj{{"key", "client_id"}, {"label", "OAuth client ID"}, {"paths", []any{}}}},
		{"client_secret", obj{{"key", "client_secret"}, {"label", "OAuth client secret"}, {"secret", true}, {"paths", []any{}}}}}
	id, secret := "{client_id}", "{client_secret}"
	switch {
	case strings.Contains(authURL, "accounts.google.com"):
		client, id, secret = nil, "{MONITOR_GOOGLE_CLIENT_ID}", "{MONITOR_GOOGLE_CLIENT_SECRET}"
	case strings.Contains(authURL, microsoftCommon):
		tenant := obj{{"key", "tenant"}, {"label", "Microsoft Entra tenant (ID, domain, organizations or consumers)"}, {"default", "organizations"}, {"paths", []any{}}}
		client = append(obj{{"tenant", tenant}}, client...)
		authURL, tokenURL = strings.Replace(authURL, microsoftCommon, microsoftTenant, 1), strings.Replace(tokenURL, microsoftCommon, microsoftTenant, 1)
	}
	if scope == "" {
		return nil, c.Name + " names no OAuth scopes; the draft takes a pasted token"
	}
	grant := obj{{"auth_url", authURL}, {"token_url", tokenURL}, {"client_id", id}, {"client_secret", secret}, {"scope", strings.ReplaceAll(scope, ",", " ")}}
	return append(client, kv{"token", append(secretField("token", s.Title+" account"), kv{"oauth", grant})}), ""
}

// catalogFor builds the catalog fields and connection from the first of the service's credentials a slot can carry.
func catalogFor(s *service, src source, p parsed, ops []drafted) (fields obj, connections obj, note string) {
	var slots []slotSpec
	var notes []string
	for _, c := range s.Credentials {
		if slices.Contains(sharedCredentials, c.Name) {
			continue
		}
		var n string
		if slots, fields, n = credentialSlots(c); slots == nil {
			hint := src.Auth
			if hint == nil {
				hint = p.Auth
			}
			slots, fields = hintSlots(c, hint)
		}
		if n != "" {
			notes = append(notes, n)
		}
		if slots != nil {
			break
		}
	}
	// A vendor's own OAuth credential wins over one its services share.
	slices.SortStableFunc(s.Credentials, func(a, b *credential) int {
		return compareBool(slices.Contains(sharedCredentials, a.Name), slices.Contains(sharedCredentials, b.Name))
	})
	if slots == nil {
		for _, c := range s.Credentials {
			if c.Kind == "oauth2" && !slices.Contains(genericCredentials, c.Name) {
				f, n := oauthField(s, c)
				if n != "" {
					notes = append(notes, n)
					f = obj{{"token", secretField("token", s.Title+" access token")}}
				}
				fields, slots = f, []slotSpec{{value: "token", header: "Authorization", prefix: "Bearer "}}
				break
			}
		}
	}
	if slots == nil {
		return nil, nil, strings.Join(append(notes, "no credential of this service has a slot"), "; ")
	}
	// One slot per origin and value, limited to the path prefix every operation on that origin shares.
	var origins []string
	prefix := map[string][]string{}
	for _, d := range ops {
		o := d.op.Origin
		segs := strings.Split(d.op.Path, "/")
		if i := slices.IndexFunc(segs, func(s string) bool { return strings.Contains(s, "{") }); i >= 0 {
			segs = segs[:i]
		}
		if !slices.Contains(origins, o) {
			origins = append(origins, o)
			prefix[o] = segs[:len(segs)-1]
		}
		n := 0
		for n < len(prefix[o]) && n < len(segs)-1 && prefix[o][n] == segs[n] {
			n++
		}
		prefix[o] = prefix[o][:n]
	}
	var slotObjs []any
	var originPaths []any
	for _, o := range origins {
		path := strings.Join(prefix[o], "/")
		if path == "" {
			path = "/"
		}
		for _, sl := range slots {
			origin := o
			if o == "{origin}" {
				origin = exampleOrigin
				originPaths = append(originPaths, []any{"connections", "", "http", "slots", len(slotObjs), "origin"})
			}
			slot := obj{{"value", sl.value}, {"origin", origin}, {"path", path}}
			switch {
			case sl.header != "":
				slot = append(slot, kv{"header", sl.header})
				if sl.prefix != "" {
					slot = append(slot, kv{"prefix", sl.prefix})
				}
			case sl.query != "":
				slot = append(slot, kv{"query", sl.query})
			default:
				slot = append(slot, kv{"basic", sl.basic})
			}
			slotObjs = append(slotObjs, slot)
		}
	}
	if len(originPaths) > 0 {
		f := obj{{"key", "origin"}, {"label", fmt.Sprintf("Your %s origin (https://host)", s.Title)}, {"paths", append([]any{[]any{"policy_options", "origin"}}, originPaths...)}}
		fields = append(obj{{"origin", f}}, fields...)
	}
	return fields, obj{{"", obj{{"http", obj{{"slots", slotObjs}}}}}}, strings.Join(notes, "; ")
}

// awsCatalog signs with SigV4 on the owner's regional endpoint, as the aws_s3 preset does.
func awsCatalog() (obj, obj) {
	fields := obj{
		{"origin", obj{{"key", "origin"}, {"label", "Service endpoint (https://service.region.amazonaws.com)"}, {"paths", []any{[]any{"policy_options", "origin"}, []any{"connections", "", "http", "slots", 0, "origin"}}}}},
		{"region", obj{{"key", "region"}, {"label", "Region (e.g. us-east-1)"}, {"path", []any{"connections", "", "http", "slots", 0, "s3", "region"}}}},
		{"access_key", secretField("access_key", "Access key ID")},
		{"secret_key", secretField("secret_key", "Secret access key")},
		{"session_token", secretField("session_token", "Session token (temporary credentials only)")},
	}
	slot := obj{{"value", "access_key"}, {"origin", exampleOrigin}, {"path", "/"}, {"s3", obj{{"region", "us-east-1"}, {"secret", "secret_key"}, {"session", "session_token"}}}}
	return fields, obj{{"", obj{{"http", obj{{"slots", []any{slot}}}}}}}
}

func compareBool(a, b bool) int {
	switch {
	case a == b:
		return 0
	case a:
		return 1
	}
	return -1
}
