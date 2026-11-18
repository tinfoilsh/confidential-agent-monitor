package slots

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/tinfoilsh/confidential-agent-monitor/core/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

const (
	httpsPort     = 443
	httpPort      = 80
	authorization = "Authorization"

	OAuthAuthorize = "authorize"
	OAuthToken     = "token"
	oauthLifetime  = time.Hour
)

var reservedHeaders = []string{
	"Host", "Content-Length", "Content-Type", "Content-Encoding", "Transfer-Encoding", "Connection", "Keep-Alive",
	"Te", "Trailer", "Upgrade", "Expect", "Proxy-Authorization", "Proxy-Connection",
}

const wildcardOrigin = "https://*."

var wildcardSuffix = regexp.MustCompile(`\A([a-z0-9-]+\.)+[a-z0-9-]+\z`)

var formTypes = map[string][]string{"username": {"", "text", "email", "tel"}, "password": {"password"}, "otp": {"", "text", "tel", "number"}}

type Slot struct {
	Value   string `json:"value"`
	Origin  string `json:"origin"`
	Path    string `json:"path,omitempty"`
	Header  string `json:"header,omitempty"`
	Prefix  string `json:"prefix,omitempty"`
	Query   string `json:"query,omitempty"`
	Basic   string `json:"basic,omitempty"`
	Segment int    `json:"segment,omitempty"`
	SigV4   *SigV4 `json:"sigv4,omitempty"`
	Form    string `json:"form,omitempty"`
	OAuth   string `json:"oauth,omitempty"`
	host    string
	port    uint32
}

type Set struct {
	slots []Slot
	Options
}

type Options struct {
	Form          bool
	Prefix        string
	MaxSignedBody int64
}

func Parse(raw json.RawMessage, o Options) (Set, error) {
	var slots []Slot
	if len(raw) != 0 {
		if err := facts.DecodeNumbers(raw, &slots); err != nil {
			return Set{}, err
		}
	}
	return New(slots, o)
}

func New(slots []Slot, o Options) (Set, error) {
	s := Set{slices.Clone(slots), o}
	for i := range s.slots {
		if err := s.slots[i].validate(); err != nil {
			return Set{}, err
		}
		if (s.slots[i].Form != "") != o.Form {
			return Set{}, fmt.Errorf("slot for %s does not fit this kind of service", s.slots[i].Value)
		}
	}
	return s, nil
}

func (s Set) MarshalJSON() ([]byte, error) { return json.Marshal(s.slots) }

func (s Set) Len() int { return len(s.slots) }

func (s Set) Names() []string {
	names := []string{}
	for _, slot := range s.slots {
		names = append(names, slot.Value)
		if slot.SigV4 != nil && slot.SigV4.Secret != "" {
			names = append(names, slot.SigV4.Secret)
			if slot.SigV4.Session != "" {
				names = append(names, slot.SigV4.Session)
			}
		}
	}
	slices.Sort(names)
	return slices.Compact(names)
}

func (s Set) Claim(target connector.Target) int {
	host := strings.ToLower(target.Host)
	score := -1
	for _, slot := range s.slots {
		if slot.host == host && slot.port == target.Port {
			score = len(host)
		} else if target.Port == httpsPort && slot.serves("https://"+host) {
			score = max(score, len(strings.TrimPrefix(slot.Origin, wildcardOrigin)))
		}
	}
	return score
}

func (s Set) Covers(origin, path string) bool {
	return slices.ContainsFunc(s.slots, func(slot Slot) bool { return slot.OAuth == "" && slot.serves(origin) && under(path, slot.Path) })
}

func (s *Slot) serves(origin string) bool {
	suffix, wildcard := strings.CutPrefix(s.Origin, wildcardOrigin)
	return origin == s.Origin || wildcard && strings.HasPrefix(origin, "https://") && strings.HasSuffix(origin, "."+suffix) && len(origin) >= len(s.Origin)
}

func (s Set) Form(origin, text string, placeholder func(string) string) (name, field string, inputTypes []string, err error) {
	if !strings.Contains(text, s.Prefix) {
		return "", "", nil, nil
	}
	for _, slot := range s.slots {
		if slot.Form != "" && slot.Origin == origin && text == placeholder(slot.Value) {
			return slot.Value, slot.Form, formTypes[slot.Form], nil
		}
	}
	return "", "", nil, errors.New("a secret placeholder is outside this service's declared slots")
}

func (s *Slot) validate() error {
	if !ValidOrigin(s.Origin) {
		return fmt.Errorf("slot origin %s must be https://host[:port] in lowercase without the default port", s.Origin)
	}
	if suffix, wildcard := strings.CutPrefix(s.Origin, wildcardOrigin); wildcard && (s.Form != "" || s.OAuth != "" || !wildcardSuffix.MatchString(suffix)) || !wildcard && strings.Contains(s.Origin, "*") {
		return fmt.Errorf("slot origin %s may only use * as the first label of a domain with at least two more, without a port, form field or OAuth endpoint", s.Origin)
	}
	u, _ := url.Parse(s.Origin)
	s.host, s.port = u.Hostname(), httpsPort
	if p := u.Port(); p != "" {
		n, err := strconv.ParseUint(p, 10, 16)
		if err != nil || n == 0 || n == httpPort {
			return fmt.Errorf("slot origin %s has an unusable port", s.Origin)
		}
		s.port = uint32(n)
	}
	if s.Path == "" {
		s.Path = "/"
	}
	if s.Value == "" || !strings.HasPrefix(s.Path, "/") {
		return errors.New("a slot needs a value and an absolute path")
	}
	places := 0
	for _, set := range []bool{s.Header != "", s.Query != "", s.Basic != "", s.Segment > 0, s.SigV4 != nil, s.Form != "", s.OAuth != ""} {
		if set {
			places++
		}
	}
	if places != 1 || (s.Basic != "" && s.Basic != "user" && s.Basic != "password") || (s.Prefix != "" && s.Header == "" && s.Segment == 0) ||
		!slices.Contains([]string{"", OAuthAuthorize, OAuthToken}, s.OAuth) {
		return fmt.Errorf("slot for %s must place it in one header, query key, basic field, path segment, SigV4 signature, form field or OAuth endpoint", s.Value)
	}
	if _, ok := formTypes[s.Form]; s.Form != "" && (!ok || s.Path != "/") {
		return fmt.Errorf("form slot for %s must fill a username, password or otp field and match the whole origin", s.Value)
	}
	if s.SigV4 != nil && s.SigV4.Secret == "" && s.SigV4.Session != "" {
		return errors.New("a SigV4 slot with a session value needs a secret value")
	}
	if s.Header != "" {
		s.Header = textproto.CanonicalMIMEHeaderKey(s.Header)
		if slices.Contains(reservedHeaders, s.Header) {
			return fmt.Errorf("header %s cannot carry a credential", s.Header)
		}
	}
	return nil
}

func ValidOrigin(origin string) bool {
	u, err := url.Parse(origin)
	return err == nil && u.Scheme == "https" && u.Host != "" && u.User == nil && u.Path == "" && u.RawQuery == "" && u.Fragment == "" &&
		u.Host == strings.ToLower(u.Host) && u.Port() != "443" && !strings.HasSuffix(origin, ":")
}

func (s Set) Bind(r *http.Request, origin string, placeholder func(string) string) ([]string, func(*http.Request, func(context.Context, string) (string, error)) (*http.Request, error), error) {
	header := r.Header.Clone()
	query := r.URL.Query()
	segments := strings.Split(r.URL.Path, "/")
	user, pass, basic := r.BasicAuth()
	if basic {
		header.Del(authorization)
	}
	var used []*Slot
	signed := false
	for i := range s.slots {
		slot := &s.slots[i]
		if !slot.serves(origin) || !under(r.URL.Path, slot.Path) {
			continue
		}
		signed = signed || slot.SigV4 != nil
		value := placeholder(slot.Value)
		if value == "" {
			continue
		}
		want := slot.Prefix + value
		switch {
		case slot.Header != "" && slices.Equal(header.Values(slot.Header), []string{want}):
			header.Del(slot.Header)
		case slot.Query != "" && slices.Equal(query[slot.Query], []string{want}):
			delete(query, slot.Query)
		case slot.Segment > 0 && slot.Segment < len(segments) && segments[slot.Segment] == want:
			segments[slot.Segment] = ""
		case basic && slot.Basic == "user" && user == want:
			user = ""
		case basic && slot.Basic == "password" && pass == want:
			pass = ""
		case slot.SigV4 != nil && len(header.Values(authorization)) == 1 && strings.HasPrefix(header.Get(authorization), sigV4Credential+want+"/"):
			if err := streaming(header); err != nil {
				return nil, nil, err
			}
			sig, err := slot.SigV4.scoped(strings.TrimPrefix(header.Get(authorization), sigV4Credential+want+"/"))
			if err != nil {
				return nil, nil, err
			}
			bound := *slot
			bound.SigV4, slot = sig, &bound
			header.Del(authorization)
			header.Del("X-Amz-Security-Token")
		default:
			continue
		}
		used = append(used, slot)
	}
	if signed && (header.Get(authorization) != "" || presigned(query)) {
		return nil, nil, errors.New("this SigV4 origin accepts only the signature its slot places")
	}
	for _, slot := range s.slots {
		if !slot.serves(origin) || !under(r.URL.Path, slot.Path) {
			continue
		}
		var values []string
		var location string
		switch {
		case slot.Header != "":
			values, location = header.Values(slot.Header), slot.Header+" header"
		case slot.Query != "":
			values, location = query[slot.Query], "query parameter "+slot.Query
		case basic && slot.Basic == "user":
			values, location = []string{user}, "Basic authentication username"
		case basic && slot.Basic == "password":
			values, location = []string{pass}, "Basic authentication password"
		case slot.Segment > 0 && slot.Segment < len(segments):
			values, location = []string{segments[slot.Segment]}, fmt.Sprintf("path segment %d", slot.Segment)
		}
		value := placeholder(slot.Value)
		for _, v := range values {
			if value == "" || !strings.Contains(v, s.Prefix) {
				continue
			}
			if strings.Contains(v, value) {
				return nil, nil, fmt.Errorf("%s has an incorrectly formatted or repeated credential placeholder. Send exactly one value: %q", location, slot.Prefix+value)
			}
			return nil, nil, fmt.Errorf("%s contains an unrecognized credential placeholder. Expected %q. Update the client's %s credential placeholder to %q, then restart the client", location, slot.Prefix+value, slot.Value, value)
		}
	}
	fields := map[string]string{"Basic authentication username": user, "Basic authentication password": pass}
	for i, segment := range segments {
		fields[fmt.Sprintf("path segment %d", i)] = segment
	}
	for key, entries := range query {
		fields["query parameter "+key] = strings.Join(append(entries, key), " ")
	}
	for key, entries := range header {
		fields[key+" header"] = strings.Join(append(entries, strings.ToLower(key)), " ")
	}
	for _, field := range slices.Sorted(maps.Keys(fields)) {
		if !strings.Contains(fields[field], s.Prefix) {
			continue
		}
		for _, name := range s.Names() {
			if p := placeholder(name); p != "" && strings.Contains(fields[field], p) {
				return nil, nil, fmt.Errorf("%s: credential %s is not allowed for %s%s", field, name, origin, r.URL.Path)
			}
		}
		return nil, nil, fmt.Errorf("%s: this identity has no credential with this placeholder for %s", field, origin)
	}
	var names []string
	for _, slot := range used {
		if r.Header["Upgrade"] != nil && strings.HasPrefix(slot.Header, "Sec-Websocket-") {
			return nil, nil, errors.New("WebSocket negotiation headers cannot carry credentials")
		}
		names = append(names, slot.Value)
	}
	return names, func(r *http.Request, value func(context.Context, string) (string, error)) (*http.Request, error) {
		return place(r, used, value, s.MaxSignedBody)
	}, nil
}

// Answer serves a client that signs in to the credential's provider itself, and gives it the placeholder as its tokens.
func (s Set) Answer(r *http.Request, origin string, form url.Values, placeholder func(string) string) http.HandlerFunc {
	query := r.URL.Query()
	for _, slot := range s.slots {
		value := placeholder(slot.Value)
		if slot.OAuth == "" || slot.Origin != origin || !under(r.URL.Path, slot.Path) || value == "" {
			continue
		}
		redirect, err := url.Parse(query.Get("redirect_uri"))
		switch {
		case slot.OAuth == OAuthAuthorize && r.Method == http.MethodGet && query.Get("response_type") == "code" && err == nil &&
			(redirect.Hostname() == "localhost" || net.ParseIP(redirect.Hostname()).IsLoopback()):
			return func(w http.ResponseWriter, r *http.Request) {
				answer := redirect.Query()
				answer.Set("code", value)
				answer.Set("state", query.Get("state"))
				redirect.RawQuery = answer.Encode()
				http.Redirect(w, r, redirect.String(), http.StatusFound)
			}
		case slot.OAuth == OAuthToken && r.Method == http.MethodPost && cmp.Or(form.Get("code"), form.Get("refresh_token")) == value:
			return func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(map[string]any{"access_token": value, "refresh_token": value, "token_type": "Bearer", "expires_in": int(oauthLifetime.Seconds())})
			}
		}
	}
	return nil
}

func under(path, prefix string) bool {
	return path == prefix || strings.HasPrefix(path, strings.TrimSuffix(prefix, "/")+"/")
}

func place(r *http.Request, slots []*Slot, value func(context.Context, string) (string, error), maxSigned int64) (*http.Request, error) {
	if len(slots) == 0 {
		return r, nil
	}
	resolve := func(name string) (string, error) {
		secret, err := value(r.Context(), name)
		if err != nil {
			return "", fmt.Errorf("credential %s is unavailable", name)
		}
		return secret, nil
	}
	r = r.Clone(r.Context())
	query := r.URL.Query()
	segments := strings.Split(r.URL.Path, "/")
	user, pass, _ := r.BasicAuth()
	var signer *Slot
	var keys aws.Credentials
	for _, s := range slots {
		secret, err := resolve(s.Value)
		if err != nil {
			return nil, err
		}
		placed := s.Prefix + secret
		if s.Basic == "user" && strings.Contains(secret, ":") {
			return nil, fmt.Errorf("credential %s contains a Basic username separator", s.Value)
		}
		if strings.ContainsFunc(placed, func(c rune) bool { return c < ' ' || c == 0x7f }) || (s.Segment > 0 && (url.PathEscape(placed) != placed || placed == "" || placed == "." || placed == "..")) {
			return nil, fmt.Errorf("credential %s cannot be placed in its slot", s.Value)
		}
		switch {
		case s.Header != "":
			r.Header.Set(s.Header, placed)
		case s.Query != "":
			query.Set(s.Query, secret)
			r.URL.RawQuery = strings.ReplaceAll(query.Encode(), "+", "%20")
		case s.Segment > 0:
			segments[s.Segment] = placed
			r.URL.Path = strings.Join(segments, "/")
		case s.Basic == "user":
			user = secret
			r.SetBasicAuth(user, pass)
		case s.Basic == "password":
			pass = secret
			r.SetBasicAuth(user, pass)
		default:
			signer = s
			if keys, err = s.awsKeys(secret, resolve); err != nil {
				return nil, err
			}
		}
	}
	if signer != nil {
		if err := sign(r, keys, signer.SigV4, time.Now(), maxSigned); err != nil {
			return nil, err
		}
	}
	return r, nil
}
