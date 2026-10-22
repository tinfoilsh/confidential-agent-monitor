package web

import (
	"errors"
	"fmt"
	"iter"
	"maps"
	"net/http"
	"net/textproto"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/tinfoilsh/monitor/connector"
	"github.com/tinfoilsh/monitor/connector/credential"
)

// Headers the transport owns; a credential there could change framing or routing.
var reservedHeaders = []string{
	"Host", "Content-Length", "Content-Type", "Content-Encoding", "Transfer-Encoding", "Connection", "Keep-Alive",
	"Te", "Trailer", "Upgrade", "Expect", "Proxy-Authorization", "Proxy-Connection",
}

// FormTypes are the input types a browser may fill with each kind of form value.
var FormTypes = map[string][]string{"username": {"", "text", "email", "tel"}, "password": {"password"}, "otp": {"", "text", "tel", "number"}}

// Credentials are a connection's values and the slots where each may be placed.
type Credentials struct {
	connector.SecretConfig
	Slots []Slot `json:"slots"`
}

func (c *Credentials) Names() iter.Seq[string] { return maps.Keys(c.Secrets) }

func (c *Credentials) Placeholder(value string) string {
	if secret := c.Secrets[value]; secret != nil {
		return secret.Placeholder
	}
	return ""
}

// Validate checks every slot; a browser places values only in form fields, and HTTP never does.
func (c *Credentials) Validate(form bool) error {
	for i := range c.Slots {
		if err := c.Slots[i].validate(); err != nil {
			return err
		}
		if (c.Slots[i].Form != "") != form {
			return fmt.Errorf("slot for %s does not fit this kind of connection", c.Slots[i].Value)
		}
	}
	return nil
}

// Form returns the form slot whose placeholder is the whole text, for a field on origin; text without a placeholder needs none.
func (c *Credentials) Form(origin, text string) (*Slot, error) {
	if !strings.Contains(text, placeholderPrefix) {
		return nil, nil
	}
	for i := range c.Slots {
		if s := &c.Slots[i]; s.Form != "" && s.Origin == origin && text == c.Placeholder(s.Value) {
			return s, nil
		}
	}
	return nil, errors.New("a secret placeholder is outside this connection's declared slots")
}

// A Slot is the one header, query key, Basic field, path segment, SigV4 signature or form field where a value's placeholder may appear.
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
	host    string
	port    uint32
}

func (s *Slot) validate() error {
	if !ValidOrigin(s.Origin) {
		return fmt.Errorf("slot origin %s must be https://host[:port] in lowercase without the default port", s.Origin)
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
	for _, set := range []bool{s.Header != "", s.Query != "", s.Basic != "", s.Segment > 0, s.SigV4 != nil, s.Form != ""} {
		if set {
			places++
		}
	}
	if places != 1 || (s.Basic != "" && s.Basic != "user" && s.Basic != "password") || (s.Prefix != "" && s.Header == "" && s.Segment == 0) {
		return fmt.Errorf("slot for %s must place it in one header, query key, basic field, path segment, SigV4 signature or form field", s.Value)
	}
	if _, ok := FormTypes[s.Form]; s.Form != "" && (!ok || s.Path != "/") {
		return fmt.Errorf("form slot for %s must fill a username, password or otp field and match the whole origin", s.Value)
	}
	if s.SigV4 != nil && (s.SigV4.Service == "" || s.SigV4.Region == "" || s.SigV4.Secret == "") {
		return errors.New("a SigV4 slot needs a service, a region and a secret value")
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

// bind returns the slots this request fills and refuses a placeholder anywhere else.
func (h *HTTP) bind(r *http.Request, origin string) ([]*Slot, error) {
	header := r.Header.Clone()
	query := r.URL.Query()
	segments := strings.Split(r.URL.Path, "/")
	user, pass, basic := r.BasicAuth()
	if basic {
		header.Del(authorization)
	}
	var used []*Slot
	signed := false
	for i := range h.Slots {
		s := &h.Slots[i]
		if s.Origin != origin || !under(r.URL.Path, s.Path) {
			continue
		}
		signed = signed || s.SigV4 != nil
		placeholder := h.Placeholder(s.Value)
		if placeholder == "" {
			continue
		}
		want := s.Prefix + placeholder
		switch {
		case s.Header != "" && slices.Equal(header.Values(s.Header), []string{want}):
			header.Del(s.Header)
		case s.Query != "" && slices.Equal(query[s.Query], []string{want}):
			delete(query, s.Query)
		case s.Segment > 0 && s.Segment < len(segments) && segments[s.Segment] == want:
			segments[s.Segment] = ""
		case basic && s.Basic == "user" && user == want:
			user = ""
		case basic && s.Basic == "password" && pass == want:
			pass = ""
		case s.SigV4 != nil && len(header.Values(authorization)) == 1 && strings.HasPrefix(header.Get(authorization), sigV4Credential+want+"/"):
			if err := streaming(header); err != nil {
				return nil, err
			}
			header.Del(authorization)
			header.Del("X-Amz-Security-Token")
		default:
			continue
		}
		used = append(used, s)
	}
	if signed && (header.Get(authorization) != "" || presigned(query)) {
		return nil, errors.New("this SigV4 origin accepts only the monitor's signature")
	}
	// Diagnose only values left after every allowed placement has been tried.
	// In particular, an alternate prefix for the same header may have matched.
	for _, s := range h.Slots {
		if s.Origin != origin || !under(r.URL.Path, s.Path) {
			continue
		}
		var values []string
		var location string
		switch {
		case s.Header != "":
			values, location = header.Values(s.Header), s.Header+" header"
		case s.Query != "":
			values, location = query[s.Query], "query parameter "+s.Query
		case basic && s.Basic == "user":
			values, location = []string{user}, "Basic authentication username"
		case basic && s.Basic == "password":
			values, location = []string{pass}, "Basic authentication password"
		case s.Segment > 0 && s.Segment < len(segments):
			values, location = []string{segments[s.Segment]}, fmt.Sprintf("path segment %d", s.Segment)
		}
		placeholder := h.Placeholder(s.Value)
		for _, value := range values {
			if placeholder == "" || !strings.Contains(value, placeholderPrefix) {
				continue
			}
			if strings.Contains(value, placeholder) {
				return nil, fmt.Errorf("%s has an incorrectly formatted or repeated credential placeholder. Send exactly one value: %q", location, s.Prefix+placeholder)
			}
			// Placeholder is a public reference. Never quote the supplied value or resolve the secret here.
			return nil, fmt.Errorf("%s contains an unrecognized credential placeholder. Expected %q. Update the client's %s credential placeholder to %q, then restart the client", location, s.Prefix+placeholder, s.Value, placeholder)
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
		if !strings.Contains(fields[field], placeholderPrefix) {
			continue
		}
		for name := range h.Names() {
			if p := h.Placeholder(name); p != "" && strings.Contains(fields[field], p) {
				return nil, fmt.Errorf("%s: credential %s is not allowed for %s%s", field, name, origin, r.URL.Path)
			}
		}
		return nil, fmt.Errorf("%s: this identity has no credential with this placeholder for %s", field, origin)
	}
	return used, nil
}

// under matches whole segments, so /api does not cover /api-other.
func under(path, prefix string) bool {
	return path == prefix || strings.HasPrefix(path, strings.TrimSuffix(prefix, "/")+"/")
}

// substitution resolves credentials for an approved request and writes them only into its bound slots.
type substitution struct {
	base   http.RoundTripper
	values map[string]*credential.Value
	slots  []*Slot
}

func (t substitution) RoundTrip(r *http.Request) (*http.Response, error) {
	if len(t.slots) == 0 {
		return t.base.RoundTrip(r)
	}
	r = r.Clone(r.Context())
	query := r.URL.Query()
	segments := strings.Split(r.URL.Path, "/")
	user, pass, _ := r.BasicAuth()
	var signer *Slot
	var keys aws.Credentials
	for _, s := range t.slots {
		secret, err := t.resolve(r, s.Value)
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
			r.URL.RawQuery = encodeQuery(query)
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
			signer, keys.AccessKeyID = s, secret
			if keys.SecretAccessKey, err = t.resolve(r, s.SigV4.Secret); err != nil {
				return nil, err
			}
			if s.SigV4.Session != "" {
				if keys.SessionToken, err = t.resolve(r, s.SigV4.Session); err != nil {
					return nil, err
				}
			}
		}
	}
	if signer != nil {
		if err := sign(r, keys, signer.SigV4, time.Now()); err != nil {
			return nil, err
		}
	}
	return t.base.RoundTrip(r)
}

func (t substitution) resolve(r *http.Request, name string) (string, error) {
	secret, err := t.values[name].Value(r.Context())
	if err != nil {
		return "", fmt.Errorf("credential %s is unavailable", name)
	}
	return secret, nil
}
