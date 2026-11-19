package web

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/tinfoilsh/confidential-agent-monitor/core/connector"
	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

type Slots interface {
	Claim(connector.Target) int
	Covers(origin, path string) bool
	Bind(r *http.Request, origin string, placeholder func(string) string) (names, query []string, place func(*http.Request, func(context.Context, string) (string, error)) (*http.Request, error), err error)
	Answer(r *http.Request, origin string, form url.Values, placeholder func(string) string) http.HandlerFunc
}

func Parse(config, definition, options json.RawMessage, slots func(json.RawMessage) (Slots, error)) (*Setup, error) {
	var c struct {
		Hosts []string        `json:"hosts"`
		Slots json.RawMessage `json:"slots"`
	}
	if err := facts.DecodeNumbers(config, &c); err != nil {
		return nil, err
	}
	s, err := slots(c.Slots)
	if err != nil {
		return nil, err
	}
	return New(definition, options, c.Hosts, s)
}

func New(definition, options json.RawMessage, hosts []string, slots Slots) (*Setup, error) {
	var preset struct {
		Title string  `json:"title"`
		HTTP  *Preset `json:"http"`
	}
	if len(definition) != 0 {
		if err := json.Unmarshal(definition, &preset); err != nil {
			return nil, err
		}
	}
	var option struct{ Origin string }
	if len(options) != 0 {
		if err := json.Unmarshal(options, &option); err != nil {
			return nil, err
		}
	}
	origin, base := option.Origin, ""
	if u, err := url.Parse(option.Origin); err == nil && u.Host != "" && u.Path != "" {
		origin, base = u.Scheme+"://"+u.Host, strings.TrimSuffix(u.Path, "/")
		if origin+u.Path != option.Origin || canonicalPath(u) != nil || strings.Contains(u.Path, "//") {
			return nil, fmt.Errorf("origin %s may add only a canonical base path", option.Origin)
		}
	}
	return &Setup{Hosts: hosts, Preset: preset.HTTP, title: preset.Title, origin: origin, base: base, slots: slots}, nil
}

func (h *Setup) Claim(target connector.Target) int {
	target.Host = strings.ToLower(target.Host)
	score := h.slots.Claim(target)
	if target.Port != httpPort && target.Port != httpsPort {
		return score
	}
	for _, pattern := range h.Hosts {
		if ok, _ := path.Match(pattern, target.Host); ok {
			score = max(score, len(pattern))
		}
	}
	return score
}
