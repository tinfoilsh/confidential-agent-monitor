package web

import (
	"context"
	"encoding/json"
	"net/http"
	"path"
	"strings"

	"github.com/tinfoilsh/confidential-agent-monitor/core/facts"
)

type Slots struct {
	Claim  func(host string, port uint32) int
	Covers func(origin, path string) bool
	Bind   func(r *http.Request, origin string, placeholder func(string) string) (names []string, place func(*http.Request, func(context.Context, string) (string, error)) (*http.Request, error), err error)
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
	return &Setup{Hosts: hosts, Preset: preset.HTTP, title: preset.Title, origin: option.Origin, slots: slots}, nil
}

func (h *Setup) Claim(host string, port uint32) int {
	host = strings.ToLower(host)
	score := h.slots.Claim(host, port)
	if port != httpPort && port != httpsPort {
		return score
	}
	for _, pattern := range h.Hosts {
		if ok, _ := path.Match(pattern, host); ok {
			score = max(score, len(pattern))
		}
	}
	return score
}
