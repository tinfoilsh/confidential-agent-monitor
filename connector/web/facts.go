package web

import (
	"net/http"
	"net/url"
)

type HTTPFacts struct {
	WebSocket bool        `json:"websocket,omitempty"`
	Method    string      `json:"method"`
	Origin    string      `json:"origin"`
	Host      string      `json:"host"`
	Path      string      `json:"path"`
	Query     url.Values  `json:"query"`
	Headers   http.Header `json:"headers"`
	Secrets   []string    `json:"secrets"`
	BodyKind  string      `json:"body_kind"`
	Body      any         `json:"body,omitempty"`
	Form      url.Values  `json:"form,omitempty"`
	// HeaderJSON holds single header values that are JSON objects, as Dropbox-API-Arg is.
	HeaderJSON map[string]any `json:"header_json,omitempty"`
}

type GraphQLFacts struct {
	Kind   string              `json:"kind"`
	Fields []GraphQLFieldFacts `json:"fields"`
}

type GraphQLFieldFacts struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments"`
}

type Details struct {
	HTTP    *HTTPFacts    `json:"http,omitempty"`
	GraphQL *GraphQLFacts `json:"graphql,omitempty"`
}
