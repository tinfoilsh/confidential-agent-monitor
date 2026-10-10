package sentinel

import (
	"context"
	"encoding/json"
	"maps"
	"net/http"
	"slices"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/auth"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const Version = "0.1.0"

type Remote struct {
	URL     string            `json:"url"`
	Headers map[string]string `json:"headers,omitempty"`
	SSE     bool              `json:"sse,omitempty"`
	Pin     *Snapshot         `json:"pin,omitempty"`
	// OAuth authorizes streamable HTTP requests; the SSE transport has no OAuth support.
	OAuth auth.OAuthHandler `json:"-"`
}

type Snapshot struct {
	Instructions string      `json:"instructions,omitempty"`
	Tools        []*mcp.Tool `json:"tools"`
}

type headerTransport map[string]string

func (h headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for k, v := range h {
		r.Header.Set(k, v)
	}
	return http.DefaultTransport.RoundTrip(r)
}

func Dial(ctx context.Context, remote *Remote) (*mcp.ClientSession, error) {
	client := mcp.NewClient(&mcp.Implementation{Name: "mcp-sentinel", Version: Version}, nil)
	httpClient := &http.Client{Transport: headerTransport(remote.Headers)}
	var transport mcp.Transport = &mcp.StreamableClientTransport{Endpoint: remote.URL, HTTPClient: httpClient, OAuthHandler: remote.OAuth}
	if remote.SSE {
		transport = &mcp.SSEClientTransport{Endpoint: remote.URL, HTTPClient: httpClient}
	}
	return client.Connect(ctx, transport, nil)
}

func Inspect(ctx context.Context, session *mcp.ClientSession) (*Snapshot, error) {
	snap := &Snapshot{Instructions: session.InitializeResult().Instructions}
	for tool, err := range session.Tools(ctx, nil) {
		if err != nil {
			return nil, err
		}
		snap.Tools = append(snap.Tools, tool)
	}
	slices.SortFunc(snap.Tools, func(a, b *mcp.Tool) int { return strings.Compare(a.Name, b.Name) })
	return snap, nil
}

func canonical(tool *mcp.Tool) string {
	b, _ := json.Marshal(tool)
	return string(b)
}

func (pin *Snapshot) pinned() (instructions string, tools map[string]string) {
	tools = map[string]string{}
	if pin == nil {
		return "", tools
	}
	for _, t := range pin.Tools {
		tools[t.Name] = canonical(t)
	}
	return pin.Instructions, tools
}

// approved splits the current tools into those matching the pin exactly and the names of the rest.
func (pin *Snapshot) approved(cur *Snapshot) (ok []*mcp.Tool, blocked []string) {
	instructions, tools := pin.pinned()
	for _, t := range cur.Tools {
		if instructions == cur.Instructions && tools[t.Name] == canonical(t) {
			ok = append(ok, t)
		} else {
			blocked = append(blocked, t.Name)
		}
	}
	return ok, blocked
}

func (pin *Snapshot) Diff(cur *Snapshot) (changes []string) {
	instructions, old := pin.pinned()
	if cur.Instructions != instructions {
		changes = append(changes, "~ instructions:\n"+cur.Instructions)
	}
	for _, t := range cur.Tools {
		pretty, _ := json.MarshalIndent(t, "  ", "  ")
		switch prev, seen := old[t.Name]; {
		case !seen:
			changes = append(changes, "+ "+t.Name+"\n  "+string(pretty))
		case prev != canonical(t):
			changes = append(changes, "~ "+t.Name+"\n  "+string(pretty))
		}
		delete(old, t.Name)
	}
	for _, name := range slices.Sorted(maps.Keys(old)) {
		changes = append(changes, "- "+name)
	}
	return changes
}
