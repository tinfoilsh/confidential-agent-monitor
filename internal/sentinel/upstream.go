package sentinel

import (
	"context"
	"encoding/json"
	"log"
	"maps"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Gate screens one call; its error is returned to the caller instead of the result.
type Gate func(ctx context.Context, tool *mcp.Tool, arguments json.RawMessage) error

// Upstream is one connected MCP server reduced to the tools its pin approves.
type Upstream struct {
	// Instructions are the server's, when they match the pin.
	Instructions string
	// Blocked counts the tools that await review because they differ from the pin.
	Blocked int

	name    string
	session *mcp.ClientSession
	tools   []*mcp.Tool
}

func NewUpstream(name string, session *mcp.ClientSession, pin, cur *Snapshot) *Upstream {
	u := &Upstream{name: name, session: session}
	var blocked []string
	u.tools, blocked = pin.approved(cur)
	u.Blocked = len(blocked)
	if len(u.tools) > 0 {
		u.Instructions = cur.Instructions
	}
	for i, original := range u.tools {
		t := *original
		u.tools[i] = &t
		schema, _ := t.InputSchema.(map[string]any)
		if schema["type"] != "object" {
			schema = maps.Clone(schema)
			if schema == nil {
				schema = map[string]any{}
			}
			schema["type"] = "object"
			t.InputSchema = schema
		}
	}
	log.Printf("%s: exposing %d of %d tools", name, len(u.tools), len(cur.Tools))
	return u
}

// Register adds the approved tools to server under prefix; gate screens every call.
func (u *Upstream) Register(server *mcp.Server, prefix string, gate Gate) {
	for _, t := range u.tools {
		exposed := *t
		exposed.Name = prefix + t.Name
		server.AddTool(&exposed, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			if err := gate(ctx, t, req.Params.Arguments); err != nil {
				log.Printf("%s: blocked %s: %v", u.name, t.Name, err)
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "blocked by policy: " + err.Error()}}}, nil
			}
			return u.session.CallTool(ctx, &mcp.CallToolParams{Name: t.Name, Arguments: req.Params.Arguments})
		})
	}
}

func (u *Upstream) Close() error { return u.session.Close() }
