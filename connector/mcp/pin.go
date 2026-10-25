package mcp

import (
	"context"
	"encoding/json"
	"maps"
	"slices"
	"strings"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const Version = "0.1.0"

type Snapshot struct {
	Instructions string      `json:"instructions,omitempty"`
	Tools        []*sdk.Tool `json:"tools"`
}

func Inspect(ctx context.Context, session *sdk.ClientSession) (*Snapshot, error) {
	snap := &Snapshot{Instructions: session.InitializeResult().Instructions}
	for tool, err := range session.Tools(ctx, nil) {
		if err != nil {
			return nil, err
		}
		snap.Tools = append(snap.Tools, tool)
	}
	slices.SortFunc(snap.Tools, func(a, b *sdk.Tool) int { return strings.Compare(a.Name, b.Name) })
	return snap, nil
}

func canonical(tool *sdk.Tool) string {
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
func (pin *Snapshot) approved(cur *Snapshot) (ok []*sdk.Tool, blocked []string) {
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
