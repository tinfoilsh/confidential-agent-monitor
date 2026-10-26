package mcp

type MCPFacts struct {
	Tool      string `json:"tool"`
	Arguments any    `json:"arguments"`
	ReadOnly  bool   `json:"read_only"`
}

type Details struct {
	MCP *MCPFacts `json:"mcp,omitempty"`
}
