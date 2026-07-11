package config

import (
	"path/filepath"
)

type CursorParser struct{}

func (p *CursorParser) ClientName() string { return "cursor" }

// ConfigPaths returns Cursor's canonical MCP config locations: the global
// ~/.cursor/mcp.json (all OSes) and the project-scoped .cursor/mcp.json
// (resolved against the current working directory, like ClaudeCodeParser's
// .mcp.json). Cursor documents no per-OS globalStorage location.
func (p *CursorParser) ConfigPaths(homeDir string) []string {
	return []string{
		filepath.Join(homeDir, ".cursor", "mcp.json"),
		filepath.Join(".cursor", "mcp.json"),
	}
}

func (p *CursorParser) Parse(path string, data []byte) (*ParsedConfig, error) {
	m, err := parseJSONToMap(data)
	if err != nil {
		return nil, err
	}

	servers, err := parseMCPServersMap(m, "mcpServers", "url")
	if err != nil {
		return nil, err
	}

	return &ParsedConfig{Client: p.ClientName(), Path: path, Servers: servers}, nil
}
