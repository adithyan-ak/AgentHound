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
	if _, ok := m["mcpServers"]; !ok {
		return nil, nil
	}

	servers, err := parseMCPServersMap(m, "mcpServers", "url")
	return &ParsedConfig{Client: p.ClientName(), Path: path, Servers: servers}, err
}
