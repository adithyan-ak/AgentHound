package config

import "path/filepath"

type ClaudeCodeParser struct{}

func (p *ClaudeCodeParser) ClientName() string { return "claude-code" }

func (p *ClaudeCodeParser) ConfigPaths(homeDir string) []string {
	return []string{
		filepath.Join(homeDir, ".claude.json"),
		".mcp.json",
	}
}

func (p *ClaudeCodeParser) Parse(path string, data []byte) (*ParsedConfig, error) {
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
