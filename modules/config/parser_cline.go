package config

import (
	"path/filepath"
	"runtime"
)

type ClineParser struct{}

func (p *ClineParser) ClientName() string { return "cline" }

func (p *ClineParser) ConfigPaths(homeDir string) []string {
	paths := []string{filepath.Join(".cline", "mcp.json")}
	switch runtime.GOOS {
	case "darwin":
		return append(paths, filepath.Join(homeDir, "Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"))
	case "linux":
		return append(paths, filepath.Join(homeDir, ".config", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"))
	default:
		return paths
	}
}

func (p *ClineParser) Parse(path string, data []byte) (*ParsedConfig, error) {
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
