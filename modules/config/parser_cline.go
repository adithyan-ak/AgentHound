package config

import (
	"path/filepath"
	"runtime"
)

type ClineParser struct{}

func (p *ClineParser) ClientName() string { return "cline" }

func (p *ClineParser) ConfigPaths(homeDir string) []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{filepath.Join(homeDir, "Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json")}
	case "linux":
		return []string{filepath.Join(homeDir, ".config", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json")}
	default:
		return nil
	}
}

func (p *ClineParser) Parse(path string, data []byte) (*ParsedConfig, error) {
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
