package config

import (
	"path/filepath"
	"runtime"
)

type WindsurfParser struct{}

func (p *WindsurfParser) ClientName() string { return "windsurf" }

func (p *WindsurfParser) ConfigPaths(homeDir string) []string {
	switch runtime.GOOS {
	case "darwin", "linux":
		return []string{filepath.Join(homeDir, ".codeium", "windsurf", "mcp_config.json")}
	default:
		return nil
	}
}

func (p *WindsurfParser) Parse(path string, data []byte) (*ParsedConfig, error) {
	m, err := parseJSONToMap(data)
	if err != nil {
		return nil, err
	}

	servers, err := parseMCPServersMap(m, "mcpServers", "serverUrl")
	if err != nil {
		return nil, err
	}

	return &ParsedConfig{Client: p.ClientName(), Path: path, Servers: servers}, nil
}
