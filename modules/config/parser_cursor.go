package config

import (
	"path/filepath"
	"runtime"
)

type CursorParser struct{}

func (p *CursorParser) ClientName() string { return "cursor" }

func (p *CursorParser) ConfigPaths(homeDir string) []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{filepath.Join(homeDir, "Library", "Application Support", "Cursor", "User", "globalStorage", "cursor.mcp", "mcp.json")}
	case "linux":
		return []string{filepath.Join(homeDir, ".config", "Cursor", "User", "globalStorage", "cursor.mcp", "mcp.json")}
	default:
		return nil
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
