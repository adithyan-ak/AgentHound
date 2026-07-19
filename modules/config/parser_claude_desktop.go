package config

import (
	"path/filepath"
	"runtime"
)

type ClaudeDesktopParser struct{}

func (p *ClaudeDesktopParser) ClientName() string { return "claude-desktop" }

func (p *ClaudeDesktopParser) ConfigPaths(homeDir string) []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{filepath.Join(homeDir, "Library", "Application Support", "Claude", "claude_desktop_config.json")}
	case "linux":
		return []string{filepath.Join(homeDir, ".config", "Claude", "claude_desktop_config.json")}
	case "windows":
		return []string{filepath.Join(homeDir, "AppData", "Roaming", "Claude", "claude_desktop_config.json")}
	default:
		return nil
	}
}

func (p *ClaudeDesktopParser) Parse(path string, data []byte) (*ParsedConfig, error) {
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
