package config

import "path/filepath"

type KiroParser struct{}

func (p *KiroParser) ClientName() string { return "kiro" }

func (p *KiroParser) ConfigPaths(homeDir string) []string {
	return []string{
		filepath.Join(".kiro", "settings", "mcp.json"),
		filepath.Join(homeDir, ".kiro", "settings", "mcp.json"),
	}
}

func (p *KiroParser) Parse(path string, data []byte) (*ParsedConfig, error) {
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
