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

	servers, err := parseMCPServersMap(m, "mcpServers", "url")
	if err != nil {
		return nil, err
	}

	return &ParsedConfig{Client: p.ClientName(), Path: path, Servers: servers}, nil
}
