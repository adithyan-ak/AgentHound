package config

import "path/filepath"

type JetBrainsParser struct{}

func (p *JetBrainsParser) ClientName() string { return "jetbrains" }

func (p *JetBrainsParser) ConfigPaths(homeDir string) []string {
	return []string{
		filepath.Join(".junie", "mcp", "mcp.json"),
		filepath.Join(homeDir, ".junie", "mcp", "mcp.json"),
	}
}

func (p *JetBrainsParser) Parse(path string, data []byte) (*ParsedConfig, error) {
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
