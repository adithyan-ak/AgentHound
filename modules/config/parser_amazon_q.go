package config

import "path/filepath"

type AmazonQParser struct{}

func (p *AmazonQParser) ClientName() string { return "amazon-q" }

func (p *AmazonQParser) ConfigPaths(homeDir string) []string {
	return []string{filepath.Join(homeDir, ".aws", "amazonq", "mcp.json")}
}

func (p *AmazonQParser) Parse(path string, data []byte) (*ParsedConfig, error) {
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
