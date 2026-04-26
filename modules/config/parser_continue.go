package config

import (
	"fmt"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type ContinueParser struct{}

func (p *ContinueParser) ClientName() string { return "continue" }

func (p *ContinueParser) ConfigPaths(homeDir string) []string {
	return []string{filepath.Join(homeDir, ".continue", "config.yaml")}
}

func (p *ContinueParser) Parse(path string, data []byte) (*ParsedConfig, error) {
	var cfg struct {
		MCPServers []struct {
			Name    string            `yaml:"name"`
			Command string            `yaml:"command"`
			Args    []string          `yaml:"args"`
			Env     map[string]string `yaml:"env"`
			URL     string            `yaml:"url"`
		} `yaml:"mcpServers"`
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("invalid YAML: %w", err)
	}

	var servers []ServerDef
	for _, s := range cfg.MCPServers {
		sd := ServerDef{
			Name: s.Name,
			Env:  s.Env,
		}

		if s.URL != "" {
			sd.Transport = "http"
			sd.URL = s.URL
		} else if s.Command != "" {
			sd.Transport = "stdio"
			sd.Command = s.Command
			sd.Args = s.Args
		} else {
			continue
		}

		servers = append(servers, sd)
	}

	return &ParsedConfig{Client: p.ClientName(), Path: path, Servers: servers}, nil
}
