package config

import (
	"path/filepath"
	"runtime"
)

type AugmentParser struct{}

func (p *AugmentParser) ClientName() string { return "augment" }

func (p *AugmentParser) ConfigPaths(homeDir string) []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{filepath.Join(homeDir, "Library", "Application Support", "Code", "User", "settings.json")}
	case "linux":
		return []string{filepath.Join(homeDir, ".config", "Code", "User", "settings.json")}
	default:
		return nil
	}
}

func (p *AugmentParser) Parse(path string, data []byte) (*ParsedConfig, error) {
	m, err := parseJSONToMap(data)
	if err != nil {
		return nil, err
	}

	advanced := p.extractServersMap(m)
	if advanced == nil {
		return &ParsedConfig{Client: p.ClientName(), Path: path}, nil
	}

	// Real Augment persists augment.advanced.mcpServers as a JSON ARRAY (each
	// element carries its own "name"). The object-keyed form only appears in
	// the "Import from JSON" box and the Auggie CLI settings file, so support
	// both shapes.
	var servers []ServerDef
	switch raw := advanced["mcpServers"].(type) {
	case []any:
		servers = parseMCPServersList(raw, "url")
	case map[string]any:
		parsed, err := parseMCPServersMap(advanced, "mcpServers", "url")
		if err != nil {
			return nil, err
		}
		servers = parsed
	}

	return &ParsedConfig{Client: p.ClientName(), Path: path, Servers: servers}, nil
}

func (p *AugmentParser) extractServersMap(m map[string]any) map[string]any {
	// Format 1: dotted key "augment.advanced"
	if raw, ok := m["augment.advanced"]; ok {
		if obj, ok := raw.(map[string]any); ok {
			return obj
		}
	}

	// Format 2: nested "augment" -> "advanced"
	if augRaw, ok := m["augment"]; ok {
		if augObj, ok := augRaw.(map[string]any); ok {
			if raw, ok := augObj["advanced"]; ok {
				if obj, ok := raw.(map[string]any); ok {
					return obj
				}
			}
		}
	}

	return nil
}

var _ ConfigParser = (*AugmentParser)(nil)
