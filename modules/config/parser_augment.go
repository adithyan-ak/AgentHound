package config

import (
	"fmt"
	"path/filepath"
	"runtime"
)

type AugmentParser struct{}

func (p *AugmentParser) ClientName() string { return "augment" }

func (p *AugmentParser) ConfigPaths(homeDir string) []string {
	paths := []string{filepath.Join(homeDir, ".augment", "settings.json")}
	switch runtime.GOOS {
	case "darwin":
		return append(paths, filepath.Join(homeDir, "Library", "Application Support", "Code", "User", "settings.json"))
	case "linux":
		return append(paths, filepath.Join(homeDir, ".config", "Code", "User", "settings.json"))
	default:
		return paths
	}
}

func (p *AugmentParser) Parse(path string, data []byte) (*ParsedConfig, error) {
	m, err := parseJSONToMap(data)
	if err != nil {
		return nil, err
	}

	advanced, applicable, err := p.extractServersMap(m)
	if err != nil {
		return nil, err
	}
	if !applicable {
		return nil, nil
	}

	// Real Augment persists augment.advanced.mcpServers as a JSON ARRAY (each
	// element carries its own "name"). The object-keyed form only appears in
	// the "Import from JSON" box and the Auggie CLI settings file, so support
	// both shapes.
	var servers []ServerDef
	var parseErr error
	switch raw := advanced["mcpServers"].(type) {
	case []any:
		servers, parseErr = parseMCPServersList(raw, "url")
	case map[string]any:
		servers, parseErr = parseMCPServersMap(advanced, "mcpServers", "url")
	}

	return &ParsedConfig{Client: p.ClientName(), Path: path, Servers: servers}, parseErr
}

func (p *AugmentParser) extractServersMap(m map[string]any) (map[string]any, bool, error) {
	// Augment CLI persists a direct top-level mcpServers map in
	// ~/.augment/settings.json.
	if raw, ok := m["mcpServers"]; ok {
		if _, valid := raw.(map[string]any); !valid {
			return nil, true, fmt.Errorf("mcpServers: expected object, got %T", raw)
		}
		return m, true, nil
	}
	// Format 1: dotted key "augment.advanced"
	if raw, ok := m["augment.advanced"]; ok {
		if obj, ok := raw.(map[string]any); ok {
			return validateAugmentServers(obj)
		}
		return nil, true, fmt.Errorf("augment.advanced: expected object, got %T", raw)
	}

	// Format 2: nested "augment" -> "advanced"
	if augRaw, ok := m["augment"]; ok {
		if augObj, ok := augRaw.(map[string]any); ok {
			if raw, ok := augObj["advanced"]; ok {
				if obj, ok := raw.(map[string]any); ok {
					return validateAugmentServers(obj)
				}
				return nil, true, fmt.Errorf("augment.advanced: expected object, got %T", raw)
			}
			return nil, false, nil
		}
		return nil, true, fmt.Errorf("augment: expected object, got %T", augRaw)
	}

	return nil, false, nil
}

func validateAugmentServers(advanced map[string]any) (map[string]any, bool, error) {
	raw, ok := advanced["mcpServers"]
	if !ok {
		return nil, false, nil
	}
	switch raw.(type) {
	case []any, map[string]any:
		return advanced, true, nil
	default:
		return nil, true, fmt.Errorf("augment.advanced.mcpServers: expected array or object, got %T", raw)
	}
}

var _ ConfigParser = (*AugmentParser)(nil)
