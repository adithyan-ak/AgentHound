package config

import (
	"path/filepath"
	"runtime"
)

type VSCodeParser struct{}

func (p *VSCodeParser) ClientName() string { return "vscode" }

func (p *VSCodeParser) ConfigPaths(homeDir string) []string {
	switch runtime.GOOS {
	case "darwin":
		return []string{filepath.Join(homeDir, "Library", "Application Support", "Code", "User", "settings.json")}
	case "linux":
		return []string{filepath.Join(homeDir, ".config", "Code", "User", "settings.json")}
	default:
		return nil
	}
}

func (p *VSCodeParser) Parse(path string, data []byte) (*ParsedConfig, error) {
	m, err := parseJSONToMap(data)
	if err != nil {
		return nil, err
	}

	serversMap := p.extractServersMap(m)
	if serversMap == nil {
		return &ParsedConfig{Client: p.ClientName(), Path: path}, nil
	}

	var servers []ServerDef
	for name, entry := range serversMap {
		obj, ok := entry.(map[string]any)
		if !ok {
			continue
		}

		sd := ServerDef{Name: name}

		if v, ok := obj["disabled"].(bool); ok {
			sd.Disabled = v
		}

		if envObj, ok := obj["env"].(map[string]any); ok {
			sd.Env = make(map[string]string, len(envObj))
			for k, v := range envObj {
				if s, ok := v.(string); ok {
					sd.Env[k] = s
				}
			}
		}

		if hdrs, ok := obj["headers"].(map[string]any); ok {
			sd.Headers = make(map[string]string, len(hdrs))
			for k, v := range hdrs {
				if s, ok := v.(string); ok {
					sd.Headers[k] = s
				}
			}
		}

		typ := getString(obj, "type")
		switch typ {
		case "http":
			sd.Transport = "http"
			sd.URL = getString(obj, "url")
			if sd.URL == "" {
				continue
			}
		case "stdio", "":
			cmd := getString(obj, "command")
			if cmd == "" {
				continue
			}
			sd.Transport = "stdio"
			sd.Command = cmd
			sd.Args = toStringSlice(obj["args"])
		default:
			continue
		}

		servers = append(servers, sd)
	}

	return &ParsedConfig{Client: p.ClientName(), Path: path, Servers: servers}, nil
}

func (p *VSCodeParser) extractServersMap(m map[string]any) map[string]any {
	// Format 1: dotted key "mcp.servers"
	if raw, ok := m["mcp.servers"]; ok {
		if sm, ok := raw.(map[string]any); ok {
			return sm
		}
	}

	// Format 2: nested "mcp" -> "servers"
	if mcpRaw, ok := m["mcp"]; ok {
		if mcpObj, ok := mcpRaw.(map[string]any); ok {
			if raw, ok := mcpObj["servers"]; ok {
				if sm, ok := raw.(map[string]any); ok {
					return sm
				}
			}
		}
	}

	return nil
}

var _ ConfigParser = (*VSCodeParser)(nil)
