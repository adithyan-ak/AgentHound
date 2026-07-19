package config

import (
	"fmt"
	"path/filepath"
	"runtime"
)

type VSCodeParser struct{}

func (p *VSCodeParser) ClientName() string { return "vscode" }

func (p *VSCodeParser) ConfigPaths(homeDir string) []string {
	// The dedicated mcp.json (top-level "servers") is VS Code's documented,
	// primary MCP location: project-scoped .vscode/mcp.json (resolved against
	// CWD, like other project parsers) and the user-profile mcp.json. The
	// legacy settings.json ("mcp.servers") is also scanned for older setups.
	paths := []string{filepath.Join(".vscode", "mcp.json")}
	switch runtime.GOOS {
	case "darwin":
		paths = append(paths,
			filepath.Join(homeDir, "Library", "Application Support", "Code", "User", "mcp.json"),
			filepath.Join(homeDir, "Library", "Application Support", "Code", "User", "settings.json"),
		)
	case "linux":
		paths = append(paths,
			filepath.Join(homeDir, ".config", "Code", "User", "mcp.json"),
			filepath.Join(homeDir, ".config", "Code", "User", "settings.json"),
		)
	}
	return paths
}

func (p *VSCodeParser) Parse(path string, data []byte) (*ParsedConfig, error) {
	m, err := parseJSONToMap(data)
	if err != nil {
		return nil, err
	}

	serversMap, applicable, err := p.extractServersMap(m)
	if err != nil {
		return nil, err
	}
	if !applicable {
		return nil, nil
	}

	var servers []ServerDef
	malformed := 0
	for name, entry := range serversMap {
		obj, ok := entry.(map[string]any)
		if !ok {
			malformed++
			continue
		}
		sd, usable, entryMalformed := parseServerObject(name, obj, "url")
		typ := getString(obj, "type")
		if rawType, present := obj["type"]; present {
			if _, ok := rawType.(string); !ok {
				entryMalformed = true
			}
		}
		switch typ {
		case "http":
			if sd.Transport != "http" {
				usable, entryMalformed = false, true
			}
		case "stdio":
			if sd.Transport != "stdio" {
				usable, entryMalformed = false, true
			}
		case "":
			// Legacy settings omitted type; the observed endpoint still
			// determines whether this is HTTP or stdio.
		default:
			usable, entryMalformed = false, true
		}
		if entryMalformed {
			malformed++
		}
		if usable {
			servers = append(servers, sd)
		}
	}
	var parseErr error
	if malformed > 0 {
		parseErr = malformedServerEntriesError("servers", malformed)
	}
	return &ParsedConfig{Client: p.ClientName(), Path: path, Servers: servers}, parseErr
}

func (p *VSCodeParser) extractServersMap(m map[string]any) (map[string]any, bool, error) {
	// Format 1: top-level "servers" (the dedicated .vscode/mcp.json and
	// user-profile mcp.json format; VS Code uses "servers", not "mcpServers")
	if raw, ok := m["servers"]; ok {
		if sm, ok := raw.(map[string]any); ok {
			return sm, true, nil
		}
		return nil, true, fmt.Errorf("servers: expected object, got %T", raw)
	}

	// Format 2: dotted key "mcp.servers"
	if raw, ok := m["mcp.servers"]; ok {
		if sm, ok := raw.(map[string]any); ok {
			return sm, true, nil
		}
		return nil, true, fmt.Errorf("mcp.servers: expected object, got %T", raw)
	}

	// Format 3: nested "mcp" -> "servers"
	if mcpRaw, ok := m["mcp"]; ok {
		mcpObj, ok := mcpRaw.(map[string]any)
		if !ok {
			return nil, true, fmt.Errorf("mcp: expected object, got %T", mcpRaw)
		}
		raw, ok := mcpObj["servers"]
		if !ok {
			return nil, false, nil
		}
		if sm, ok := raw.(map[string]any); ok {
			return sm, true, nil
		}
		return nil, true, fmt.Errorf("mcp.servers: expected object, got %T", raw)
	}

	return nil, false, nil
}

var _ ConfigParser = (*VSCodeParser)(nil)
