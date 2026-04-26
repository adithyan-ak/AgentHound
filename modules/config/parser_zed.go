package config

import (
	"fmt"
	"path/filepath"
	"runtime"
)

type ZedParser struct{}

func (p *ZedParser) ClientName() string { return "zed" }

func (p *ZedParser) ConfigPaths(homeDir string) []string {
	switch runtime.GOOS {
	case "darwin", "linux":
		return []string{filepath.Join(homeDir, ".config", "zed", "settings.json")}
	default:
		return nil
	}
}

func (p *ZedParser) Parse(path string, data []byte) (*ParsedConfig, error) {
	m, err := parseJSONToMap(data)
	if err != nil {
		return nil, err
	}

	raw, ok := m["context_servers"]
	if !ok {
		return &ParsedConfig{Client: p.ClientName(), Path: path}, nil
	}

	serversMap, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("context_servers: expected object, got %T", raw)
	}

	var servers []ServerDef
	for name, entry := range serversMap {
		obj, ok := entry.(map[string]any)
		if !ok {
			continue
		}

		sd := ServerDef{Name: name}

		if urlVal, ok := obj["url"].(string); ok && urlVal != "" {
			sd.Transport = "http"
			sd.URL = urlVal
		} else if cmd, ok := obj["command"].(string); ok && cmd != "" {
			sd.Transport = "stdio"
			sd.Command = cmd
			sd.Args = toStringSlice(obj["args"])
		} else {
			continue
		}

		servers = append(servers, sd)
	}

	return &ParsedConfig{Client: p.ClientName(), Path: path, Servers: servers}, nil
}
