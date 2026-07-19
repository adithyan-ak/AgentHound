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
		return nil, nil
	}

	serversMap, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("context_servers: expected object, got %T", raw)
	}

	var servers []ServerDef
	malformed := 0
	for name, entry := range serversMap {
		obj, ok := entry.(map[string]any)
		if !ok {
			malformed++
			continue
		}
		if settings, present := obj["settings"]; present {
			var valid bool
			obj, valid = settings.(map[string]any)
			if !valid {
				malformed++
				continue
			}
		}
		sd, usable, entryMalformed := parseServerObject(name, obj, "url")
		if entryMalformed {
			malformed++
		}
		if !usable {
			continue
		}
		servers = append(servers, sd)
	}
	var parseErr error
	if malformed > 0 {
		parseErr = malformedServerEntriesError("context_servers", malformed)
	}
	return &ParsedConfig{Client: p.ClientName(), Path: path, Servers: servers}, parseErr
}
