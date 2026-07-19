package config

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/adithyan-ak/agenthound/sdk/common"
)

type ConfigParser interface {
	ClientName() string
	ConfigPaths(homeDir string) []string
	Parse(path string, data []byte) (*ParsedConfig, error)
}

type ParsedConfig struct {
	Client  string
	Path    string
	Servers []ServerDef
}

type ServerDef struct {
	Name        string
	Transport   string // "stdio" or "http"
	Command     string
	Args        []string
	Env         map[string]string
	URL         string
	Headers     map[string]string
	Disabled    bool
	AutoApprove []string
}

func parseMCPServersMap(data map[string]any, rootKey, urlKey string) ([]ServerDef, error) {
	raw, ok := data[rootKey]
	if !ok {
		return nil, nil
	}

	serversMap, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%s: expected object, got %T", rootKey, raw)
	}

	var servers []ServerDef
	malformed := 0
	for name, entry := range serversMap {
		obj, ok := entry.(map[string]any)
		if !ok {
			malformed++
			continue
		}
		sd, usable, entryMalformed := parseServerObject(name, obj, urlKey)
		if entryMalformed {
			malformed++
		}
		if !usable {
			continue
		}
		servers = append(servers, sd)
	}
	if malformed > 0 {
		return servers, malformedServerEntriesError(rootKey, malformed)
	}
	return servers, nil
}

// parseMCPServersList parses the ARRAY form of an MCP server list, where each
// element is an object carrying its own "name" plus the same fields as the
// keyed map form. Augment persists augment.advanced.mcpServers this way.
func parseMCPServersList(list []any, urlKey string) ([]ServerDef, error) {
	var servers []ServerDef
	malformed := 0
	for _, entry := range list {
		obj, ok := entry.(map[string]any)
		if !ok {
			malformed++
			continue
		}
		sd, usable, entryMalformed := parseServerObject(getString(obj, "name"), obj, urlKey)
		if entryMalformed {
			malformed++
		}
		if !usable {
			continue
		}
		servers = append(servers, sd)
	}
	if malformed > 0 {
		return servers, malformedServerEntriesError("mcpServers", malformed)
	}
	return servers, nil
}

func malformedServerEntriesError(scope string, count int) error {
	noun := "entries"
	if count == 1 {
		noun = "entry"
	}
	return fmt.Errorf("%s: %d malformed server %s", scope, count, noun)
}

func parseServerObject(name string, obj map[string]any, urlKey string) (ServerDef, bool, bool) {
	sd := ServerDef{Name: name}
	malformed := strings.TrimSpace(name) == ""

	if raw, present := obj["disabled"]; present {
		value, ok := raw.(bool)
		if !ok {
			malformed = true
		} else {
			sd.Disabled = value
		}
	}
	sd.AutoApprove, malformed = stringSliceField(obj, "autoApprove", malformed)
	sd.Headers, malformed = stringMapField(obj, "headers", malformed)
	sd.Env, malformed = stringMapField(obj, "env", malformed)

	urlValue, urlPresent := obj[urlKey]
	if urlPresent {
		urlText, ok := urlValue.(string)
		if !ok || strings.TrimSpace(urlText) == "" {
			malformed = true
		} else {
			sd.Transport = "http"
			sd.URL = urlText
		}
	}
	if sd.Transport == "" {
		commandValue, commandPresent := obj["command"]
		if commandPresent {
			command, ok := commandValue.(string)
			if !ok || strings.TrimSpace(command) == "" {
				malformed = true
			} else {
				sd.Transport = "stdio"
				sd.Command = command
				sd.Args, malformed = stringSliceField(obj, "args", malformed)
			}
		}
	}
	if sd.Transport == "" {
		return sd, false, true
	}
	return sd, true, malformed
}

func stringSliceField(obj map[string]any, key string, malformed bool) ([]string, bool) {
	raw, present := obj[key]
	if !present {
		return nil, malformed
	}
	values, ok := raw.([]any)
	if !ok {
		return nil, true
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		text, ok := value.(string)
		if !ok {
			malformed = true
			continue
		}
		result = append(result, text)
	}
	return result, malformed
}

func stringMapField(obj map[string]any, key string, malformed bool) (map[string]string, bool) {
	raw, present := obj[key]
	if !present {
		return nil, malformed
	}
	values, ok := raw.(map[string]any)
	if !ok {
		return nil, true
	}
	result := make(map[string]string, len(values))
	for name, value := range values {
		text, ok := value.(string)
		if !ok {
			malformed = true
			continue
		}
		result[name] = text
	}
	return result, malformed
}

func parseJSONToMap(data []byte) (map[string]any, error) {
	data = common.StripJSONComments(data)
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("invalid JSON: %w", err)
	}
	return m, nil
}

func toStringSlice(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	var result []string
	for _, item := range arr {
		if s, ok := item.(string); ok {
			result = append(result, s)
		}
	}
	return result
}

func toStringMap(v any) map[string]string {
	raw, ok := v.(map[string]any)
	if !ok {
		return nil
	}
	result := make(map[string]string, len(raw))
	for key, value := range raw {
		if text, ok := value.(string); ok {
			result[key] = text
		}
	}
	return result
}

func getString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}
