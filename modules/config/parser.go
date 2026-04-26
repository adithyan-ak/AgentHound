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
	for name, entry := range serversMap {
		obj, ok := entry.(map[string]any)
		if !ok {
			continue
		}

		sd := ServerDef{Name: name}

		if v, ok := obj["disabled"].(bool); ok {
			sd.Disabled = v
		}

		if aa, ok := obj["autoApprove"].([]any); ok {
			for _, item := range aa {
				if s, ok := item.(string); ok {
					sd.AutoApprove = append(sd.AutoApprove, s)
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

		if envObj, ok := obj["env"].(map[string]any); ok {
			sd.Env = make(map[string]string, len(envObj))
			for k, v := range envObj {
				if s, ok := v.(string); ok {
					sd.Env[k] = s
				}
			}
		}

		if urlVal, ok := obj[urlKey].(string); ok && urlVal != "" {
			sd.Transport = "http"
			sd.URL = urlVal
		} else if cmd, ok := obj["command"].(string); ok && cmd != "" {
			sd.Transport = "stdio"
			sd.Command = cmd
			if args, ok := obj["args"].([]any); ok {
				for _, a := range args {
					if s, ok := a.(string); ok {
						sd.Args = append(sd.Args, s)
					}
				}
			}
		} else {
			continue
		}

		servers = append(servers, sd)
	}

	return servers, nil
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

func getString(m map[string]any, key string) string {
	if v, ok := m[key].(string); ok {
		return strings.TrimSpace(v)
	}
	return ""
}
