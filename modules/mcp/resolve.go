package mcp

import (
	"errors"
	"fmt"
	"strings"
)

// ResolveAuthorizationHeader returns the unique Authorization header configured
// for the exact MCP URL across AgentHound's existing client-config discovery
// paths. It never returns other configured headers because routing headers can
// change which ContextForge tool surface is being observed.
func ResolveAuthorizationHeader(targetURL string) (string, error) {
	specs, err := discoverRawConfigSpecs()
	if err != nil {
		return "", fmt.Errorf("discover MCP client credentials: %w", err)
	}
	header, _, err := resolveAuthorizationHeaderFromSpecs(targetURL, specs)
	return header, err
}

func resolveAuthorizationHeaderFromSpecs(targetURL string, specs []ServerSpec) (string, bool, error) {
	targetURL = strings.TrimSpace(targetURL)
	if targetURL == "" {
		return "", false, errors.New("MCP credential resolution requires an exact target URL")
	}
	var resolved string
	for _, spec := range specs {
		if spec.Transport != "http" || strings.TrimSpace(spec.URL) != targetURL {
			continue
		}
		var candidate string
		for name, value := range spec.Headers {
			if !strings.EqualFold(name, "Authorization") {
				continue
			}
			value = strings.TrimSpace(value)
			if strings.ContainsAny(value, "\r\n") {
				return "", false, errors.New("configured MCP Authorization header contains prohibited control characters")
			}
			if value == "" {
				continue
			}
			if candidate != "" && candidate != value {
				return "", false, fmt.Errorf("ambiguous MCP Authorization headers within one config entry for exact URL %q", targetURL)
			}
			candidate = value
		}
		if candidate == "" {
			continue
		}
		if resolved != "" && resolved != candidate {
			return "", false, fmt.Errorf("ambiguous MCP Authorization headers for exact URL %q", targetURL)
		}
		resolved = candidate
	}
	return resolved, resolved != "", nil
}
