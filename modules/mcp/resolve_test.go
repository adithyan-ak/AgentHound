package mcp

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestResolveAuthorizationHeaderFromSpecsRequiresExactUniqueURL(t *testing.T) {
	specs := []ServerSpec{
		{Transport: "http", URL: "https://gateway.example/servers/a/mcp", Headers: map[string]string{"Authorization": "Bearer exact"}},
		{Transport: "http", URL: "https://gateway.example/servers/b/mcp", Headers: map[string]string{"Authorization": "Bearer other"}},
	}
	got, found, err := resolveAuthorizationHeaderFromSpecs("https://gateway.example/servers/a/mcp", specs)
	if err != nil {
		t.Fatalf("resolveAuthorizationHeaderFromSpecs: %v", err)
	}
	if !found || got != "Bearer exact" {
		t.Fatalf("header = %q, found=%v", got, found)
	}

	if got, found, err := resolveAuthorizationHeaderFromSpecs("https://gateway.example/servers/a/mcp/", specs); err != nil || found || got != "" {
		t.Fatalf("non-exact URL resolved: header=%q found=%v err=%v", got, found, err)
	}
}

func TestResolveAuthorizationHeaderFromSpecsRejectsConflictingMatches(t *testing.T) {
	specs := []ServerSpec{
		{Transport: "http", URL: "https://gateway.example/mcp", Headers: map[string]string{"Authorization": "Bearer first"}},
		{Transport: "http", URL: "https://gateway.example/mcp", Headers: map[string]string{"authorization": "Bearer second"}},
	}
	_, _, err := resolveAuthorizationHeaderFromSpecs("https://gateway.example/mcp", specs)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "ambiguous") {
		t.Fatalf("error = %v, want ambiguity", err)
	}
}

func TestResolveAuthorizationHeaderFromSpecsRejectsDuplicateCaseVariants(t *testing.T) {
	specs := []ServerSpec{{
		Transport: "http",
		URL:       "https://gateway.example/mcp",
		Headers: map[string]string{
			"Authorization": "Bearer first",
			"authorization": "Bearer second",
		},
	}}
	_, _, err := resolveAuthorizationHeaderFromSpecs("https://gateway.example/mcp", specs)
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "ambiguous") {
		t.Fatalf("error = %v, want ambiguity", err)
	}
}

func TestResolveAuthorizationHeaderFromSpecsIgnoresNonAuthorizationHeaders(t *testing.T) {
	specs := []ServerSpec{{
		Transport: "http",
		URL:       "https://gateway.example/mcp",
		Headers:   map[string]string{"X-Context-Forge-Gateway-Id": "unsafe-routing-override"},
	}}
	got, found, err := resolveAuthorizationHeaderFromSpecs("https://gateway.example/mcp", specs)
	if err != nil || found || got != "" {
		t.Fatalf("header=%q found=%v err=%v", got, found, err)
	}
}

func TestResolveAuthorizationHeaderRejectsConflictsWithinDiscoveredConfig(t *testing.T) {
	home := t.TempDir()
	path := claudeDesktopConfigPath(home)
	if path == "" {
		t.Skip("unsupported OS for client config discovery")
	}
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatalf("mkdir client config: %v", err)
	}
	target := "https://gateway.example/servers/aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa/mcp"
	config := fmt.Sprintf(`{
		"mcpServers": {
			"first": {"url": %q, "headers": {"Authorization": "Bearer first"}},
			"second": {"url": %q, "headers": {"Authorization": "Bearer second"}}
		}
	}`, target, target)
	if err := os.WriteFile(path, []byte(config), 0o600); err != nil {
		t.Fatalf("write client config: %v", err)
	}

	if _, err := ResolveAuthorizationHeader(target); err == nil || !strings.Contains(strings.ToLower(err.Error()), "ambiguous") {
		t.Fatalf("ResolveAuthorizationHeader error = %v, want ambiguity", err)
	}
}

func TestResolveAuthorizationHeaderRejectsConflictsAcrossDiscoveredConfigs(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("secondary client config path is unavailable on this OS")
	}
	home := t.TempDir()
	primaryPath := claudeDesktopConfigPath(home)
	secondaryPath := filepath.Join(home, ".config", "zed", "settings.json")
	t.Setenv("HOME", home)
	for _, path := range []string{primaryPath, secondaryPath} {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("mkdir client config: %v", err)
		}
	}
	target := "https://gateway.example/servers/bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb/mcp"
	primary := fmt.Sprintf(`{
		"mcpServers": {
			"primary": {"url": %q, "headers": {"Authorization": "Bearer primary"}}
		}
	}`, target)
	secondary := fmt.Sprintf(`{
		"context_servers": {
			"secondary": {"url": %q, "headers": {"Authorization": "Bearer secondary"}}
		}
	}`, target)
	if err := os.WriteFile(primaryPath, []byte(primary), 0o600); err != nil {
		t.Fatalf("write primary config: %v", err)
	}
	if err := os.WriteFile(secondaryPath, []byte(secondary), 0o600); err != nil {
		t.Fatalf("write secondary config: %v", err)
	}

	if _, err := ResolveAuthorizationHeader(target); err == nil || !strings.Contains(strings.ToLower(err.Error()), "ambiguous") {
		t.Fatalf("ResolveAuthorizationHeader error = %v, want ambiguity", err)
	}
}
