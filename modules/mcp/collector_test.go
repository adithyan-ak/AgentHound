package mcp

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestNewMCPCollectorDefaults(t *testing.T) {
	c := NewMCPCollector()

	if c.concurrency != 5 {
		t.Errorf("default concurrency: got %d, want 5", c.concurrency)
	}
	if c.timeout != 120*time.Second {
		t.Errorf("default timeout: got %v, want 120s", c.timeout)
	}
	if c.initTimeout != 30*time.Second {
		t.Errorf("default initTimeout: got %v, want 30s", c.initTimeout)
	}
	if c.maxItems != defaultMaxItems {
		t.Errorf("default maxItems: got %d, want %d", c.maxItems, defaultMaxItems)
	}
}

func TestNewMCPCollectorOptions(t *testing.T) {
	c := NewMCPCollector(
		WithConcurrency(10),
		WithTimeout(60*time.Second),
		WithInitTimeout(15*time.Second),
		WithMaxItems(5000),
	)

	if c.concurrency != 10 {
		t.Errorf("concurrency: got %d, want 10", c.concurrency)
	}
	if c.timeout != 60*time.Second {
		t.Errorf("timeout: got %v, want 60s", c.timeout)
	}
	if c.initTimeout != 15*time.Second {
		t.Errorf("initTimeout: got %v, want 15s", c.initTimeout)
	}
	if c.maxItems != 5000 {
		t.Errorf("maxItems: got %d, want 5000", c.maxItems)
	}
}

func TestNewMCPCollectorInvalidOptions(t *testing.T) {
	c := NewMCPCollector(
		WithConcurrency(-1),
		WithTimeout(-1),
		WithInitTimeout(-1),
		WithMaxItems(-1),
	)

	if c.concurrency != 5 {
		t.Errorf("expected default concurrency after invalid value, got %d", c.concurrency)
	}
	if c.timeout != 120*time.Second {
		t.Errorf("expected default timeout after invalid value, got %v", c.timeout)
	}
}

func TestMCPCollectorName(t *testing.T) {
	c := NewMCPCollector()
	if c.Name() != "mcp" {
		t.Errorf("expected 'mcp', got %q", c.Name())
	}
}

func TestCollectorInterface(t *testing.T) {
	var _ interface {
		Name() string
	} = NewMCPCollector()
}

func TestComputeServerID(t *testing.T) {
	t.Run("stdio", func(t *testing.T) {
		spec := ServerSpec{
			Transport: "stdio",
			Command:   "npx",
			Args:      []string{"-y", "@modelcontextprotocol/server-postgres"},
		}
		id := computeServerID(spec)

		expected := ingest.ComputeMCPServerID("stdio", "npx", "-y", "@modelcontextprotocol/server-postgres")
		if id != expected {
			t.Errorf("stdio server ID mismatch:\n  got  %s\n  want %s", id, expected)
		}
	})

	t.Run("http", func(t *testing.T) {
		spec := ServerSpec{
			Transport: "http",
			URL:       "http://localhost:8080/mcp",
		}
		id := computeServerID(spec)

		expected := ingest.ComputeMCPServerID("http", "http://localhost:8080/mcp")
		if id != expected {
			t.Errorf("http server ID mismatch:\n  got  %s\n  want %s", id, expected)
		}
	})

	t.Run("arg_order_independent", func(t *testing.T) {
		spec1 := ServerSpec{Transport: "stdio", Command: "npx", Args: []string{"b", "a"}}
		spec2 := ServerSpec{Transport: "stdio", Command: "npx", Args: []string{"a", "b"}}
		if computeServerID(spec1) != computeServerID(spec2) {
			t.Error("server IDs should be equal regardless of arg order")
		}
	})
}

func TestParseConfigForSpecs(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")

	configJSON := `{
		"mcpServers": {
			"postgres": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-postgres"],
				"env": {
					"POSTGRES_URL": "postgres://localhost/test"
				}
			},
			"remote": {
				"url": "http://localhost:3000/mcp",
				"headers": {
					"Authorization": "Bearer token123"
				}
			},
			"disabled-server": {
				"command": "npx",
				"args": ["-y", "disabled-pkg"],
				"disabled": true
			}
		}
	}`

	if err := os.WriteFile(configPath, []byte(configJSON), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	specs, err := parseConfigForSpecs(configPath)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}

	if len(specs) != 2 {
		t.Fatalf("expected 2 specs (disabled excluded), got %d", len(specs))
	}

	foundStdio := false
	foundHTTP := false
	for _, s := range specs {
		if s.Transport == "stdio" && s.Command == "npx" {
			foundStdio = true
			if s.Env["POSTGRES_URL"] != "postgres://localhost/test" {
				t.Error("expected POSTGRES_URL env var")
			}
		}
		if s.Transport == "http" && s.URL == "http://localhost:3000/mcp" {
			foundHTTP = true
			if s.Headers["Authorization"] != "Bearer token123" {
				t.Error("expected Authorization header")
			}
		}
	}

	if !foundStdio {
		t.Error("expected to find stdio server spec")
	}
	if !foundHTTP {
		t.Error("expected to find http server spec")
	}
}

func TestParseConfigForSpecsVSCode(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "settings.json")

	configJSON := `{
		"servers": {
			"my-server": {
				"command": "node",
				"args": ["server.js"]
			}
		}
	}`

	if err := os.WriteFile(configPath, []byte(configJSON), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	specs, err := parseConfigForSpecs(configPath)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}

	if len(specs) != 1 {
		t.Fatalf("expected 1 spec, got %d", len(specs))
	}

	if specs[0].Command != "node" {
		t.Errorf("expected command 'node', got %q", specs[0].Command)
	}
}

func TestParseConfigForSpecsVSCodeDottedKey(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "settings.json")
	configJSON := `{
		"mcp.servers": {
			"puppeteer": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-puppeteer"]
			}
		}
	}`
	if err := os.WriteFile(configPath, []byte(configJSON), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	specs, err := parseConfigForSpecs(configPath)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if len(specs) != 1 {
		t.Fatalf("expected 1 spec, got %d", len(specs))
	}
	if specs[0].Name != "puppeteer" || specs[0].Command != "npx" {
		t.Fatalf("unexpected spec: %+v", specs[0])
	}
}

func TestParseConfigForSpecsVSCodeNestedMCPServers(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "settings.json")
	configJSON := `{
		"mcp": {
			"servers": {
				"sqlite": {
					"command": "uvx",
					"args": ["mcp-server-sqlite"]
				}
			}
		}
	}`
	if err := os.WriteFile(configPath, []byte(configJSON), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	specs, err := parseConfigForSpecs(configPath)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if len(specs) != 1 {
		t.Fatalf("expected 1 spec, got %d", len(specs))
	}
	if specs[0].Name != "sqlite" || specs[0].Command != "uvx" {
		t.Fatalf("unexpected spec: %+v", specs[0])
	}
}

func TestParseConfigForSpecsContinueYAML(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	configYAML := `mcpServers:
  - name: filesystem
    command: npx
    args: ["-y", "@modelcontextprotocol/server-filesystem"]
    env:
      ROOT: /tmp
  - name: remote
    url: https://example.com/mcp
    headers:
      Authorization: Bearer token
`
	if err := os.WriteFile(configPath, []byte(configYAML), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	specs, err := parseConfigForSpecs(configPath)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	if len(specs) != 2 {
		t.Fatalf("expected 2 specs, got %d", len(specs))
	}
	if specs[0].Name != "filesystem" || specs[0].Command != "npx" || specs[0].Env["ROOT"] != "/tmp" {
		t.Fatalf("unexpected first spec: %+v", specs[0])
	}
	if specs[1].Name != "remote" || specs[1].URL != "https://example.com/mcp" ||
		specs[1].Headers["Authorization"] != "Bearer token" {
		t.Fatalf("unexpected second spec: %+v", specs[1])
	}
}

func TestParseConfigForSpecsZed(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "settings.json")

	configJSON := `{
		"context_servers": {
			"my-server": {
				"settings": {
					"command": "python3",
					"args": ["-m", "mcp_server"]
				}
			}
		}
	}`

	if err := os.WriteFile(configPath, []byte(configJSON), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	specs, err := parseConfigForSpecs(configPath)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}

	if len(specs) != 1 {
		t.Fatalf("expected 1 spec, got %d", len(specs))
	}

	if specs[0].Command != "python3" {
		t.Errorf("expected command 'python3', got %q", specs[0].Command)
	}
}

func TestParseConfigForSpecsComments(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.json")

	configJSON := `{
		// This is a comment
		"mcpServers": {
			"server1": {
				"command": "echo",
				"args": ["hello"]
			}
		}
	}`

	if err := os.WriteFile(configPath, []byte(configJSON), 0644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	specs, err := parseConfigForSpecs(configPath)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}

	if len(specs) != 1 {
		t.Fatalf("expected 1 spec, got %d", len(specs))
	}
}

func TestParseConfigForSpecsInvalidFile(t *testing.T) {
	_, err := parseConfigForSpecs("/nonexistent/path.json")
	if err == nil {
		t.Fatal("expected error for nonexistent file")
	}
}

func TestParseConfigForSpecsInvalidJSON(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "bad.json")

	if err := os.WriteFile(configPath, []byte("not json"), 0644); err != nil {
		t.Fatalf("write: %v", err)
	}

	_, err := parseConfigForSpecs(configPath)
	if err == nil {
		t.Fatal("expected error for invalid JSON")
	}
}

func TestMarshalJSON(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		if marshalJSON(nil) != "" {
			t.Error("expected empty string for nil")
		}
	})

	t.Run("map", func(t *testing.T) {
		result := marshalJSON(map[string]any{"type": "object"})
		if result == "" {
			t.Error("expected non-empty JSON string")
		}
	})
}

// claudeDesktopConfigPath returns the per-OS Claude Desktop config path under
// the given home dir, matching modules/config ClaudeDesktopParser.ConfigPaths.
func claudeDesktopConfigPath(homeDir string) string {
	switch runtime.GOOS {
	case "darwin":
		return filepath.Join(homeDir, "Library", "Application Support", "Claude", "claude_desktop_config.json")
	case "linux":
		return filepath.Join(homeDir, ".config", "claude", "claude_desktop_config.json")
	case "windows":
		return filepath.Join(homeDir, "AppData", "Roaming", "Claude", "claude_desktop_config.json")
	default:
		return ""
	}
}

// TestDiscoverRetainsDistinctStdioServers covers Finding 1: two stdio servers
// sharing the same command but with different args must both survive discovery
// dedup (the old key omitted Args and collapsed them into one).
func TestDiscoverRetainsDistinctStdioServers(t *testing.T) {
	home := t.TempDir()
	dest := claudeDesktopConfigPath(home)
	if dest == "" {
		t.Skip("unsupported OS for discovery path")
	}
	t.Setenv("HOME", home)
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}

	configJSON := `{
		"mcpServers": {
			"serverA": {"command": "npx", "args": ["-y", "serverA"]},
			"serverB": {"command": "npx", "args": ["-y", "serverB"]}
		}
	}`
	if err := os.WriteFile(dest, []byte(configJSON), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	specs, err := discoverAllConfigs()
	if err != nil {
		t.Fatalf("discoverAllConfigs: %v", err)
	}

	ids := make(map[string]bool)
	for _, s := range specs {
		ids[computeServerID(s)] = true
	}
	if len(ids) != 2 {
		t.Fatalf("expected 2 distinct stdio servers to survive dedup, got %d (specs=%d)", len(ids), len(specs))
	}
}

// TestDiscoverCoversPreviouslyMissedClient covers Finding 18: discovery now
// shares the config collector's parser path registry, so it picks up clients
// the old hardcoded list missed (here: Zed via ~/.config/zed/settings.json).
func TestDiscoverCoversPreviouslyMissedClient(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("Zed parser only covers darwin/linux")
	}

	home := t.TempDir()
	t.Setenv("HOME", home)

	zedPath := filepath.Join(home, ".config", "zed", "settings.json")
	if err := os.MkdirAll(filepath.Dir(zedPath), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	zedJSON := `{
		"context_servers": {
			"zed-server": {"command": "uvx", "args": ["mcp-server-zed"]}
		}
	}`
	if err := os.WriteFile(zedPath, []byte(zedJSON), 0o644); err != nil {
		t.Fatalf("write zed config: %v", err)
	}

	// Confirm the shared path registry includes the Zed path (the old
	// hardcoded MCP list did not).
	covered := false
	for _, p := range discoveryCandidatePaths(home) {
		if p == zedPath {
			covered = true
			break
		}
	}
	if !covered {
		t.Fatalf("Zed config path %q not in discovery candidates", zedPath)
	}

	specs, err := discoverAllConfigs()
	if err != nil {
		t.Fatalf("discoverAllConfigs: %v", err)
	}
	found := false
	for _, s := range specs {
		if s.Command == "uvx" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected discovery to find the Zed server, but it did not")
	}
}
