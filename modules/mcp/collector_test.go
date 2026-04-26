package mcp

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/adithyan-ak/agenthound/internal/model"
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

		expected := model.ComputeMCPServerID("stdio", "npx", "-y", "@modelcontextprotocol/server-postgres")
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

		expected := model.ComputeMCPServerID("http", "http://localhost:8080/mcp")
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
