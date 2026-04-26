package config

import (
	"testing"
)

func TestParseMCPServersMap_StdioServer(t *testing.T) {
	data := map[string]any{
		"mcpServers": map[string]any{
			"postgres": map[string]any{
				"command": "npx",
				"args":    []any{"-y", "@modelcontextprotocol/server-postgres"},
				"env": map[string]any{
					"PGHOST": "localhost",
				},
			},
		},
	}

	servers, err := parseMCPServersMap(data, "mcpServers", "url")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}

	s := servers[0]
	if s.Name != "postgres" {
		t.Errorf("name = %q, want %q", s.Name, "postgres")
	}
	if s.Transport != "stdio" {
		t.Errorf("transport = %q, want %q", s.Transport, "stdio")
	}
	if s.Command != "npx" {
		t.Errorf("command = %q, want %q", s.Command, "npx")
	}
	if len(s.Args) != 2 || s.Args[0] != "-y" {
		t.Errorf("args = %v, want [-y @modelcontextprotocol/server-postgres]", s.Args)
	}
	if s.Env["PGHOST"] != "localhost" {
		t.Errorf("env PGHOST = %q, want %q", s.Env["PGHOST"], "localhost")
	}
}

func TestParseMCPServersMap_HTTPServer(t *testing.T) {
	data := map[string]any{
		"mcpServers": map[string]any{
			"remote": map[string]any{
				"url": "https://mcp.example.com/sse",
				"headers": map[string]any{
					"Authorization": "Bearer tok123",
				},
			},
		},
	}

	servers, err := parseMCPServersMap(data, "mcpServers", "url")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}

	s := servers[0]
	if s.Transport != "http" {
		t.Errorf("transport = %q, want %q", s.Transport, "http")
	}
	if s.URL != "https://mcp.example.com/sse" {
		t.Errorf("url = %q", s.URL)
	}
	if s.Headers["Authorization"] != "Bearer tok123" {
		t.Errorf("header Authorization = %q", s.Headers["Authorization"])
	}
}

func TestParseMCPServersMap_AlternateURLKey(t *testing.T) {
	data := map[string]any{
		"mcpServers": map[string]any{
			"wind": map[string]any{
				"serverUrl": "https://wind.example.com",
			},
		},
	}

	servers, err := parseMCPServersMap(data, "mcpServers", "serverUrl")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}
	if servers[0].Transport != "http" {
		t.Errorf("transport = %q, want http", servers[0].Transport)
	}
	if servers[0].URL != "https://wind.example.com" {
		t.Errorf("url = %q", servers[0].URL)
	}
}

func TestParseMCPServersMap_MissingRootKey(t *testing.T) {
	data := map[string]any{
		"otherKey": "value",
	}

	servers, err := parseMCPServersMap(data, "mcpServers", "url")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 0 {
		t.Fatalf("expected 0 servers, got %d", len(servers))
	}
}

func TestParseMCPServersMap_DisabledAndAutoApprove(t *testing.T) {
	data := map[string]any{
		"mcpServers": map[string]any{
			"cline-server": map[string]any{
				"command":     "node",
				"args":        []any{"server.js"},
				"disabled":    true,
				"autoApprove": []any{"tool1", "tool2"},
			},
		},
	}

	servers, err := parseMCPServersMap(data, "mcpServers", "url")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 1 {
		t.Fatalf("expected 1 server, got %d", len(servers))
	}

	s := servers[0]
	if !s.Disabled {
		t.Error("expected Disabled = true")
	}
	if len(s.AutoApprove) != 2 || s.AutoApprove[0] != "tool1" {
		t.Errorf("autoApprove = %v, want [tool1 tool2]", s.AutoApprove)
	}
}

func TestParseMCPServersMap_MultipleServers(t *testing.T) {
	data := map[string]any{
		"mcpServers": map[string]any{
			"alpha": map[string]any{
				"command": "alpha-cmd",
			},
			"beta": map[string]any{
				"url": "https://beta.example.com",
			},
		},
	}

	servers, err := parseMCPServersMap(data, "mcpServers", "url")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 2 {
		t.Fatalf("expected 2 servers, got %d", len(servers))
	}

	byName := make(map[string]ServerDef)
	for _, s := range servers {
		byName[s.Name] = s
	}

	if byName["alpha"].Transport != "stdio" {
		t.Errorf("alpha transport = %q, want stdio", byName["alpha"].Transport)
	}
	if byName["beta"].Transport != "http" {
		t.Errorf("beta transport = %q, want http", byName["beta"].Transport)
	}
}

func TestParseMCPServersMap_SkipsEntryWithNoTransport(t *testing.T) {
	data := map[string]any{
		"mcpServers": map[string]any{
			"empty": map[string]any{
				"env": map[string]any{"FOO": "bar"},
			},
		},
	}

	servers, err := parseMCPServersMap(data, "mcpServers", "url")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(servers) != 0 {
		t.Fatalf("expected 0 servers (skipped), got %d", len(servers))
	}
}

func TestParseMCPServersMap_InvalidRootType(t *testing.T) {
	data := map[string]any{
		"mcpServers": "not-an-object",
	}

	_, err := parseMCPServersMap(data, "mcpServers", "url")
	if err == nil {
		t.Fatal("expected error for non-object root value")
	}
}

func TestParseJSONToMap(t *testing.T) {
	input := []byte(`{
		// single-line comment
		"mcpServers": {
			"test": {
				"command": "echo" /* block comment */
			}
		}
	}`)

	m, err := parseJSONToMap(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, ok := m["mcpServers"]; !ok {
		t.Error("expected mcpServers key after comment stripping")
	}
}

func TestGetString(t *testing.T) {
	m := map[string]any{
		"name":   "  hello  ",
		"count":  42,
		"nested": map[string]any{},
	}

	if got := getString(m, "name"); got != "hello" {
		t.Errorf("got %q, want %q", got, "hello")
	}
	if got := getString(m, "count"); got != "" {
		t.Errorf("got %q for non-string, want empty", got)
	}
	if got := getString(m, "missing"); got != "" {
		t.Errorf("got %q for missing key, want empty", got)
	}
}

func TestToStringSlice(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want int
	}{
		{"valid", []any{"a", "b"}, 2},
		{"nil", nil, 0},
		{"non-slice", "string", 0},
		{"mixed", []any{"a", 42, "b"}, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toStringSlice(tt.in)
			if len(got) != tt.want {
				t.Errorf("len = %d, want %d", len(got), tt.want)
			}
		})
	}
}
