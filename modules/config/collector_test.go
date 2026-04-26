package config

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/collector"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestConfigCollector_Name(t *testing.T) {
	c := NewConfigCollector()
	if c.Name() != "config" {
		t.Fatalf("Name() = %q, want %q", c.Name(), "config")
	}
}

func TestConfigCollector_RegistersAllParsers(t *testing.T) {
	c := NewConfigCollector()
	if len(c.parsers) != 12 {
		t.Fatalf("expected 12 parsers, got %d", len(c.parsers))
	}
}

func TestConfigCollector_CollectSingleConfig(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "claude_desktop_config.json")
	writeJSON(t, configPath, `{
		"mcpServers": {
			"postgres": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-postgres"],
				"env": {
					"PGPASSWORD": "my-secret-password"
				}
			},
			"remote-api": {
				"url": "https://mcp.example.com/api",
				"headers": {
					"Authorization": "Bearer sk-test-12345"
				}
			},
			"disabled-server": {
				"command": "node",
				"args": ["server.js"],
				"disabled": true
			}
		}
	}`)

	c := NewConfigCollector()
	result, err := c.Collect(context.Background(), collector.CollectOptions{
		ConfigPath: configPath,
		ScanID:     "test-scan-001",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if result.Meta.Collector != "config" {
		t.Errorf("meta.collector = %q, want %q", result.Meta.Collector, "config")
	}
	if result.Meta.ScanID != "test-scan-001" {
		t.Errorf("meta.scan_id = %q, want %q", result.Meta.ScanID, "test-scan-001")
	}
	if result.Meta.Version != 1 {
		t.Errorf("meta.version = %d, want 1", result.Meta.Version)
	}
	if result.Meta.Type != "agenthound-ingest" {
		t.Errorf("meta.type = %q", result.Meta.Type)
	}

	nodesByKind := countNodesByKind(result)
	if nodesByKind["ConfigFile"] != 1 {
		t.Errorf("ConfigFile nodes = %d, want 1", nodesByKind["ConfigFile"])
	}
	if nodesByKind["AgentInstance"] != 1 {
		t.Errorf("AgentInstance nodes = %d, want 1", nodesByKind["AgentInstance"])
	}
	if nodesByKind["MCPServer"] != 2 {
		t.Errorf("MCPServer nodes = %d, want 2 (disabled excluded)", nodesByKind["MCPServer"])
	}
	if nodesByKind["Host"] < 1 {
		t.Errorf("Host nodes = %d, want >= 1", nodesByKind["Host"])
	}

	edgesByKind := countEdgesByKind(result)
	if edgesByKind["TRUSTS_SERVER"] != 2 {
		t.Errorf("TRUSTS_SERVER edges = %d, want 2", edgesByKind["TRUSTS_SERVER"])
	}
	if edgesByKind["CONFIGURED_IN"] != 2 {
		t.Errorf("CONFIGURED_IN edges = %d, want 2", edgesByKind["CONFIGURED_IN"])
	}
	if edgesByKind["RUNS_ON"] != 2 {
		t.Errorf("RUNS_ON edges = %d, want 2", edgesByKind["RUNS_ON"])
	}
}

func TestConfigCollector_DeterministicServerIDs(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")
	writeJSON(t, configPath, `{
		"mcpServers": {
			"test-server": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-postgres"]
			}
		}
	}`)

	c := NewConfigCollector()
	r1, err := c.Collect(context.Background(), collector.CollectOptions{
		ConfigPath: configPath,
		ScanID:     "scan-1",
	})
	if err != nil {
		t.Fatalf("first Collect: %v", err)
	}

	r2, err := c.Collect(context.Background(), collector.CollectOptions{
		ConfigPath: configPath,
		ScanID:     "scan-2",
	})
	if err != nil {
		t.Fatalf("second Collect: %v", err)
	}

	s1 := findNodeByKind(r1, "MCPServer")
	s2 := findNodeByKind(r2, "MCPServer")
	if s1 == nil || s2 == nil {
		t.Fatal("MCPServer node not found")
	}
	if s1.ID != s2.ID {
		t.Errorf("server IDs not deterministic: %q vs %q", s1.ID, s2.ID)
	}

	expectedID := ingest.ComputeMCPServerID("stdio", "npx", "-y", "@modelcontextprotocol/server-postgres")
	if s1.ID != expectedID {
		t.Errorf("server ID = %q, want %q", s1.ID, expectedID)
	}
}

func TestConfigCollector_CredentialExtraction(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")
	writeJSON(t, configPath, `{
		"mcpServers": {
			"credtest": {
				"command": "node",
				"args": ["server.js"],
				"env": {
					"API_KEY": "sk-ant-secret123456789",
					"DB_HOST": "localhost"
				}
			}
		}
	}`)

	c := NewConfigCollector()
	result, err := c.Collect(context.Background(), collector.CollectOptions{
		ConfigPath: configPath,
		ScanID:     "cred-test",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	nodesByKind := countNodesByKind(result)
	if nodesByKind["Identity"] < 1 {
		t.Errorf("Identity nodes = %d, want >= 1", nodesByKind["Identity"])
	}
	if nodesByKind["Credential"] < 1 {
		t.Errorf("Credential nodes = %d, want >= 1", nodesByKind["Credential"])
	}

	credNode := findNodeByKindAndProp(result, "Credential", "name", "API_KEY")
	if credNode == nil {
		t.Fatal("Credential node for API_KEY not found")
	}
	if credNode.Properties["value"] == "sk-ant-secret123456789" {
		t.Error("credential value should be hashed by default, got raw value")
	}
	if credNode.Properties["is_exposed"] != true {
		t.Error("hardcoded credential should be is_exposed=true")
	}

	edgesByKind := countEdgesByKind(result)
	if edgesByKind["AUTHENTICATES_WITH"] < 1 {
		t.Errorf("AUTHENTICATES_WITH edges = %d, want >= 1", edgesByKind["AUTHENTICATES_WITH"])
	}
	if edgesByKind["USES_CREDENTIAL"] < 1 {
		t.Errorf("USES_CREDENTIAL edges = %d, want >= 1", edgesByKind["USES_CREDENTIAL"])
	}
	if edgesByKind["HAS_ENV_VAR"] < 1 {
		t.Errorf("HAS_ENV_VAR edges = %d, want >= 1", edgesByKind["HAS_ENV_VAR"])
	}
}

func TestConfigCollector_CredentialValuesIncluded(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")
	writeJSON(t, configPath, `{
		"mcpServers": {
			"credtest": {
				"command": "node",
				"args": ["server.js"],
				"env": {
					"API_KEY": "test-raw-value"
				}
			}
		}
	}`)

	c := NewConfigCollector()
	result, err := c.Collect(context.Background(), collector.CollectOptions{
		ConfigPath:              configPath,
		ScanID:                  "raw-cred-test",
		IncludeCredentialValues: true,
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	credNode := findNodeByKindAndProp(result, "Credential", "name", "API_KEY")
	if credNode == nil {
		t.Fatal("Credential node not found")
	}
	if credNode.Properties["value"] != "test-raw-value" {
		t.Errorf("expected raw value with IncludeCredentialValues, got %q", credNode.Properties["value"])
	}
}

func TestConfigCollector_UnpinnedPackageDetection(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")
	writeJSON(t, configPath, `{
		"mcpServers": {
			"unpinned": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-postgres"]
			},
			"pinned": {
				"command": "npx",
				"args": ["-y", "@modelcontextprotocol/server-postgres@1.2.3"]
			}
		}
	}`)

	c := NewConfigCollector()
	result, err := c.Collect(context.Background(), collector.CollectOptions{
		ConfigPath: configPath,
		ScanID:     "pin-test",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	servers := findNodesByKind(result, "MCPServer")
	if len(servers) != 2 {
		t.Fatalf("expected 2 MCPServer nodes, got %d", len(servers))
	}

	byName := map[string]ingest.Node{}
	for _, n := range servers {
		if name, ok := n.Properties["name"].(string); ok {
			byName[name] = n
		}
	}

	unpinned, ok := byName["unpinned"]
	if !ok {
		t.Fatal("unpinned server not found")
	}
	if unpinned.Properties["is_pinned"] != false {
		t.Errorf("unpinned server is_pinned = %v, want false", unpinned.Properties["is_pinned"])
	}

	pinned, ok := byName["pinned"]
	if !ok {
		t.Fatal("pinned server not found")
	}
	if pinned.Properties["is_pinned"] != true {
		t.Errorf("pinned server is_pinned = %v, want true", pinned.Properties["is_pinned"])
	}
}

func TestConfigCollector_HTTPServerHostExtraction(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")
	writeJSON(t, configPath, `{
		"mcpServers": {
			"remote": {
				"url": "https://mcp.example.com:8443/api"
			}
		}
	}`)

	c := NewConfigCollector()
	result, err := c.Collect(context.Background(), collector.CollectOptions{
		ConfigPath: configPath,
		ScanID:     "host-test",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	hostNode := findNodeByKind(result, "Host")
	if hostNode == nil {
		t.Fatal("Host node not found")
	}
	hostname := hostNode.Properties["hostname"]
	if hostname != "mcp.example.com" {
		t.Errorf("hostname = %q, want %q", hostname, "mcp.example.com")
	}
	if hostNode.Properties["is_public"] != true {
		t.Errorf("is_public = %v, want true", hostNode.Properties["is_public"])
	}
}

func TestConfigCollector_StdioServerLocalhostHost(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")
	writeJSON(t, configPath, `{
		"mcpServers": {
			"local": {
				"command": "node",
				"args": ["server.js"]
			}
		}
	}`)

	c := NewConfigCollector()
	result, err := c.Collect(context.Background(), collector.CollectOptions{
		ConfigPath: configPath,
		ScanID:     "localhost-test",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	hostNode := findNodeByKind(result, "Host")
	if hostNode == nil {
		t.Fatal("Host node not found")
	}
	if hostNode.Properties["is_local"] != true {
		t.Errorf("is_local = %v, want true", hostNode.Properties["is_local"])
	}
}

func TestConfigCollector_DisabledServersExcluded(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")
	writeJSON(t, configPath, `{
		"mcpServers": {
			"active": {
				"command": "node",
				"args": ["a.js"]
			},
			"disabled1": {
				"command": "node",
				"args": ["b.js"],
				"disabled": true
			},
			"disabled2": {
				"command": "node",
				"args": ["c.js"],
				"disabled": true
			}
		}
	}`)

	c := NewConfigCollector()
	result, err := c.Collect(context.Background(), collector.CollectOptions{
		ConfigPath: configPath,
		ScanID:     "disabled-test",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	nodesByKind := countNodesByKind(result)
	if nodesByKind["MCPServer"] != 1 {
		t.Errorf("MCPServer nodes = %d, want 1 (only active)", nodesByKind["MCPServer"])
	}

	cf := findNodeByKind(result, "ConfigFile")
	if cf == nil {
		t.Fatal("ConfigFile not found")
	}
	if cf.Properties["server_count"] != 1 {
		t.Errorf("server_count = %v, want 1", cf.Properties["server_count"])
	}
}

func TestConfigCollector_NodeDeduplication(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")
	writeJSON(t, configPath, `{
		"mcpServers": {
			"server-a": {
				"command": "node",
				"args": ["a.js"]
			},
			"server-b": {
				"command": "node",
				"args": ["b.js"]
			}
		}
	}`)

	c := NewConfigCollector()
	result, err := c.Collect(context.Background(), collector.CollectOptions{
		ConfigPath: configPath,
		ScanID:     "dedup-test",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	nodesByKind := countNodesByKind(result)
	if nodesByKind["Host"] != 1 {
		t.Errorf("Host nodes = %d, want 1 (both stdio → localhost deduped)", nodesByKind["Host"])
	}
}

func TestConfigCollector_MultipleConfigPaths(t *testing.T) {
	tmp := t.TempDir()
	path1 := filepath.Join(tmp, "config1.json")
	writeJSON(t, path1, `{"mcpServers":{"s1":{"command":"cmd1"}}}`)
	path2 := filepath.Join(tmp, "config2.json")
	writeJSON(t, path2, `{"mcpServers":{"s2":{"command":"cmd2"}}}`)

	c := NewConfigCollector()
	result, err := c.Collect(context.Background(), collector.CollectOptions{
		ConfigPaths: []string{path1, path2},
		ScanID:      "multi-test",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	nodesByKind := countNodesByKind(result)
	if nodesByKind["ConfigFile"] != 2 {
		t.Errorf("ConfigFile nodes = %d, want 2", nodesByKind["ConfigFile"])
	}
	if nodesByKind["AgentInstance"] != 2 {
		t.Errorf("AgentInstance nodes = %d, want 2", nodesByKind["AgentInstance"])
	}
	if nodesByKind["MCPServer"] != 2 {
		t.Errorf("MCPServer nodes = %d, want 2", nodesByKind["MCPServer"])
	}
}

func TestConfigCollector_InstructionFiles(t *testing.T) {
	tmp := t.TempDir()

	configPath := filepath.Join(tmp, "config.json")
	writeJSON(t, configPath, `{"mcpServers":{"s1":{"command":"node","args":["s.js"]}}}`)

	projectDir := filepath.Join(tmp, "project")
	if err := os.MkdirAll(projectDir, 0o755); err != nil {
		t.Fatal(err)
	}
	claudeMD := filepath.Join(projectDir, "CLAUDE.md")
	if err := os.WriteFile(claudeMD, []byte("# Normal instructions\nDo your best."), 0o644); err != nil {
		t.Fatal(err)
	}

	c := NewConfigCollector()
	result, err := c.Collect(context.Background(), collector.CollectOptions{
		ConfigPath: configPath,
		ProjectDir: projectDir,
		ScanID:     "instr-test",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	instrNodes := findNodesByKind(result, "InstructionFile")
	if len(instrNodes) < 1 {
		t.Fatal("expected at least 1 InstructionFile node")
	}

	found := false
	for _, n := range instrNodes {
		if n.Properties["type"] == "claude.md" {
			found = true
			if n.Properties["is_suspicious"] != false {
				t.Error("normal instruction file should not be suspicious")
			}
		}
	}
	if !found {
		t.Error("claude.md instruction file not found")
	}

	edgesByKind := countEdgesByKind(result)
	if edgesByKind["LOADS_INSTRUCTIONS"] < 1 {
		t.Errorf("LOADS_INSTRUCTIONS edges = %d, want >= 1", edgesByKind["LOADS_INSTRUCTIONS"])
	}
}

func TestConfigCollector_AuthMethodDerivation(t *testing.T) {
	tests := []struct {
		name    string
		env     map[string]string
		headers map[string]string
		want    string
	}{
		{
			name: "bearer from header",
			headers: map[string]string{
				"Authorization": "Bearer tok123",
			},
			want: "bearer",
		},
		{
			name: "apiKey from env",
			env: map[string]string{
				"API_KEY": "some-value",
			},
			want: "apiKey",
		},
		{
			name: "oauth from env",
			env: map[string]string{
				"OAUTH_CLIENT_ID": "cid",
			},
			want: "oauth",
		},
		{
			name: "none when empty",
			want: "none",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deriveAuthMethod(tt.env, tt.headers)
			if got != tt.want {
				t.Errorf("deriveAuthMethod() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConfigCollector_EdgeProperties(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")
	writeJSON(t, configPath, `{
		"mcpServers": {
			"test": {
				"command": "node",
				"args": ["server.js"]
			}
		}
	}`)

	c := NewConfigCollector()
	result, err := c.Collect(context.Background(), collector.CollectOptions{
		ConfigPath: configPath,
		ScanID:     "edge-props-test",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	for _, e := range result.Graph.Edges {
		if _, ok := e.Properties["scan_id"]; !ok {
			t.Errorf("edge %s missing scan_id", e.Kind)
		}
		if _, ok := e.Properties["last_seen"]; !ok {
			t.Errorf("edge %s missing last_seen", e.Kind)
		}
		if _, ok := e.Properties["confidence"]; !ok {
			t.Errorf("edge %s missing confidence", e.Kind)
		}
		if _, ok := e.Properties["risk_weight"]; !ok {
			t.Errorf("edge %s missing risk_weight", e.Kind)
		}
	}

	trustEdge := findEdgeByKind(result, "TRUSTS_SERVER")
	if trustEdge == nil {
		t.Fatal("TRUSTS_SERVER edge not found")
	}
	rw, _ := trustEdge.Properties["risk_weight"].(float64)
	if rw != 0.1 {
		t.Errorf("TRUSTS_SERVER risk_weight = %v, want 0.1 (none auth)", rw)
	}

	configuredIn := findEdgeByKind(result, "CONFIGURED_IN")
	if configuredIn == nil {
		t.Fatal("CONFIGURED_IN edge not found")
	}
	rw, _ = configuredIn.Properties["risk_weight"].(float64)
	if rw != 0.0 {
		t.Errorf("CONFIGURED_IN risk_weight = %v, want 0.0", rw)
	}
}

func TestConfigCollector_AllNodesHaveObjectID(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")
	writeJSON(t, configPath, `{
		"mcpServers": {
			"test": {
				"command": "npx",
				"args": ["-y", "server"],
				"env": {"API_KEY": "secret"}
			}
		}
	}`)

	c := NewConfigCollector()
	result, err := c.Collect(context.Background(), collector.CollectOptions{
		ConfigPath: configPath,
		ScanID:     "objectid-test",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	for _, n := range result.Graph.Nodes {
		oid, ok := n.Properties["objectid"].(string)
		if !ok || oid == "" {
			t.Errorf("node %q (kinds=%v) missing objectid", n.ID, n.Kinds)
		}
		if oid != n.ID {
			t.Errorf("objectid %q != node ID %q", oid, n.ID)
		}
	}
}

func TestConfigCollector_ScanIDGenerated(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")
	writeJSON(t, configPath, `{"mcpServers":{"s":{"command":"cmd"}}}`)

	c := NewConfigCollector()
	result, err := c.Collect(context.Background(), collector.CollectOptions{
		ConfigPath: configPath,
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	if result.Meta.ScanID == "" {
		t.Error("scan_id should be auto-generated when not provided")
	}
	if len(result.Meta.ScanID) < 10 {
		t.Errorf("scan_id too short: %q", result.Meta.ScanID)
	}
}

func TestConfigCollector_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	c := NewConfigCollector()
	_, err := c.Collect(ctx, collector.CollectOptions{
		Discover: true,
	})
	if err == nil {
		t.Error("expected error on cancelled context")
	}
}

func TestConfigCollector_EdgeConnectionsCorrect(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")
	writeJSON(t, configPath, `{
		"mcpServers": {
			"server1": {
				"command": "node",
				"args": ["s1.js"]
			}
		}
	}`)

	c := NewConfigCollector()
	result, err := c.Collect(context.Background(), collector.CollectOptions{
		ConfigPath: configPath,
		ScanID:     "edge-conn-test",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	nodeIDs := make(map[string]string)
	for _, n := range result.Graph.Nodes {
		nodeIDs[n.ID] = n.Kinds[0]
	}

	for _, e := range result.Graph.Edges {
		srcKind, srcOK := nodeIDs[e.Source]
		tgtKind, tgtOK := nodeIDs[e.Target]
		if !srcOK {
			t.Errorf("edge %s has unknown source %s", e.Kind, e.Source)
		}
		if !tgtOK {
			t.Errorf("edge %s has unknown target %s", e.Kind, e.Target)
		}

		switch e.Kind {
		case "TRUSTS_SERVER":
			if srcKind != "AgentInstance" || tgtKind != "MCPServer" {
				t.Errorf("TRUSTS_SERVER: %s -> %s, want AgentInstance -> MCPServer", srcKind, tgtKind)
			}
		case "CONFIGURED_IN":
			if srcKind != "MCPServer" || tgtKind != "ConfigFile" {
				t.Errorf("CONFIGURED_IN: %s -> %s, want MCPServer -> ConfigFile", srcKind, tgtKind)
			}
		case "RUNS_ON":
			if srcKind != "MCPServer" || tgtKind != "Host" {
				t.Errorf("RUNS_ON: %s -> %s, want MCPServer -> Host", srcKind, tgtKind)
			}
		}
	}
}

func TestConfigCollector_BearerAuthRiskWeight(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")
	writeJSON(t, configPath, `{
		"mcpServers": {
			"authed": {
				"url": "https://api.example.com/mcp",
				"headers": {
					"Authorization": "Bearer sk-test-12345"
				}
			}
		}
	}`)

	c := NewConfigCollector()
	result, err := c.Collect(context.Background(), collector.CollectOptions{
		ConfigPath: configPath,
		ScanID:     "bearer-rw-test",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	server := findNodeByKind(result, "MCPServer")
	if server == nil {
		t.Fatal("MCPServer not found")
	}
	if server.Properties["auth_method"] != "bearer" {
		t.Errorf("auth_method = %q, want bearer", server.Properties["auth_method"])
	}

	trustEdge := findEdgeByKind(result, "TRUSTS_SERVER")
	if trustEdge == nil {
		t.Fatal("TRUSTS_SERVER edge not found")
	}
	rw, _ := trustEdge.Properties["risk_weight"].(float64)
	if rw != 0.5 {
		t.Errorf("bearer TRUSTS_SERVER risk_weight = %v, want 0.5", rw)
	}
}

func TestConfigCollector_HTTPServerEndpoint(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")
	writeJSON(t, configPath, `{
		"mcpServers": {
			"remote": {
				"url": "https://mcp.example.com/api"
			}
		}
	}`)

	c := NewConfigCollector()
	result, err := c.Collect(context.Background(), collector.CollectOptions{
		ConfigPath: configPath,
		ScanID:     "endpoint-test",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	server := findNodeByKind(result, "MCPServer")
	if server == nil {
		t.Fatal("MCPServer not found")
	}
	if server.Properties["endpoint"] != "https://mcp.example.com/api" {
		t.Errorf("endpoint = %q, want URL", server.Properties["endpoint"])
	}
}

func TestConfigCollector_StdioServerEndpoint(t *testing.T) {
	tmp := t.TempDir()
	configPath := filepath.Join(tmp, "config.json")
	writeJSON(t, configPath, `{
		"mcpServers": {
			"local": {
				"command": "npx",
				"args": ["-y", "server"]
			}
		}
	}`)

	c := NewConfigCollector()
	result, err := c.Collect(context.Background(), collector.CollectOptions{
		ConfigPath: configPath,
		ScanID:     "stdio-ep-test",
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	server := findNodeByKind(result, "MCPServer")
	if server == nil {
		t.Fatal("MCPServer not found")
	}
	if server.Properties["endpoint"] != "npx" {
		t.Errorf("endpoint = %q, want command name", server.Properties["endpoint"])
	}
}

// ---- helpers ----

func writeJSON(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

func countNodesByKind(d *ingest.IngestData) map[string]int {
	m := make(map[string]int)
	for _, n := range d.Graph.Nodes {
		for _, k := range n.Kinds {
			m[k]++
		}
	}
	return m
}

func countEdgesByKind(d *ingest.IngestData) map[string]int {
	m := make(map[string]int)
	for _, e := range d.Graph.Edges {
		m[e.Kind]++
	}
	return m
}

func findNodeByKind(d *ingest.IngestData, kind string) *ingest.Node {
	for i, n := range d.Graph.Nodes {
		for _, k := range n.Kinds {
			if k == kind {
				return &d.Graph.Nodes[i]
			}
		}
	}
	return nil
}

func findNodesByKind(d *ingest.IngestData, kind string) []ingest.Node {
	var out []ingest.Node
	for _, n := range d.Graph.Nodes {
		for _, k := range n.Kinds {
			if k == kind {
				out = append(out, n)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool {
		ni, _ := out[i].Properties["name"].(string)
		nj, _ := out[j].Properties["name"].(string)
		return ni < nj
	})
	return out
}

func findNodeByKindAndProp(d *ingest.IngestData, kind, propKey string, propVal any) *ingest.Node {
	for i, n := range d.Graph.Nodes {
		for _, k := range n.Kinds {
			if k == kind && n.Properties[propKey] == propVal {
				return &d.Graph.Nodes[i]
			}
		}
	}
	return nil
}

func findEdgeByKind(d *ingest.IngestData, kind string) *ingest.Edge {
	for i, e := range d.Graph.Edges {
		if e.Kind == kind {
			return &d.Graph.Edges[i]
		}
	}
	return nil
}
