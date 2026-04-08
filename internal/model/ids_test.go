package model

import "testing"

func TestComputeNodeIDDeterministic(t *testing.T) {
	id1 := ComputeNodeID("MCPServer", "stdio", "npx", "-y,@modelcontextprotocol/server-postgres")
	id2 := ComputeNodeID("MCPServer", "stdio", "npx", "-y,@modelcontextprotocol/server-postgres")
	if id1 != id2 {
		t.Errorf("IDs not deterministic: %s != %s", id1, id2)
	}
	if id1[:7] != "sha256:" {
		t.Errorf("expected sha256: prefix, got %s", id1[:7])
	}
}

func TestComputeNodeIDDiffersForDifferentInputs(t *testing.T) {
	id1 := ComputeNodeID("MCPServer", "stdio", "npx")
	id2 := ComputeNodeID("MCPTool", "stdio", "npx")
	if id1 == id2 {
		t.Error("different prefixes should produce different IDs")
	}
}

func TestComputeMCPServerIDMatchesAcrossCollectors(t *testing.T) {
	configID := ComputeMCPServerID("stdio", "npx", "-y,@modelcontextprotocol/server-postgres")
	mcpID := ComputeMCPServerID("stdio", "npx", "-y,@modelcontextprotocol/server-postgres")
	if configID != mcpID {
		t.Errorf("config and mcp IDs differ: %s != %s", configID, mcpID)
	}
}
