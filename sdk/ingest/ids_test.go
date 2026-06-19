package ingest

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

func TestComputeMCPServerIDDoesNotMutateArgs(t *testing.T) {
	args := []string{"server-b", "server-a", "server-c"}
	orig := append([]string(nil), args...)

	ComputeMCPServerID("stdio", "npx", args...)

	for i := range orig {
		if args[i] != orig[i] {
			t.Fatalf("ComputeMCPServerID mutated caller args: got %v, want %v", args, orig)
		}
	}
}

func TestComputeMCPServerIDNormalizesEndpointWhitespace(t *testing.T) {
	clean := ComputeMCPServerID("stdio", "npx")
	spaced := ComputeMCPServerID("stdio", " npx ")
	if clean != spaced {
		t.Errorf("endpoint whitespace not normalized: %q vs %q produced %s != %s",
			"npx", " npx ", clean, spaced)
	}
}

func TestComputeMCPServerIDNormalizesArgWhitespace(t *testing.T) {
	clean := ComputeMCPServerID("stdio", "npx", "-y", "pkg")
	spaced := ComputeMCPServerID("stdio", "npx", " -y", "pkg ")
	if clean != spaced {
		t.Errorf("arg whitespace not normalized: produced %s != %s", clean, spaced)
	}
}

func TestComputeMCPServerIDStableForCleanInputs(t *testing.T) {
	// Guards the cross-collector merge invariant: already-clean inputs must
	// hash to the same value before and after centralizing normalization.
	cases := []struct {
		transport string
		endpoint  string
		args      []string
		want      string
	}{
		{"stdio", "npx", []string{"-y", "@modelcontextprotocol/server-postgres"},
			ComputeNodeID("MCPServer", "stdio", "npx", "-y,@modelcontextprotocol/server-postgres")},
		{"http", "https://example.com/mcp", nil,
			ComputeNodeID("MCPServer", "http", "https://example.com/mcp")},
	}
	for _, tc := range cases {
		got := ComputeMCPServerID(tc.transport, tc.endpoint, tc.args...)
		if got != tc.want {
			t.Errorf("ComputeMCPServerID(%q, %q, %v) = %s, want %s",
				tc.transport, tc.endpoint, tc.args, got, tc.want)
		}
	}
}
