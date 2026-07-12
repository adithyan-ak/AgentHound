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

func TestComputeMCPServerIDPreservesArgWhitespace(t *testing.T) {
	clean := ComputeMCPServerID("stdio", "npx", "-y", "pkg")
	spaced := ComputeMCPServerID("stdio", "npx", " -y", "pkg ")
	if clean == spaced {
		t.Errorf("semantically distinct argv whitespace collided: %s", clean)
	}
}

func TestComputeMCPServerIDStableForCleanInputs(t *testing.T) {
	first := ComputeMCPServerID("stdio", "npx", "-y", "@modelcontextprotocol/server-postgres")
	second := ComputeMCPServerID("stdio", "npx", "-y", "@modelcontextprotocol/server-postgres")
	if first != second {
		t.Fatalf("ordered stdio identity is not deterministic: %s != %s", first, second)
	}
}

func TestComputeMCPServerIDPreservesArgOrder(t *testing.T) {
	first := ComputeMCPServerID("stdio", "node", "a.js", "b.js")
	reversed := ComputeMCPServerID("stdio", "node", "b.js", "a.js")
	if first == reversed {
		t.Fatalf("reordered argv collided: %s", first)
	}
}

func TestComputeMCPServerIDLengthFramesArgs(t *testing.T) {
	oneArg := ComputeMCPServerID("stdio", "cmd", "a,b")
	twoArgs := ComputeMCPServerID("stdio", "cmd", "a", "b")
	if oneArg == twoArgs {
		t.Fatalf("comma-containing argv collided: %s", oneArg)
	}
}

func TestComputeMCPServerIDKeepsHTTPV1Stable(t *testing.T) {
	want := ComputeNodeID("MCPServer", "http", "https://example.com/mcp")
	got := ComputeMCPServerID("http", "https://example.com/mcp")
	if got != want {
		t.Fatalf("HTTP ID changed: got %s, want %s", got, want)
	}
	identity := ResolveMCPServerIdentity("http", "https://example.com/mcp")
	if identity.ObjectID != want || identity.Scheme != MCPHTTPIdentitySchemeV1 {
		t.Fatalf("unexpected HTTP identity: %+v", identity)
	}
}
