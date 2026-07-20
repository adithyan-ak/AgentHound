package ingest

import (
	"strings"
	"testing"
)

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

func TestIsCanonicalNodeID(t *testing.T) {
	valid := ComputeNodeID("AIModel", "instance", "model")
	for _, test := range []struct {
		name  string
		value string
		want  bool
	}{
		{name: "computed", value: valid, want: true},
		{name: "empty", value: "", want: false},
		{name: "external locator", value: "hf://example/model.gguf", want: false},
		{name: "short digest", value: "sha256:abcd", want: false},
		{name: "uppercase digest", value: "sha256:" + strings.Repeat("A", 64), want: false},
		{name: "non-hex digest", value: "sha256:" + strings.Repeat("g", 64), want: false},
		{name: "whitespace", value: valid + " ", want: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := IsCanonicalNodeID(test.value); got != test.want {
				t.Fatalf("IsCanonicalNodeID(%q) = %v, want %v", test.value, got, test.want)
			}
		})
	}
}

func TestComputeMCPServerIDMatchesAcrossCollectors(t *testing.T) {
	configID := ComputeMCPServerID("stdio", "npx", "-y,@modelcontextprotocol/server-postgres")
	mcpID := ComputeMCPServerID("stdio", "npx", "-y,@modelcontextprotocol/server-postgres")
	if configID != mcpID {
		t.Errorf("config and mcp IDs differ: %s != %s", configID, mcpID)
	}
}

func TestResolveMCPServerIdentityUsesHashedArgvV3(t *testing.T) {
	secret := "sk-RAW-ARG-SECRET-123456789"
	identity := ResolveMCPServerIdentity("stdio", "npx", "--api-key", secret)
	if identity.Scheme != MCPStdioIdentitySchemeV3 || identity.Version != 3 {
		t.Fatalf("unexpected stdio identity contract: %+v", identity)
	}
	if len(identity.ArgumentHashes) != 2 {
		t.Fatalf("argument hashes = %v, want two", identity.ArgumentHashes)
	}
	for i, argumentHash := range identity.ArgumentHashes {
		if !IsCanonicalSHA256(argumentHash) {
			t.Fatalf("argument hash %d is not canonical: %q", i, argumentHash)
		}
		if strings.Contains(argumentHash, secret) {
			t.Fatalf("argument hash leaked raw secret: %q", argumentHash)
		}
	}
	want := ComputeMCPServerIDFromArgumentHashes("npx", identity.ArgumentHashes...)
	if identity.ObjectID != want {
		t.Fatalf("identity cannot be recomputed from public hashes: got %s, want %s", identity.ObjectID, want)
	}
}

func TestComputeMCPStdioArgumentHashesPreservesBytesAndOrder(t *testing.T) {
	first := ComputeMCPStdioArgumentHashes("a", " b")
	reversed := ComputeMCPStdioArgumentHashes(" b", "a")
	trimmed := ComputeMCPStdioArgumentHashes("a", "b")
	if first[0] != reversed[1] || first[1] != reversed[0] {
		t.Fatalf("per-argument hashes are not stable: %v vs %v", first, reversed)
	}
	if first[1] == trimmed[1] {
		t.Fatalf("argument whitespace was normalized: %s", first[1])
	}
	if ComputeMCPServerIDFromArgumentHashes("cmd", first...) ==
		ComputeMCPServerIDFromArgumentHashes("cmd", reversed...) {
		t.Fatal("ordered argument hashes collided after reordering")
	}
	if empty := ComputeMCPStdioArgumentHashes(); empty == nil || len(empty) != 0 {
		t.Fatalf("empty argument hashes = %#v, want non-nil empty slice", empty)
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
