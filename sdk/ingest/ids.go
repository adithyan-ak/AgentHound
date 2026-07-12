package ingest

import (
	"crypto/sha256"
	"fmt"
	"strings"
)

// ComputeNodeID produces a deterministic SHA-256 hex ID for a node.
// The prefix identifies the node type (e.g., "MCPServer", "MCPTool").
// Components are joined with ":" to form the hash input.
func ComputeNodeID(prefix string, components ...string) string {
	input := prefix + ":" + strings.Join(components, ":")
	hash := sha256.Sum256([]byte(input))
	return fmt.Sprintf("sha256:%x", hash)
}

// ComputeMCPServerID produces the deterministic ID for an MCPServer node.
// For stdio transport: ComputeMCPServerID("stdio", "npx", "-y", "@modelcontextprotocol/server-postgres")
// For http transport: ComputeMCPServerID("http", "https://example.com/mcp")
//
// Args are ORDER-PRESERVING (identity version 2). The launch argv is
// semantically ordered — `npx -y pkg --port 8080` and `npx --port 8080 -y
// pkg` are different invocations, and a flag's value follows the flag
// positionally — so sorting the args (identity version 1) both collapsed
// genuinely distinct servers onto one ID and destroyed flag/value adjacency.
// Only surrounding whitespace is normalized; the caller's slice is never
// mutated. Config and MCP collectors MUST derive args identically (same
// order) so the two collectors merge on a shared MCPServer ID.
func ComputeMCPServerID(transport string, endpoint string, args ...string) string {
	endpoint = strings.TrimSpace(endpoint)
	trimmed := make([]string, len(args))
	for i, a := range args {
		trimmed[i] = strings.TrimSpace(a)
	}
	argsStr := strings.Join(trimmed, ",")
	if argsStr != "" {
		return ComputeNodeID("MCPServer", transport, endpoint, argsStr)
	}
	return ComputeNodeID("MCPServer", transport, endpoint)
}
