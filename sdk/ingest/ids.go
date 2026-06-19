package ingest

import (
	"crypto/sha256"
	"fmt"
	"sort"
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
// For stdio transport: ComputeMCPServerID("stdio", "npx", "-y,@modelcontextprotocol/server-postgres")
// For http transport: ComputeMCPServerID("http", "https://example.com/mcp")
// Args should be sorted and joined with commas.
func ComputeMCPServerID(transport string, endpoint string, args ...string) string {
	endpoint = strings.TrimSpace(endpoint)
	sorted := make([]string, len(args))
	for i, a := range args {
		sorted[i] = strings.TrimSpace(a)
	}
	sort.Strings(sorted)
	argsStr := strings.Join(sorted, ",")
	if argsStr != "" {
		return ComputeNodeID("MCPServer", transport, endpoint, argsStr)
	}
	return ComputeNodeID("MCPServer", transport, endpoint)
}
