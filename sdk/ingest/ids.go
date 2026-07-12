package ingest

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"strings"
)

const (
	MCPHTTPIdentitySchemeV1  = "mcp_http_v1"
	MCPStdioIdentitySchemeV2 = "mcp_stdio_v2_ordered"
)

// ComputeNodeID produces a deterministic SHA-256 hex ID for a node.
// The prefix identifies the node type (e.g., "MCPServer", "MCPTool").
// Components are joined with ":" to form the hash input.
func ComputeNodeID(prefix string, components ...string) string {
	input := prefix + ":" + strings.Join(components, ":")
	hash := sha256.Sum256([]byte(input))
	return fmt.Sprintf("sha256:%x", hash)
}

// ComputeMCPServerID produces the current deterministic ID for an MCPServer.
// HTTP retains the v1 identity byte-for-byte. Stdio uses a domain-separated,
// length-framed command/argv sequence that preserves argument order and bytes.
func ComputeMCPServerID(transport string, endpoint string, args ...string) string {
	if strings.TrimSpace(transport) != "stdio" {
		return ComputeNodeID(
			"MCPServer",
			strings.TrimSpace(transport),
			strings.TrimSpace(endpoint),
		)
	}

	h := sha256.New()
	writeIDFrame(h, "MCPServer")
	writeIDFrame(h, MCPStdioIdentitySchemeV2)
	writeIDFrame(h, strings.TrimSpace(endpoint))
	for _, arg := range args {
		writeIDFrame(h, arg)
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil))
}

type MCPServerIdentity struct {
	ObjectID string
	Scheme   string
	Version  int
}

func ResolveMCPServerIdentity(transport, endpoint string, args ...string) MCPServerIdentity {
	if strings.TrimSpace(transport) != "stdio" {
		return MCPServerIdentity{
			ObjectID: ComputeMCPServerID(transport, endpoint, args...),
			Scheme:   MCPHTTPIdentitySchemeV1,
			Version:  1,
		}
	}
	return MCPServerIdentity{
		ObjectID: ComputeMCPServerID("stdio", endpoint, args...),
		Scheme:   MCPStdioIdentitySchemeV2,
		Version:  2,
	}
}

func writeIDFrame(h hash.Hash, value string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = h.Write(size[:])
	_, _ = h.Write([]byte(value))
}
