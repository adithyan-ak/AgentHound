package ingest

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"strings"
)

const (
	MCPHTTPIdentitySchemeV1      = "mcp_http_v1"
	MCPStdioIdentitySchemeV2     = "mcp_stdio_v2_ordered"
	MCPStdioIdentitySchemeV3     = "mcp_stdio_v3_hashed_argv"
	MCPStdioArgumentHashSchemeV1 = "mcp_stdio_argument_v1"
)

// ComputeNodeID produces a deterministic SHA-256 hex ID for a node.
// The prefix identifies the node type (e.g., "MCPServer", "MCPTool").
// Components are joined with ":" to form the hash input.
func ComputeNodeID(prefix string, components ...string) string {
	input := prefix + ":" + strings.Join(components, ":")
	hash := sha256.Sum256([]byte(input))
	return fmt.Sprintf("sha256:%x", hash)
}

// IsCanonicalSHA256 reports whether value is a lowercase, prefix-qualified
// SHA-256 digest. It validates representation only, not the bytes that were
// hashed.
func IsCanonicalSHA256(value string) bool {
	if len(value) != len("sha256:")+sha256.Size*2 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, char := range value[len("sha256:"):] {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return false
		}
	}
	return true
}

// IsCanonicalNodeID reports whether value has the exact public node-ID shape
// produced by ComputeNodeID. Node IDs and public digest properties share the
// same canonical SHA-256 representation.
func IsCanonicalNodeID(value string) bool {
	return IsCanonicalSHA256(value)
}

// ComputeMCPServerID produces the current deterministic ID for an MCPServer.
// HTTP retains the v1 identity byte-for-byte. Stdio hashes each raw argument
// in memory, then uses the ordered hashes as the validator-recomputable v3
// identity input. Raw argv therefore never needs to be serialized merely to
// prove the server ID.
func ComputeMCPServerID(transport string, endpoint string, args ...string) string {
	if strings.TrimSpace(transport) != "stdio" {
		return ComputeNodeID(
			"MCPServer",
			strings.TrimSpace(transport),
			strings.TrimSpace(endpoint),
		)
	}

	return ComputeMCPServerIDFromArgumentHashes(
		endpoint,
		ComputeMCPStdioArgumentHashes(args...)...,
	)
}

// ComputeMCPStdioArgumentHash returns the domain-separated digest that may be
// serialized in place of one raw stdio argument. Argument bytes are preserved
// exactly; callers must not trim or normalize them first.
func ComputeMCPStdioArgumentHash(argument string) string {
	h := sha256.New()
	writeIDFrame(h, "MCPServerArgument")
	writeIDFrame(h, MCPStdioArgumentHashSchemeV1)
	writeIDFrame(h, argument)
	return fmt.Sprintf("sha256:%x", h.Sum(nil))
}

// ComputeMCPStdioArgumentHashes returns an order-preserving, non-aliasing copy
// of the digests for args. The returned slice is non-nil even for empty argv so
// collectors can emit an explicit empty arg_hashes array.
func ComputeMCPStdioArgumentHashes(args ...string) []string {
	hashes := make([]string, len(args))
	for i, argument := range args {
		hashes[i] = ComputeMCPStdioArgumentHash(argument)
	}
	return hashes
}

// ComputeMCPServerIDFromArgumentHashes recomputes a stdio MCPServer ID without
// access to raw argv. Callers accepting untrusted artifacts must separately
// require every value to satisfy IsCanonicalSHA256 before trusting the result.
func ComputeMCPServerIDFromArgumentHashes(command string, argumentHashes ...string) string {
	h := sha256.New()
	writeIDFrame(h, "MCPServer")
	writeIDFrame(h, MCPStdioIdentitySchemeV3)
	writeIDFrame(h, strings.TrimSpace(command))
	for _, argumentHash := range argumentHashes {
		writeIDFrame(h, argumentHash)
	}
	return fmt.Sprintf("sha256:%x", h.Sum(nil))
}

type MCPServerIdentity struct {
	ObjectID       string
	Scheme         string
	Version        int
	ArgumentHashes []string
}

func ResolveMCPServerIdentity(transport, endpoint string, args ...string) MCPServerIdentity {
	if strings.TrimSpace(transport) != "stdio" {
		return MCPServerIdentity{
			ObjectID: ComputeMCPServerID(transport, endpoint, args...),
			Scheme:   MCPHTTPIdentitySchemeV1,
			Version:  1,
		}
	}
	argumentHashes := ComputeMCPStdioArgumentHashes(args...)
	return MCPServerIdentity{
		ObjectID:       ComputeMCPServerIDFromArgumentHashes(endpoint, argumentHashes...),
		Scheme:         MCPStdioIdentitySchemeV3,
		Version:        3,
		ArgumentHashes: argumentHashes,
	}
}

func writeIDFrame(h hash.Hash, value string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = h.Write(size[:])
	_, _ = h.Write([]byte(value))
}
