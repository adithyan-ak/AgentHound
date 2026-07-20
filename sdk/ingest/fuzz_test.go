package ingest

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzIngestData fuzzes json.Unmarshal into IngestData. The contract is "no panic
// on arbitrary bytes" — we do not assert correctness beyond that.
func FuzzIngestData(f *testing.F) {
	// Seed with a small, hand-written valid sample so the fuzzer has at least
	// one well-formed starting point even if the repo testdata tree is missing.
	f.Add([]byte(`{"meta":{"version":3,"type":"agenthound-ingest","origin":{"host_id":"fixture-host","network_realm_id":"fixture-realm"},"collector":"mcp","collector_version":"0.1.0","timestamp":"2026-04-06T10:30:00Z","scan_id":"scan-001","collection":{"state":"complete","coverage_keys":["mcp:target:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],"outcomes":[{"collector":"mcp","coverage_key":"mcp:target:sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","target":"https://mcp.example","method":"enumerate","state":"complete"}]},"ruleset":{"digest":"sha256:rules","load_state":"complete","authenticity":"unverified"},"identity_schemes":[{"entity_kind":"MCPServer","transport":"stdio","scheme":"mcp_stdio_v3_hashed_argv","version":3}]},"graph":{"nodes":[],"edges":[]}}`))
	f.Add([]byte(`{}`))
	f.Add([]byte(`null`))
	f.Add([]byte(``))

	// Pull in any reachable testdata/**/*.json files as additional seeds.
	// Walk up from the package directory until we find a testdata/ sibling
	// (so the seed corpus survives the file living under sdk/ingest/).
	if dir := findRepoTestdata(); dir != "" {
		_ = filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() {
				return nil
			}
			if !strings.HasSuffix(path, ".json") {
				return nil
			}
			data, err := os.ReadFile(path)
			if err != nil {
				return nil
			}
			f.Add(data)
			return nil
		})
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		var d IngestData
		_ = json.Unmarshal(data, &d)
	})
}

// findRepoTestdata walks parent directories looking for a testdata/ sibling.
// Returns "" if not found within a reasonable depth.
func findRepoTestdata() string {
	dir, err := os.Getwd()
	if err != nil {
		return ""
	}
	for i := 0; i < 6; i++ {
		candidate := filepath.Join(dir, "testdata")
		if info, err := os.Stat(candidate); err == nil && info.IsDir() {
			return candidate
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
	return ""
}
