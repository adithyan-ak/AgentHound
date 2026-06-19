package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/sdk/module"
)

// --- Mock Fingerprinter (Finding 6) ---

type mockFingerprinter struct {
	targetKind  string
	gotAddress  string
	probeCount  int
	matchedNode string
}

func (m *mockFingerprinter) ID() string            { return "mock.fingerprint." + m.targetKind }
func (m *mockFingerprinter) Action() action.Action { return action.Fingerprint }
func (m *mockFingerprinter) Target() string        { return m.targetKind }
func (m *mockFingerprinter) Description() string   { return "mock fingerprinter" }
func (m *mockFingerprinter) Version() string       { return "0.0.0" }
func (m *mockFingerprinter) IsDestructive() bool   { return false }
func (m *mockFingerprinter) Fingerprint(ctx context.Context, t action.Target) (*action.FingerprintResult, error) {
	m.probeCount++
	m.gotAddress = t.Address
	return &action.FingerprintResult{
		Matched:     true,
		ServiceKind: m.targetKind,
		IngestData: &ingest.IngestData{
			Graph: ingest.GraphData{
				Nodes: []ingest.Node{{ID: m.matchedNode, Kinds: []string{"AIService"}}},
			},
		},
	}, nil
}

// TestDispatchFingerprints_DerivesKindFromPort is the Finding 6 regression.
// With custom --ports producing an unmapped port (9999) BEFORE a mapped one
// (4000 → litellm), the old index-zip logic paired kinds[0]="litellm" with
// ports[0]="9999" and probed the wrong port. The fix derives the kind per
// port via networkscan.PortToKind, so the litellm fingerprinter must be
// dispatched against :4000, not :9999.
func TestDispatchFingerprints_DerivesKindFromPort(t *testing.T) {
	fp := &mockFingerprinter{targetKind: "litellm", matchedNode: "sha256:litellm-node"}
	module.Register(fp)
	defer deregisterModule(t, fp.ID())

	// open_ports lists the unmapped port FIRST; candidate_kinds lists only
	// the mapped kind (mirrors hostResultToTarget's real output).
	targets := []action.Target{{
		Kind:    "host",
		Address: "10.0.0.7",
		Meta: map[string]string{
			"open_ports":      "9999,4000",
			"candidate_kinds": "litellm",
		},
	}}

	envelope := &ingest.IngestData{}
	dispatchFingerprints(context.Background(), io.Discard, targets, envelope)

	if fp.probeCount != 1 {
		t.Fatalf("fingerprinter probed %d time(s), want exactly 1", fp.probeCount)
	}
	if fp.gotAddress != "10.0.0.7:4000" {
		t.Errorf("fingerprinter probed %q, want 10.0.0.7:4000 (port derived from PortToKind)", fp.gotAddress)
	}
	if len(envelope.Graph.Nodes) != 1 || envelope.Graph.Nodes[0].ID != "sha256:litellm-node" {
		t.Errorf("matched node not merged into envelope: %+v", envelope.Graph.Nodes)
	}
}

// TestRunScan_URLWithoutMCP is the Finding 7 regression: `scan --url <srv>`
// with no explicit mode flag must infer MCP-only mode and not trip the
// "--url requires --mcp" guard. We point --url at a closed local address so
// the MCP collector returns quickly (its error is logged, not fatal) and
// assert runScan returns nil and writes the artifact.
func TestRunScan_URLWithoutMCP(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "url-only.json")

	cmd := newScanCmdForTest()
	mustSetFlag(t, cmd, "url", "http://127.0.0.1:1")
	mustSetFlag(t, cmd, "scan-output", out)

	if err := runScan(cmd, nil); err != nil {
		t.Fatalf("runScan with --url and no mode flags: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("expected artifact at %s: %v", out, err)
	}
}

// TestRunScan_ExplicitConfigWithURLStillErrors confirms the Finding 7 fix
// preserves the legitimate usage error: explicit --config combined with
// --url remains rejected.
func TestRunScan_ExplicitConfigWithURLStillErrors(t *testing.T) {
	cmd := newScanCmdForTest()
	mustSetFlag(t, cmd, "config", "true")
	mustSetFlag(t, cmd, "url", "http://example.com")
	err := runScan(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "--url requires --mcp") {
		t.Fatalf("expected '--url requires --mcp', got: %v", err)
	}
}

// TestResolveScanConcurrency is the Finding 9 regression: the root
// --concurrency / AGENTHOUND_CONCURRENCY value (resolved onto cfg.Concurrency)
// must be honored when --scan-concurrency is unset, while an explicit
// --scan-concurrency always wins.
func TestResolveScanConcurrency(t *testing.T) {
	tests := []struct {
		name            string
		scanConcurrency int
		changed         bool
		cfgConcurrency  int
		want            int
	}{
		{"root fallback when scan-concurrency unset", 5, false, 17, 17},
		{"explicit scan-concurrency wins", 9, true, 17, 9},
		{"scan-concurrency default when cfg is zero", 5, false, 0, 5},
		{"explicit scan-concurrency wins even when cfg unset", 9, true, 0, 9},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveScanConcurrency(tt.scanConcurrency, tt.changed, tt.cfgConcurrency)
			if got != tt.want {
				t.Errorf("resolveScanConcurrency(%d, %v, %d) = %d, want %d",
					tt.scanConcurrency, tt.changed, tt.cfgConcurrency, got, tt.want)
			}
		})
	}
}

// TestAllCollectorsFailed is the Finding 12 regression: scan must exit
// non-zero only when EVERY enabled collector errored. Partial success and a
// legitimately empty-but-successful scan (zero enabled, or zero failed) must
// exit 0 — the decision keys on collector errors, never node count.
func TestAllCollectorsFailed(t *testing.T) {
	tests := []struct {
		name    string
		enabled int
		failed  int
		want    bool
	}{
		{"all failed", 2, 2, true},
		{"single collector failed", 1, 1, true},
		{"partial success", 2, 1, false},
		{"all succeeded", 3, 0, false},
		{"nothing enabled", 0, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := allCollectorsFailed(tt.enabled, tt.failed); got != tt.want {
				t.Errorf("allCollectorsFailed(%d, %d) = %v, want %v",
					tt.enabled, tt.failed, got, tt.want)
			}
		})
	}
}

// TestRunScan_EmptySuccessExitsZero drives runScan end-to-end with a
// config-only scan against an existing file that declares zero servers. The
// config collector succeeds with an empty graph, so runScan must return nil
// (exit 0) — a legitimately empty-but-successful result is not a failure.
func TestRunScan_EmptySuccessExitsZero(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "empty-ok.json")

	cmd := newScanCmdForTest()
	mustSetFlag(t, cmd, "config", "true")
	mustSetFlag(t, cmd, "path", writeEmptyConfig(t))
	mustSetFlag(t, cmd, "scan-output", out)

	if err := runScan(cmd, nil); err != nil {
		t.Fatalf("empty-but-successful scan must exit 0, got: %v", err)
	}
	if _, err := os.Stat(out); err != nil {
		t.Fatalf("expected artifact at %s: %v", out, err)
	}
}

// TestRunScan_AllCollectorsFailExitsNonZero drives runScan end-to-end into
// total failure: --config with a non-existent --path makes the (only enabled)
// config collector error, so runScan must return non-zero AFTER still writing
// the artifact, so the operator keeps the envelope and logs.
func TestRunScan_AllCollectorsFailExitsNonZero(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "all-fail.json")

	cmd := newScanCmdForTest()
	mustSetFlag(t, cmd, "config", "true")
	mustSetFlag(t, cmd, "path", filepath.Join(dir, "no-such-config.json"))
	mustSetFlag(t, cmd, "scan-output", out)

	err := runScan(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "all 1 enabled collector(s) failed") {
		t.Fatalf("expected total-failure error, got: %v", err)
	}
	if _, statErr := os.Stat(out); statErr != nil {
		t.Fatalf("artifact must still be written on total failure: %v", statErr)
	}
}
