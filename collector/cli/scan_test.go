package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/collector/internal/clientcfg"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/spf13/cobra"
)

func newScanCmdForTest() *cobra.Command {
	cmd := &cobra.Command{RunE: runScan}
	cmd.Flags().Bool("config", false, "")
	cmd.Flags().Bool("mcp", false, "")
	cmd.Flags().Bool("a2a", false, "")
	cmd.Flags().String("path", "", "")
	cmd.Flags().StringSlice("paths", nil, "")
	cmd.Flags().String("project-dir", "", "")
	cmd.Flags().Bool("include-credential-values", false, "")
	cmd.Flags().String("url", "", "")
	cmd.Flags().String("target", "", "")
	cmd.Flags().StringSlice("targets", nil, "")
	cmd.Flags().StringSlice("discover-domain", nil, "")
	cmd.Flags().String("targets-file", "", "")
	cmd.Flags().String("auth-token", "", "")
	cmd.Flags().Int("scan-concurrency", 5, "")
	cmd.Flags().Duration("timeout", 0, "")
	cmd.Flags().Bool("insecure", false, "")
	cmd.Flags().String("scan-output", "", "")
	return cmd
}

func TestRunScan_ConfigWithURL(t *testing.T) {
	cmd := newScanCmdForTest()
	_ = cmd.Flags().Set("config", "true")
	_ = cmd.Flags().Set("url", "http://example.com")
	err := runScan(cmd, nil)
	if err == nil {
		t.Fatal("expected error for --url with --config")
	}
	if !strings.Contains(err.Error(), "--url requires --mcp") {
		t.Errorf("error = %q, want '--url requires --mcp'", err.Error())
	}
}

func TestRunScan_A2ANoTarget(t *testing.T) {
	cmd := newScanCmdForTest()
	_ = cmd.Flags().Set("a2a", "true")
	err := runScan(cmd, nil)
	if err == nil {
		t.Fatal("expected error for A2A without target")
	}
	if !strings.Contains(err.Error(), "A2A requires") {
		t.Errorf("error = %q, want 'A2A requires'", err.Error())
	}
}

// TestRunScan_DefaultOutputCWD verifies that when --output is unset, the
// scan is written to ./scan-<scan_id>.json in the current working directory.
// The test temporarily changes CWD to a tempdir and runs --config (offline,
// no network), then asserts a scan-*.json file appeared.
func TestRunScan_DefaultOutputCWD(t *testing.T) {
	dir := t.TempDir()
	oldCWD, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatalf("chdir: %v", err)
	}
	defer func() { _ = os.Chdir(oldCWD) }()

	cmd := newScanCmdForTest()
	// --config with an existing file that no parser claims → the collector
	// returns an empty graph successfully (a non-existent path would now be
	// a hard error: scan exits non-zero when every collector fails).
	_ = cmd.Flags().Set("config", "true")
	_ = cmd.Flags().Set("path", writeEmptyConfig(t))

	if err := runScan(cmd, nil); err != nil {
		t.Fatalf("runScan: %v", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	var scanFile string
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "scan-") && strings.HasSuffix(e.Name(), ".json") {
			scanFile = e.Name()
			break
		}
	}
	if scanFile == "" {
		var names []string
		for _, e := range entries {
			names = append(names, e.Name())
		}
		t.Fatalf("expected a scan-*.json file in CWD; got: %v", names)
	}

	// Verify the file is valid JSON with the expected meta.
	raw, err := os.ReadFile(filepath.Join(dir, scanFile))
	if err != nil {
		t.Fatalf("read scan: %v", err)
	}
	var got ingest.IngestData
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Meta.Type != "agenthound-ingest" {
		t.Errorf("meta.type = %q, want agenthound-ingest", got.Meta.Type)
	}
	if got.Meta.Collector != "scan" {
		t.Errorf("meta.collector = %q, want scan", got.Meta.Collector)
	}
}

// TestRunScan_HonoursAgentHoundOutputEnv verifies that runScan resolves
// the destination path via cfg.Output, which is populated from the
// AGENTHOUND_OUTPUT env var by clientcfg. Regression for the dead-code
// state where cfg.Output existed but runScan never read it.
func TestRunScan_HonoursAgentHoundOutputEnv(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "env-output.json")

	// Stand up a Config the same way root.go's PersistentPreRunE would,
	// then assign the package-level cfg used by runScan.
	t.Setenv("AGENTHOUND_OUTPUT", target)
	prev := cfg
	defer func() { cfg = prev }()
	cfg = clientcfg.Load()
	if cfg.Output != target {
		t.Fatalf("cfg.Output = %q, want %q", cfg.Output, target)
	}

	cmd := newScanCmdForTest()
	_ = cmd.Flags().Set("config", "true")
	_ = cmd.Flags().Set("path", writeEmptyConfig(t))

	if err := runScan(cmd, nil); err != nil {
		t.Fatalf("runScan: %v", err)
	}

	if _, err := os.Stat(target); err != nil {
		t.Fatalf("expected scan written to %s (from AGENTHOUND_OUTPUT): %v", target, err)
	}

	raw, err := os.ReadFile(target)
	if err != nil {
		t.Fatalf("read scan: %v", err)
	}
	var got ingest.IngestData
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.Meta.Type != "agenthound-ingest" {
		t.Errorf("meta.type = %q, want agenthound-ingest", got.Meta.Type)
	}
}

// writeEmptyConfig writes a JSON file that exists and parses cleanly but
// declares zero MCP servers, so the config collector returns an empty graph
// without error. A non-existent --path is now a hard error (scan exits
// non-zero when every enabled collector fails), so tests that want a quick
// empty-but-successful scan use this instead.
func writeEmptyConfig(t *testing.T) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "empty-config.json")
	if err := os.WriteFile(p, []byte(`{"mcpServers":{}}`), 0o600); err != nil {
		t.Fatalf("write empty config: %v", err)
	}
	return p
}

// TestRunScan_StdoutDash verifies that --output - writes JSON to stdout.
func TestRunScan_StdoutDash(t *testing.T) {
	cmd := newScanCmdForTest()
	_ = cmd.Flags().Set("config", "true")
	_ = cmd.Flags().Set("path", writeEmptyConfig(t))
	_ = cmd.Flags().Set("scan-output", "-")

	out := captureStdout(t, func() {
		if err := runScan(cmd, nil); err != nil {
			t.Fatalf("runScan: %v", err)
		}
	})

	var got ingest.IngestData
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nraw: %q", err, out)
	}
	if got.Meta.Type != "agenthound-ingest" {
		t.Errorf("meta.type = %q, want agenthound-ingest", got.Meta.Type)
	}
}
