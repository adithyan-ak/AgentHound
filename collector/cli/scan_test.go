package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/collector/internal/clientcfg"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/sdk/rules"
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
	cmd.Flags().Bool("verbose", false, "")
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

func TestRootedCollectionReportStableAcrossScanIDs(t *testing.T) {
	targetKey := ingest.CanonicalCoverageKey("mcp", "target", "https://mcp.example")
	newScan := func(scanID string) *ingest.IngestData {
		data := common.NewIngestData("mcp", scanID)
		data.Meta.Collection = &ingest.CollectionReport{
			State:        ingest.OutcomeComplete,
			CoverageKeys: []string{targetKey},
			Outcomes: []ingest.CollectionOutcome{{
				Collector:   "mcp",
				CoverageKey: targetKey,
				Target:      "https://mcp.example",
				Method:      "enumerate",
				State:       ingest.OutcomeComplete,
				Items:       1,
			}},
		}
		data.Graph.Nodes = []ingest.Node{{
			ID:                 "mcp-server",
			Kinds:              []string{"MCPServer"},
			ObservationDomains: []string{targetKey},
		}}
		return data
	}

	first := newScan("scan-one")
	second := newScan("scan-two")
	firstReport := rootedCollectionReport("mcp", first.Meta.Collection, true)
	secondReport := rootedCollectionReport("mcp", second.Meta.Collection, true)
	rootKey := collectorRootCoverageKey("mcp")
	wantRootKey := ingest.CanonicalCoverageKey("mcp", "root", "collect")

	if rootKey != wantRootKey {
		t.Fatalf("collector root key = %q, want %q", rootKey, wantRootKey)
	}
	for scanID, report := range map[string]*ingest.CollectionReport{
		first.Meta.ScanID:  firstReport,
		second.Meta.ScanID: secondReport,
	} {
		states := ingest.CoverageStates(report)
		if states[rootKey] != ingest.OutcomeComplete {
			t.Fatalf("scan %s root state = %q, want complete", scanID, states[rootKey])
		}
		if states[targetKey] != ingest.OutcomeComplete {
			t.Fatalf("scan %s target state = %q, want complete", scanID, states[targetKey])
		}
	}
	if firstReport.CoverageKeys[0] != secondReport.CoverageKeys[0] {
		t.Fatalf(
			"collector root changed across scan IDs: %v != %v",
			firstReport.CoverageKeys,
			secondReport.CoverageKeys,
		)
	}
	if len(firstReport.AuthoritativeRoots) != 1 ||
		firstReport.AuthoritativeRoots[0].CoverageKey != rootKey ||
		len(firstReport.AuthoritativeRoots[0].ChildCoverageKeys) != 1 ||
		firstReport.AuthoritativeRoots[0].ChildCoverageKeys[0] != targetKey {
		t.Fatalf("authoritative root = %+v, want root with target child", firstReport.AuthoritativeRoots)
	}
	for _, data := range []*ingest.IngestData{first, second} {
		if got := data.Graph.Nodes[0].ObservationDomains; len(got) != 1 || got[0] != targetKey {
			t.Fatalf("scan %s fact ownership = %v, want [%s]", data.Meta.ScanID, got, targetKey)
		}
	}
}

func TestRootedCollectionReportPreservesPartialAttempt(t *testing.T) {
	targetKey := ingest.CanonicalCoverageKey("mcp", "target", "https://mcp.example")
	report := rootedCollectionReport("mcp", &ingest.CollectionReport{
		State:        ingest.OutcomePartial,
		CoverageKeys: []string{targetKey},
		Outcomes: []ingest.CollectionOutcome{{
			Collector:   "mcp",
			CoverageKey: targetKey,
			State:       ingest.OutcomeFailed,
		}},
	}, true)

	states := ingest.CoverageStates(report)
	if states[collectorRootCoverageKey("mcp")] != ingest.OutcomePartial {
		t.Fatalf("root states = %v, want partial MCP root", states)
	}
	if roots := ingest.CompleteAuthoritativeRoots(report); len(roots) != 0 {
		t.Fatalf("partial run became authoritative: %+v", roots)
	}
}

func TestRootedCollectionReportTargetedRunIsNotAuthoritative(t *testing.T) {
	targetKey := ingest.CanonicalCoverageKey("mcp", "target", "https://mcp.example")
	report := rootedCollectionReport("mcp", &ingest.CollectionReport{
		State:        ingest.OutcomeComplete,
		CoverageKeys: []string{targetKey},
		Outcomes: []ingest.CollectionOutcome{{
			Collector:   "mcp",
			CoverageKey: targetKey,
			State:       ingest.OutcomeComplete,
		}},
	}, false)

	if len(report.AuthoritativeRoots) != 0 {
		t.Fatalf("targeted run declared authoritative roots: %+v", report.AuthoritativeRoots)
	}
}

func TestFailedCollectionReportUsesCollectorRoot(t *testing.T) {
	report := failedCollectionReport("mcp", errors.New("collector failed"))
	rootKey := collectorRootCoverageKey("mcp")

	if len(report.CoverageKeys) != 1 || report.CoverageKeys[0] != rootKey {
		t.Fatalf("failed coverage keys = %v, want [%s]", report.CoverageKeys, rootKey)
	}
	states := ingest.CoverageStates(report)
	if states[rootKey] != ingest.OutcomeFailed {
		t.Fatalf("failed root states = %v, want failed MCP root", states)
	}
	if got := report.Outcomes[0].Error; got != "collector failed" {
		t.Fatalf("failed root error = %q, want collector failed", got)
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
	if got.Meta.Version != ingest.CurrentVersion {
		t.Errorf("meta.version = %d, want strict version %d", got.Meta.Version, ingest.CurrentVersion)
	}
	if got.Meta.Collection == nil || got.Meta.Collection.State != ingest.OutcomeComplete {
		t.Errorf("complete-empty config coverage lost: %+v", got.Meta.Collection)
	}
	if got.Meta.Ruleset == nil || got.Meta.Ruleset.Digest == "" ||
		len(got.Meta.Ruleset.Entries) == 0 {
		t.Errorf("effective rules manifest missing: %+v", got.Meta.Ruleset)
	}
	if got.Graph.Nodes == nil || got.Graph.Edges == nil {
		t.Fatalf("complete-empty graph serialized null collections: %+v", got.Graph)
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

func TestLoadEffectiveRulesPersistsMatchersAndLoadFailures(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("AGENTHOUND_RULES_DIR", dir)
	rules.SetBundleOverridePath("")
	defer rules.SetBundleOverridePath("")
	if err := os.WriteFile(
		filepath.Join(dir, "broken.yaml"),
		[]byte("{{not yaml"),
		0o600,
	); err != nil {
		t.Fatalf("write broken rule: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(dir, "valid.yaml"),
		[]byte(`
id: collector-custom-rule
name: Collector custom rule
version: 4
severity: medium
scope:
  collector: mcp
  targets: [tool.description]
matcher:
  type: keyword
  keywords: [collector-custom]
emit:
  finding_type: custom
`),
		0o600,
	); err != nil {
		t.Fatalf("write valid rule: %v", err)
	}

	engine, manifest := loadEffectiveRules()
	if engine == nil {
		t.Fatal("effective rules engine is nil")
	}
	if manifest.LoadState != ingest.OutcomePartial ||
		manifest.Authenticity != "unverified" ||
		len(manifest.Errors) == 0 ||
		!strings.Contains(strings.Join(manifest.Errors, "\n"), "broken.yaml") {
		t.Fatalf("effective rules manifest = %+v", manifest)
	}
	var found bool
	for _, entry := range manifest.Entries {
		if entry.ID != "collector-custom-rule" {
			continue
		}
		found = entry.Version == 4 &&
			strings.Contains(
				string(entry.EffectiveMatcher),
				`"keywords":["collector-custom"]`,
			)
	}
	if !found {
		t.Fatalf("custom effective matcher absent: %+v", manifest.Entries)
	}
}

func TestLoadEffectiveRulesRecordsNativeJupyterDetector(t *testing.T) {
	rules.SetBundleOverridePath("")
	t.Cleanup(func() { rules.SetBundleOverridePath("") })

	_, manifest := loadEffectiveRules()
	var foundNative bool
	for _, entry := range manifest.Entries {
		if entry.Type == "fingerprint" &&
			(entry.ID == "jupyter" || strings.Contains(string(entry.EffectiveMatcher), `"service_kind":"jupyter"`)) {
			t.Fatalf("Jupyter YAML was recorded as executed semantics: %+v", entry)
		}
		if entry.Type == "detector" && entry.ID == "jupyter-http-native" {
			foundNative = entry.Version == 1 &&
				entry.Source == "builtin" &&
				strings.Contains(string(entry.EffectiveMatcher), `"path":"/api/status"`) &&
				strings.Contains(string(entry.EffectiveMatcher), `"status_codes":[401,403]`)
		}
	}
	if !foundNative {
		t.Fatalf("native Jupyter detector semantics absent: %+v", manifest.Entries)
	}
}

func TestLoadEffectiveRulesRecordsExecutedJupyterBundleOverride(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "jupyter.yaml"), []byte(`
id: jupyter
name: Jupyter override
version: 9
service_kind: jupyter
probes:
  - method: GET
    path: /bundle-jupyter
    matchers:
      - type: http_status
        status_code: 200
emit:
  node_kinds: [JupyterServer, AIService]
  properties:
    service_kind: jupyter
`), 0o600); err != nil {
		t.Fatalf("write Jupyter override: %v", err)
	}
	rules.SetBundleOverridePath(dir)
	t.Cleanup(func() { rules.SetBundleOverridePath("") })

	_, manifest := loadEffectiveRules()
	var foundOverride bool
	for _, entry := range manifest.Entries {
		if entry.Type == "detector" && entry.ID == "jupyter-http-native" {
			t.Fatalf("native detector recorded while bundle override is effective: %+v", entry)
		}
		if entry.Type == "fingerprint" && entry.ID == "jupyter" {
			foundOverride = entry.Version == 9 && entry.Source == "bundle" &&
				strings.Contains(string(entry.EffectiveMatcher), `"path":"/bundle-jupyter"`)
		}
	}
	if !foundOverride {
		t.Fatalf("executed Jupyter override absent: %+v", manifest.Entries)
	}
}

func TestLoadEffectiveRulesRejectsUnexecutableJupyterBundleRule(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "alternate.yaml"), []byte(`
id: alternate-jupyter
name: Unsupported alternate Jupyter rule
version: 1
service_kind: jupyter
probes:
  - method: GET
    path: /alternate
    matchers:
      - type: http_status
        status_code: 200
emit:
  node_kinds: [JupyterServer, AIService]
`), 0o600); err != nil {
		t.Fatalf("write alternate Jupyter rule: %v", err)
	}
	rules.SetBundleOverridePath(dir)
	t.Cleanup(func() { rules.SetBundleOverridePath("") })

	_, manifest := loadEffectiveRules()
	if manifest.LoadState != ingest.OutcomePartial ||
		!strings.Contains(strings.Join(manifest.Errors, "\n"), "alternate-jupyter") {
		t.Fatalf("unsupported Jupyter rule was not reported: %+v", manifest)
	}
	for _, entry := range manifest.Entries {
		if entry.ID == "alternate-jupyter" {
			t.Fatalf("unexecutable Jupyter rule was recorded as effective: %+v", entry)
		}
	}
}

func TestLoadEffectiveRulesRejectsWrongKindJupyterOverrideWithoutNativeFallback(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "jupyter.yaml"), []byte(`
id: jupyter
name: Misdirected Jupyter override
version: 2
service_kind: ollama
probes:
  - method: GET
    path: /wrong-kind
    matchers:
      - type: http_status
        status_code: 200
emit:
  node_kinds: [JupyterServer, AIService]
`), 0o600); err != nil {
		t.Fatalf("write wrong-kind Jupyter override: %v", err)
	}
	rules.SetBundleOverridePath(dir)
	t.Cleanup(func() { rules.SetBundleOverridePath("") })

	_, manifest := loadEffectiveRules()
	if manifest.LoadState != ingest.OutcomePartial ||
		!strings.Contains(strings.Join(manifest.Errors, "\n"), "service_kind") {
		t.Fatalf("wrong-kind Jupyter override was not reported: %+v", manifest)
	}
	for _, entry := range manifest.Entries {
		if entry.ID == "jupyter" || entry.ID == "jupyter-http-native" {
			t.Fatalf("non-executed Jupyter semantics recorded: %+v", entry)
		}
	}
}

func TestLoadEffectiveRulesRejectsJupyterOverrideWithoutRequiredLabels(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "jupyter.yaml"), []byte(`
id: jupyter
name: Structurally invalid Jupyter override
version: 2
service_kind: jupyter
probes:
  - method: GET
    path: /jupyter
    matchers:
      - type: http_status
        status_code: 200
emit:
  node_kinds: [AIService]
`), 0o600); err != nil {
		t.Fatalf("write invalid-label Jupyter override: %v", err)
	}
	rules.SetBundleOverridePath(dir)
	t.Cleanup(func() { rules.SetBundleOverridePath("") })

	_, manifest := loadEffectiveRules()
	if manifest.LoadState != ingest.OutcomePartial ||
		!strings.Contains(strings.Join(manifest.Errors, "\n"), "JupyterServer") {
		t.Fatalf("invalid-label Jupyter override was not reported: %+v", manifest)
	}
	for _, entry := range manifest.Entries {
		if entry.ID == "jupyter" || entry.ID == "jupyter-http-native" {
			t.Fatalf("non-executed Jupyter semantics recorded: %+v", entry)
		}
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
