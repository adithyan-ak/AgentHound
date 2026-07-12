package appdb

import (
	"reflect"
	"testing"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
)

func finalizeCoverageAttempt(
	inherited []string,
	coverage []string,
	complete []string,
	dirty []string,
) []string {
	begun := normalizeCoverageKeys(inherited, coverage)
	return finalizedDirtyCoverage(begun, complete, nil, dirty)
}

func TestDirtyCollectorRootClearedByLaterCompleteRoot(t *testing.T) {
	const (
		failedScanID   = "mcp-scan-failed"
		completeScanID = "mcp-scan-complete"
	)
	mcpRoot := sdkingest.CanonicalCoverageKey("mcp", "root", "collect")
	mcpTarget := sdkingest.CanonicalCoverageKey("mcp", "target", "https://mcp.example")

	dirty := finalizeCoverageAttempt(
		nil,
		[]string{mcpRoot},
		nil,
		[]string{mcpRoot},
	)
	if want := []string{mcpRoot}; !reflect.DeepEqual(dirty, want) {
		t.Fatalf("dirty coverage after %s = %v, want %v", failedScanID, dirty, want)
	}

	dirty = finalizeCoverageAttempt(
		dirty,
		[]string{mcpRoot, mcpTarget},
		[]string{mcpRoot, mcpTarget},
		nil,
	)
	if len(dirty) != 0 {
		t.Fatalf(
			"dirty coverage after %s then %s = %v, want none",
			failedScanID,
			completeScanID,
			dirty,
		)
	}
}

func TestPartialCollectorRootRemainsDirty(t *testing.T) {
	const (
		failedScanID  = "mcp-scan-failed"
		partialScanID = "mcp-scan-partial"
	)
	mcpRoot := sdkingest.CanonicalCoverageKey("mcp", "root", "collect")
	complete := sdkingest.CanonicalCoverageKey("mcp", "target", "https://complete.example")
	failed := sdkingest.CanonicalCoverageKey("mcp", "target", "https://failed.example")

	dirty := finalizeCoverageAttempt(
		nil,
		[]string{mcpRoot},
		nil,
		[]string{mcpRoot},
	)
	dirty = finalizeCoverageAttempt(
		dirty,
		[]string{mcpRoot, complete, failed},
		[]string{complete},
		[]string{mcpRoot, failed},
	)

	if want := []string{mcpRoot, failed}; !reflect.DeepEqual(dirty, want) {
		t.Fatalf(
			"dirty coverage after %s then %s = %v, want %v",
			failedScanID,
			partialScanID,
			dirty,
			want,
		)
	}
}

func TestDirtyMCPRootSurvivesCompleteConfigScan(t *testing.T) {
	const (
		mcpScanID    = "mcp-scan-failed"
		configScanID = "config-scan-complete"
	)
	mcpRoot := sdkingest.CanonicalCoverageKey("mcp", "root", "collect")
	configRoot := sdkingest.CanonicalCoverageKey("config", "root", "collect")
	configPath := sdkingest.CanonicalCoverageKey("config", "path", "/tmp/config.json")

	dirty := finalizeCoverageAttempt(
		nil,
		[]string{mcpRoot},
		nil,
		[]string{mcpRoot},
	)
	dirty = finalizeCoverageAttempt(
		dirty,
		[]string{configRoot, configPath},
		[]string{configRoot, configPath},
		nil,
	)

	if want := []string{mcpRoot}; !reflect.DeepEqual(dirty, want) {
		t.Fatalf(
			"dirty coverage after %s then %s = %v, want %v",
			mcpScanID,
			configScanID,
			dirty,
			want,
		)
	}
}

func TestFinalizedDirtyCoverageClearsOnlyExactReplacement(t *testing.T) {
	targetA := "a2a:target:sha256:a"
	targetB := "a2a:target:sha256:b"
	got := finalizedDirtyCoverage(
		[]string{targetA, targetB},
		[]string{targetB},
		nil,
		nil,
	)
	if want := []string{targetA}; !reflect.DeepEqual(got, want) {
		t.Fatalf("remaining dirty coverage = %v, want %v", got, want)
	}
}

func TestRetiredCoverageKeysDiffsOnlyAuthoritativeRootChildren(t *testing.T) {
	mcpRoot := sdkingest.CanonicalCoverageKey("mcp", "root", "collect")
	configRoot := sdkingest.CanonicalCoverageKey("config", "root", "collect")
	targetA := sdkingest.CanonicalCoverageKey("mcp", "target", "a")
	targetB := sdkingest.CanonicalCoverageKey("mcp", "target", "b")
	configPath := sdkingest.CanonicalCoverageKey("config", "path", "/tmp/config")

	got := retiredCoverageKeys(
		[]sdkingest.CoverageRoot{{
			CoverageKey:       mcpRoot,
			ChildCoverageKeys: []string{targetB},
		}},
		[]coverageHead{
			{Key: targetA, Root: mcpRoot},
			{Key: targetB, Root: mcpRoot},
			{Key: configPath, Root: configRoot},
		},
		nil,
	)
	if want := []string{targetA}; !reflect.DeepEqual(got, want) {
		t.Fatalf("retired coverage = %v, want %v", got, want)
	}
}

func TestRetiredCoverageKeysIncludesOnlyAbsentInheritedDirtyChildren(t *testing.T) {
	mcpRoot := sdkingest.CollectorRootCoverageKey("mcp")
	absentMCP := sdkingest.CanonicalCoverageKey("mcp", "target", "absent")
	activeMCP := sdkingest.CanonicalCoverageKey("mcp", "target", "active")
	dirtyConfig := sdkingest.CanonicalCoverageKey("config", "path", "/tmp/config")

	got := retiredCoverageKeys(
		[]sdkingest.CoverageRoot{{
			CoverageKey:       mcpRoot,
			ChildCoverageKeys: []string{activeMCP},
		}},
		nil,
		[]string{absentMCP, activeMCP, dirtyConfig},
	)
	if want := []string{absentMCP}; !reflect.DeepEqual(got, want) {
		t.Fatalf("retired inherited dirty coverage = %v, want %v", got, want)
	}
}

func TestRetiredCoverageKeysTargetedRunIsNonAuthoritative(t *testing.T) {
	mcpRoot := sdkingest.CanonicalCoverageKey("mcp", "root", "collect")
	targetA := sdkingest.CanonicalCoverageKey("mcp", "target", "a")
	if got := retiredCoverageKeys(nil, []coverageHead{{
		Key: targetA, Root: mcpRoot,
	}}, []string{targetA}); len(got) != 0 {
		t.Fatalf("targeted run retired sibling coverage: %v", got)
	}
}

func TestComparisonKeyIncludesOtherCoverageHeadRevisions(t *testing.T) {
	current := "config:path:sha256:current"
	other := "mcp:target:sha256:other"
	first := comparisonKeyWithCoverageHeads(
		"sha256:base",
		[]string{current},
		[]coverageHead{
			{Key: current, ScanID: "config-scan-1"},
			{Key: other, ScanID: "mcp-scan-1"},
		},
	)
	currentRevisionChanged := comparisonKeyWithCoverageHeads(
		"sha256:base",
		[]string{current},
		[]coverageHead{
			{Key: current, ScanID: "config-scan-2"},
			{Key: other, ScanID: "mcp-scan-1"},
		},
	)
	otherRevisionChanged := comparisonKeyWithCoverageHeads(
		"sha256:base",
		[]string{current},
		[]coverageHead{
			{Key: current, ScanID: "config-scan-2"},
			{Key: other, ScanID: "mcp-scan-2"},
		},
	)

	if first == "" || first != currentRevisionChanged {
		t.Fatalf("current-scope head must be excluded: %q != %q", first, currentRevisionChanged)
	}
	if first == otherRevisionChanged {
		t.Fatal("comparison remained valid after another active scope changed")
	}
}
