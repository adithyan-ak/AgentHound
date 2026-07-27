package appdb

import (
	"reflect"
	"testing"
	"time"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/model"
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
		map[string]string{
			absentMCP:   mcpRoot,
			activeMCP:   mcpRoot,
			dirtyConfig: sdkingest.CollectorRootCoverageKey("config"),
		},
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
	}}, []string{targetA}, map[string]string{targetA: mcpRoot}); len(got) != 0 {
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

func TestRegistryUpgradeRetiresChildrenUnderStableRoot(t *testing.T) {
	root := "config:instruction-deep:sha256:stable-root"
	v1Only := "config:instruction-source:sha256:v1-only"
	shared := "config:instruction-source:sha256:shared"
	v2Only := "config:instruction-source:sha256:v2-only"

	retired := retiredCoverageKeys(
		[]sdkingest.CoverageRoot{{
			CoverageKey:       root,
			ChildCoverageKeys: []string{shared, v2Only},
			RegistryContract: &sdkingest.RegistryContract{
				Generation: 2,
				Digest:     "sha256:v2",
			},
		}},
		[]coverageHead{
			{Key: v1Only, Root: root},
			{Key: shared, Root: root},
		},
		nil,
		nil,
	)
	if want := []string{v1Only}; !reflect.DeepEqual(retired, want) {
		t.Fatalf("retired v1 children = %v, want %v", retired, want)
	}
}

func TestComparisonKeyRejectsIncompleteOrOutdatedInstructionRoots(t *testing.T) {
	currentContract := sdkingest.CurrentInstructionRegistryContract()
	root := coverageHead{
		Key:              "config:instruction-deep:sha256:root",
		ScanID:           "deep-1",
		State:            sdkingest.OutcomeTruncated,
		Mode:             sdkingest.InstructionCoverageDeep,
		RegistryContract: &currentContract,
	}
	if got := comparisonKeyWithCoverageHeads("sha256:base", nil, []coverageHead{root}); got != "" {
		t.Fatalf("truncated root comparison key = %q, want empty", got)
	}

	root.State = sdkingest.OutcomeComplete
	outdated := currentContract
	outdated.Generation++
	root.RegistryContract = &outdated
	if got := comparisonKeyWithCoverageHeads("sha256:base", nil, []coverageHead{root}); got != "" {
		t.Fatalf("outdated root comparison key = %q, want empty", got)
	}
}

func TestComparisonSequenceTracksGlobalCurrentProjection(t *testing.T) {
	contract := sdkingest.CurrentInstructionRegistryContract()
	exactKey := "config:instruction-exact-user:sha256:root"
	deepKey := "config:instruction-deep:sha256:root"
	exact := func(scanID string) coverageHead {
		return coverageHead{
			Key:              exactKey,
			ScanID:           scanID,
			State:            sdkingest.OutcomeComplete,
			Mode:             sdkingest.InstructionCoverageExactUser,
			RegistryContract: &contract,
		}
	}
	deep := func(scanID string) coverageHead {
		return coverageHead{
			Key:              deepKey,
			ScanID:           scanID,
			State:            sdkingest.OutcomeComplete,
			Mode:             sdkingest.InstructionCoverageDeep,
			RegistryContract: &contract,
		}
	}

	exactA := comparisonKeyWithCoverageHeads(
		"sha256:exact",
		[]string{exactKey},
		[]coverageHead{exact("exact-a")},
	)
	exactB := comparisonKeyWithCoverageHeads(
		"sha256:exact",
		[]string{exactKey},
		[]coverageHead{exact("exact-b"), deep("deep-d")},
	)
	exactC := comparisonKeyWithCoverageHeads(
		"sha256:exact",
		[]string{exactKey},
		[]coverageHead{exact("exact-c"), deep("deep-d")},
	)
	if exactA == "" || exactB == "" || exactA == exactB {
		t.Fatalf("deep introduction did not invalidate exact baseline: A=%q B=%q", exactA, exactB)
	}
	if exactB != exactC {
		t.Fatalf("unchanged deep head did not stabilize comparison: B=%q C=%q", exactB, exactC)
	}

	afterDeepRefresh := comparisonKeyWithCoverageHeads(
		"sha256:exact",
		[]string{exactKey},
		[]coverageHead{exact("exact-d"), deep("deep-d2")},
	)
	stableAfterRefresh := comparisonKeyWithCoverageHeads(
		"sha256:exact",
		[]string{exactKey},
		[]coverageHead{exact("exact-e"), deep("deep-d2")},
	)
	if afterDeepRefresh == exactC {
		t.Fatal("deep refresh preserved the old exact comparison baseline")
	}
	if afterDeepRefresh != stableAfterRefresh {
		t.Fatal("comparison did not stabilize after unchanged refreshed deep head")
	}
}

func TestActivePostureCoverageRootsExposeCurrentRootState(t *testing.T) {
	contract := sdkingest.CurrentInstructionRegistryContract()
	observedAt := time.Now().UTC()
	roots := activePostureCoverageRoots([]coverageHead{
		{
			Key:              "config:instruction-deep:sha256:root",
			ScanID:           "scan-deep",
			State:            sdkingest.OutcomeTruncated,
			Mode:             sdkingest.InstructionCoverageDeep,
			RegistryContract: &contract,
			UpdatedAt:        observedAt,
		},
		{
			Key:       "mcp:root:sha256:root",
			ScanID:    "scan-mcp",
			State:     sdkingest.OutcomeComplete,
			UpdatedAt: observedAt,
		},
	})
	if len(roots) != 1 {
		t.Fatalf("active instruction roots = %+v, want one", roots)
	}
	if roots[0].Mode != sdkingest.InstructionCoverageDeep ||
		roots[0].State != sdkingest.OutcomeTruncated ||
		roots[0].ScanID != "scan-deep" ||
		!roots[0].ObservedAt.Equal(observedAt) ||
		!roots[0].RegistryContract.Equal(contract) ||
		!roots[0].ContractCurrent {
		t.Fatalf("active root status = %+v", roots[0])
	}
}

func TestPostureCoverageRootsLimitedIncludesOutdatedContract(t *testing.T) {
	if !postureCoverageRootsLimited([]model.PostureCoverageRoot{{
		State:           sdkingest.OutcomeComplete,
		ContractCurrent: false,
	}}) {
		t.Fatal("outdated registered-source contract was treated as complete coverage")
	}
	if postureCoverageRootsLimited([]model.PostureCoverageRoot{{
		State:           sdkingest.OutcomeComplete,
		ContractCurrent: true,
	}}) {
		t.Fatal("current complete registered-source contract was treated as limited")
	}
}
