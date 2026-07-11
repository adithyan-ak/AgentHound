package appdb

import (
	"reflect"
	"testing"
)

func TestDirtyCoverageSurvivesUnrelatedSuccessfulScan(t *testing.T) {
	mcpTarget := "mcp:target:sha256:failed"
	configPath := "config:path:sha256:complete"

	afterMCPFailure := normalizeCoverageKeys(nil, []string{mcpTarget})
	afterConfigBegin := normalizeCoverageKeys(afterMCPFailure, []string{configPath})
	afterConfigSuccess := finalizedDirtyCoverage(
		afterConfigBegin,
		[]string{configPath},
		nil,
		nil,
	)

	if want := []string{mcpTarget}; !reflect.DeepEqual(afterConfigSuccess, want) {
		t.Fatalf(
			"dirty coverage after unrelated config success = %v, want %v",
			afterConfigSuccess,
			want,
		)
	}
	if len(afterConfigSuccess) == 0 {
		t.Fatal("unrelated success would incorrectly permit global publication")
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
