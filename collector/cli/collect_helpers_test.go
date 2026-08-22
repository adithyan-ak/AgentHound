package cli

import (
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestValidateCollectorCoverageRejectsUndeclaredAndWrongPrefix(t *testing.T) {
	root := ingest.CollectorRootCoverageKey("scan")
	for _, test := range []struct {
		name    string
		report  *ingest.CollectionReport
		message string
	}{
		{
			name: "undeclared",
			report: &ingest.CollectionReport{
				CoverageKeys: []string{root},
				Outcomes: []ingest.CollectionOutcome{{
					Collector: "mcp", CoverageKey: ingest.CollectorRootCoverageKey("mcp"),
				}},
			},
			message: "not declared",
		},
		{
			name: "wrong prefix",
			report: &ingest.CollectionReport{
				CoverageKeys: []string{root},
				Outcomes:     []ingest.CollectionOutcome{{Collector: "mcp", CoverageKey: root}},
			},
			message: "not owned",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := validateCollectorCoverage(test.report)
			if err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("error = %v, want %q", err, test.message)
			}
		})
	}
}

func TestScanRuntimeOutcomesDeclareCollectorOwnedCoverage(t *testing.T) {
	scanRoot := ingest.CollectorRootCoverageKey("scan")
	runtime := &scanRuntime{
		artifact: &ingest.IngestData{Meta: ingest.IngestMeta{Collection: &ingest.CollectionReport{
			CoverageKeys: []string{scanRoot},
			Outcomes: []ingest.CollectionOutcome{{
				Collector: "scan", CoverageKey: scanRoot, Target: "scan", Method: "autonomous_scan",
				State: ingest.OutcomePartial,
			}},
		}}},
	}
	runtime.addFailure("config", "local_collection", "local", errTestFailure{})
	mcpKey := ingest.CanonicalCoverageKey("mcp", "target", "excluded")
	runtime.addOutcome(ingest.CollectionOutcome{
		Collector: "mcp", CoverageKey: mcpKey, Target: "excluded", Method: "excluded",
		State: ingest.OutcomeNotApplicable,
	})
	if err := validateCollectorCoverage(runtime.artifact.Meta.Collection); err != nil {
		t.Fatal(err)
	}
}

type errTestFailure struct{}

func (errTestFailure) Error() string { return "failure" }
