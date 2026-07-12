package action

import (
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

// TestLootResultCoverage is the F5 counterexample: loot coverage is DERIVED
// from the observed probe counters (EndpointsProbed / PartialFailures /
// PartialErrors), never hand-authored or left unknown. An empty artifact is
// clean only when every probe completed; any 401/partial failure downgrades the
// posture so a reader never coalesces it into an all-clear.
func TestLootResultCoverage(t *testing.T) {
	cases := []struct {
		name        string
		res         *LootResult
		wantStatus  ingest.CollectionStatus
		wantMethods int
	}{
		{
			name:       "nil result is unknown",
			res:        nil,
			wantStatus: ingest.StatusUnknown,
		},
		{
			name:       "no probes is unknown (nothing assessed)",
			res:        &LootResult{Summary: LootSummary{EndpointsProbed: 0}},
			wantStatus: ingest.StatusUnknown,
		},
		{
			name:       "all probes succeeded is complete",
			res:        &LootResult{Summary: LootSummary{EndpointsProbed: 3, PartialFailures: 0}},
			wantStatus: ingest.StatusComplete,
		},
		{
			name: "some probes failed is partial with per-method outcome",
			res: &LootResult{
				Summary:       LootSummary{EndpointsProbed: 3, PartialFailures: 1},
				PartialErrors: []string{"key/list: 401 unauthorized"},
			},
			wantStatus:  ingest.StatusPartial,
			wantMethods: 1,
		},
		{
			name: "every probe failed is failed",
			res: &LootResult{
				Summary:       LootSummary{EndpointsProbed: 2, PartialFailures: 2},
				PartialErrors: []string{"model/info: dial", "key/list: 401"},
			},
			wantStatus:  ingest.StatusFailed,
			wantMethods: 2,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cov := tc.res.Coverage("litellm")
			if cov == nil {
				t.Fatal("Coverage returned nil")
			}
			if cov.Status != tc.wantStatus {
				t.Errorf("status = %q, want %q", cov.Status, tc.wantStatus)
			}
			if len(cov.Methods) != tc.wantMethods {
				t.Errorf("methods = %d, want %d: %+v", len(cov.Methods), tc.wantMethods, cov.Methods)
			}
			for _, m := range cov.Methods {
				if m.Status != ingest.StatusFailed {
					t.Errorf("recorded method %q has status %q, want failed", m.Method, m.Status)
				}
				if m.Method == "" {
					t.Errorf("recorded method has empty name: %+v", m)
				}
			}
		})
	}
}

// TestLootResultCoverageConstituentCollector verifies the loot type names the
// constituent collector so the artifact's provenance is reconstructable.
func TestLootResultCoverageConstituentCollector(t *testing.T) {
	res := &LootResult{Summary: LootSummary{EndpointsProbed: 1}}
	cov := res.Coverage("litellm")
	if len(cov.ConstituentCollectors) != 1 || cov.ConstituentCollectors[0] != "loot:litellm" {
		t.Errorf("constituent collectors = %v, want [loot:litellm]", cov.ConstituentCollectors)
	}
	// A partial-error method must carry its parsed message.
	res2 := &LootResult{
		Summary:       LootSummary{EndpointsProbed: 2, PartialFailures: 1},
		PartialErrors: []string{"api/config: 500 internal"},
	}
	cov2 := res2.Coverage("openwebui")
	if len(cov2.Methods) != 1 || cov2.Methods[0].Method != "api/config" || cov2.Methods[0].Error != "500 internal" {
		t.Errorf("method outcome not parsed from partial error: %+v", cov2.Methods)
	}
}
