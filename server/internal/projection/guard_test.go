package projection

import (
	"testing"
	"time"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/model"
)

func TestReadableCountsGenericAndRegisteredSourceLimitationsOnce(t *testing.T) {
	revision := int64(4)
	now := time.Now().UTC()
	state := &model.ProjectionState{
		Status:            model.ProjectionComplete,
		ScanID:            "scan-4",
		PublishedScanID:   "scan-4",
		PublishedRevision: &revision,
		ActiveCoverageLimitations: []model.PostureCoverageLimitation{{
			CoverageKey: "config:instruction-deep:sha256:root",
			State:       sdkingest.OutcomePartial,
			ScanID:      "scan-4",
			ObservedAt:  now,
		}},
		ActiveCoverageRoots: []model.PostureCoverageRoot{{
			CoverageKey:     "config:instruction-deep:sha256:root",
			State:           sdkingest.OutcomePartial,
			ScanID:          "scan-4",
			ObservedAt:      now,
			ContractCurrent: true,
		}, {
			CoverageKey:     "config:instruction-exact-user:sha256:old",
			State:           sdkingest.OutcomeComplete,
			ScanID:          "scan-3",
			ObservedAt:      now,
			ContractCurrent: false,
		}},
	}

	identity, err := readable(state)
	if err != nil {
		t.Fatalf("readable: %v", err)
	}
	if !identity.CoverageLimited || identity.CoverageLimitationCount != 2 {
		t.Fatalf("limited identity = %+v", identity)
	}
}
