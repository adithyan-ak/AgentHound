package appdb

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/model"
)

func TestMarshalUnmarshalCoverageRoundTrip(t *testing.T) {
	in := &ingest.CollectionCoverage{
		Status:                ingest.StatusPartial,
		ConstituentCollectors: []string{"mcp"},
		Methods: []ingest.MethodOutcome{
			{Target: "srv", Method: "tools/list", Status: ingest.StatusFailed, Error: "timeout"},
		},
	}
	data, err := marshalCoverage(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, err := unmarshalCoverage(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out == nil {
		t.Fatal("expected non-nil coverage")
	}
	if out.Status != ingest.StatusPartial {
		t.Errorf("status: got %q", out.Status)
	}
	if len(out.Methods) != 1 || out.Methods[0].Status != ingest.StatusFailed {
		t.Errorf("methods not preserved: %+v", out.Methods)
	}
}

func TestUnmarshalCoverageEmptyIsNil(t *testing.T) {
	for _, empty := range [][]byte{nil, []byte("{}"), []byte("null")} {
		out, err := unmarshalCoverage(empty)
		if err != nil {
			t.Fatalf("unmarshal %q: %v", empty, err)
		}
		// {} decodes to a zeroed struct; nil/null decode to nil. Both are
		// acceptable "no manifest" representations — the point is no panic and
		// no error.
		_ = out
	}
}

func TestMarshalUnmarshalStageStatesRoundTrip(t *testing.T) {
	in := map[string]ingest.StageState{
		ingest.StageWrite:     ingest.StageSucceeded,
		ingest.StageSnapshot:  ingest.StageFailed,
		ingest.StagePromotion: ingest.StageSkipped,
	}
	data, err := marshalStageStates(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	out, err := unmarshalStageStates(data)
	if err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if out[ingest.StageWrite] != ingest.StageSucceeded || out[ingest.StageSnapshot] != ingest.StageFailed {
		t.Errorf("stage states not preserved: %+v", out)
	}
}

// TestIntegrationGenerationLifecycle exercises the generation-aware store
// methods against a real Postgres (skipped without AGENTHOUND_PG_URI).
func TestIntegrationGenerationLifecycle(t *testing.T) {
	skipIfNoPG(t)
	ctx := context.Background()

	pool, err := NewPool(os.Getenv("AGENTHOUND_PG_URI"))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	store := NewScanStore(pool)

	suffix := time.Now().Format("20060102150405.000000")
	scopeCollector := "genlifecycle-" + suffix
	scanA := "gen-a-" + suffix
	scanB := "gen-b-" + suffix
	// Use defer (not t.Cleanup): defers run before the deferred pool.Close()
	// above (LIFO within the test body), whereas a t.Cleanup would fire only
	// after the pool is already closed and the DELETE would silently no-op,
	// leaking is_current genlifecycle generations into the shared dev database.
	defer func() {
		_, _ = pool.Exec(ctx, "DELETE FROM scans WHERE collector = $1", scopeCollector)
	}()

	// Scan A: complete generation.
	if err := store.CreateScan(ctx, &model.Scan{
		ID: scanA, Collector: scopeCollector, Status: model.ScanStatusRunning,
		StartedAt: time.Now().UTC().Add(-time.Minute), GenerationID: "gen-a",
		CoverageStatus: ingest.StatusComplete,
		Coverage:       &ingest.CollectionCoverage{Status: ingest.StatusComplete},
	}); err != nil {
		t.Fatalf("create A: %v", err)
	}
	if err := store.UpdateScan(ctx, scanA, model.ScanStatusCompleted, 3, 2, ""); err != nil {
		t.Fatalf("update A: %v", err)
	}
	// Record the full promotion-gate stage set: PriorValidScanForScope only
	// rematerializes a generation that passed the same gate promotion required
	// (write succeeded, post-processing + snapshot succeeded/skipped), so a
	// realistic complete generation must record all three.
	if err := store.RecordGenerationOutcome(ctx, &model.Scan{
		ID: scanA, GenerationID: "gen-a", CoverageStatus: ingest.StatusComplete,
		StageStates: map[string]ingest.StageState{
			ingest.StageWrite:          ingest.StageSucceeded,
			ingest.StagePostProcessing: ingest.StageSucceeded,
			ingest.StageSnapshot:       ingest.StageSucceeded,
		},
		NodeInventory: &ingest.InventoryDelta{Created: 3, BeforeTotal: 0, AfterTotal: 3},
	}); err != nil {
		t.Fatalf("record A: %v", err)
	}
	if err := store.PromoteGeneration(ctx, scanA, scopeCollector); err != nil {
		t.Fatalf("promote A: %v", err)
	}

	cur, err := store.CurrentScanForScope(ctx, scopeCollector)
	if err != nil || cur == nil || cur.ID != scanA {
		t.Fatalf("current after A: %v (scan=%v)", err, cur)
	}
	if !cur.IsCurrent || cur.GenerationID != "gen-a" {
		t.Errorf("A read-back: is_current=%v gen=%q", cur.IsCurrent, cur.GenerationID)
	}
	if cur.NodeInventory == nil || cur.NodeInventory.Created != 3 {
		t.Errorf("A inventory not persisted: %+v", cur.NodeInventory)
	}
	if cur.StageStates[ingest.StageWrite] != ingest.StageSucceeded {
		t.Errorf("A stage states not persisted: %+v", cur.StageStates)
	}

	// Scan B: newer generation for the same scope; promotion demotes A.
	if err := store.CreateScan(ctx, &model.Scan{
		ID: scanB, Collector: scopeCollector, Status: model.ScanStatusRunning,
		StartedAt: time.Now().UTC(), GenerationID: "gen-b",
	}); err != nil {
		t.Fatalf("create B: %v", err)
	}
	if err := store.UpdateScan(ctx, scanB, model.ScanStatusCompleted, 4, 3, ""); err != nil {
		t.Fatalf("update B: %v", err)
	}
	if err := store.PromoteGeneration(ctx, scanB, scopeCollector); err != nil {
		t.Fatalf("promote B: %v", err)
	}

	cur, err = store.CurrentScanForScope(ctx, scopeCollector)
	if err != nil || cur == nil || cur.ID != scanB {
		t.Fatalf("current after B: %v (scan=%v)", err, cur)
	}

	// A is the prior valid generation to rematerialize if B is deleted.
	prior, err := store.PriorValidScanForScope(ctx, scopeCollector, scanB)
	if err != nil || prior == nil || prior.ID != scanA {
		t.Fatalf("prior valid for B: %v (scan=%v)", err, prior)
	}
}
