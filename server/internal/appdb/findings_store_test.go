package appdb

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/model"
)

// TestIntegrationFindingOccurrences exercises the generation-scoped current
// reads, full-occurrence persistence/parity, and preserve-vs-clear triage
// patch (skipped without AGENTHOUND_PG_URI).
func TestIntegrationFindingOccurrences(t *testing.T) {
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

	scanStore := NewScanStore(pool)
	fs := NewFindingStore(pool)

	fpCur := "1111111111111111"
	fpStaged := "2222222222222222"
	cleanup := func() {
		_, _ = pool.Exec(ctx, "DELETE FROM scans WHERE id LIKE 'occ-test-%'")
		_, _ = pool.Exec(ctx, "DELETE FROM finding_triage WHERE fingerprint = ANY($1)", []string{fpCur, fpStaged})
	}
	cleanup()
	defer cleanup()

	suffix := time.Now().Format("20060102150405.000000")
	curScan := "occ-test-cur-" + suffix
	stagedScan := "occ-test-staged-" + suffix
	genCur := "occ-gen-cur-" + suffix
	genStaged := "occ-gen-staged-" + suffix

	if err := scanStore.CreateScan(ctx, &model.Scan{
		ID: curScan, Collector: "mcp", Status: model.ScanStatusRunning, StartedAt: time.Now().UTC(),
		GenerationID: genCur, CoverageStatus: ingest.StatusComplete,
	}); err != nil {
		t.Fatalf("create cur scan: %v", err)
	}
	if err := scanStore.PromoteGeneration(ctx, curScan, "mcp"); err != nil {
		t.Fatalf("promote cur: %v", err)
	}
	// A staged (non-current) generation for a different scope; its occurrence
	// must never appear in a default current read.
	if err := scanStore.CreateScan(ctx, &model.Scan{
		ID: stagedScan, Collector: "a2a", Status: model.ScanStatusRunning, StartedAt: time.Now().UTC(),
		GenerationID: genStaged, CoverageStatus: ingest.StatusPartial,
	}); err != nil {
		t.Fatalf("create staged scan: %v", err)
	}

	cost := 0.42
	curFinding := model.Finding{
		ID: fpCur, Severity: "critical", Category: "Data Exfiltration", Title: "exfil",
		EdgeKind: "CAN_EXFILTRATE_VIA", SourceID: "s1", SourceName: "agent", SourceKind: "AgentInstance",
		TargetID: "t1", TargetName: "tool", TargetKind: "MCPTool", Confidence: 0.9,
		OWASPMap: []string{"MCP04"}, ATLASMap: []string{"AML.T0086"},
		GenerationID: genCur, DetectionSubtype: "can_exfiltrate_via", DetectionVersion: "0.1",
		EvidenceDAG: map[string]any{"complete": true}, ConfidenceBasis: "observed",
		AttackCost: &cost, WeightTotal: &cost, WeightMissingCount: 0, Lifecycle: "active",
		RuleManifest: []ingest.RuleManifestEntry{{RuleID: "r1", Version: "1"}},
	}
	if err := fs.InsertFindings(ctx, curScan, []model.Finding{curFinding}); err != nil {
		t.Fatalf("insert cur finding: %v", err)
	}
	if err := fs.InsertFindings(ctx, stagedScan, []model.Finding{{
		ID: fpStaged, Severity: "high", Category: "x", Title: "y", EdgeKind: "SHADOWS",
		SourceKind: "MCPTool", TargetKind: "MCPTool", GenerationID: genStaged,
	}}); err != nil {
		t.Fatalf("insert staged finding: %v", err)
	}

	// Current read scoped to genCur must exclude the staged occurrence.
	items, total, err := fs.ListCurrentFindings(ctx, FindingQuery{GenerationIDs: []string{genCur}, Limit: 10})
	if err != nil {
		t.Fatalf("list current: %v", err)
	}
	if total != 1 || len(items) != 1 || items[0].ID != fpCur {
		t.Fatalf("expected only the current occurrence, got total=%d items=%+v", total, items)
	}
	// Full-occurrence persistence round-trips.
	got := items[0]
	if got.DetectionSubtype != "can_exfiltrate_via" || got.ConfidenceBasis != "observed" {
		t.Errorf("occurrence detection fields not persisted: %+v", got)
	}
	if got.AttackCost == nil || *got.AttackCost != cost {
		t.Errorf("attack_cost not persisted: %v", got.AttackCost)
	}
	if len(got.ATLASMap) != 1 || got.ATLASMap[0] != "AML.T0086" {
		t.Errorf("atlas_map not persisted: %v", got.ATLASMap)
	}
	if len(got.RuleManifest) != 1 || got.RuleManifest[0].RuleID != "r1" {
		t.Errorf("rule_manifest not persisted: %v", got.RuleManifest)
	}
	if got.EvidenceDAG == nil {
		t.Error("evidence_dag not persisted")
	}

	// Detail parity: GetCurrentFinding returns the identical occurrence.
	detail, err := fs.GetCurrentFinding(ctx, []string{genCur}, fpCur)
	if err != nil || detail == nil {
		t.Fatalf("get current finding: %v (finding=%v)", err, detail)
	}
	if detail.AttackCost == nil || *detail.AttackCost != *got.AttackCost || detail.DetectionSubtype != got.DetectionSubtype {
		t.Errorf("list/detail parity broken: list=%+v detail=%+v", got, detail)
	}

	// Empty generation set → no items (never surface staged facts by default).
	empty, emptyTotal, err := fs.ListCurrentFindings(ctx, FindingQuery{Limit: 10})
	if err != nil {
		t.Fatalf("list empty scope: %v", err)
	}
	if emptyTotal != 0 || len(empty) != 0 {
		t.Fatalf("empty generation scope must yield nothing, got total=%d", emptyTotal)
	}

	// PatchTriage preserve-vs-clear.
	confirmed := "confirmed"
	noteVal := "looked at"
	if _, err := fs.PatchTriage(ctx, fpCur, &confirmed, &noteVal); err != nil {
		t.Fatalf("patch set: %v", err)
	}
	// Omit status (preserve), clear note (explicit empty).
	empty2 := ""
	patched, err := fs.PatchTriage(ctx, fpCur, nil, &empty2)
	if err != nil {
		t.Fatalf("patch clear: %v", err)
	}
	if patched.Status != "confirmed" {
		t.Errorf("omitted status must preserve 'confirmed', got %q", patched.Status)
	}
	if patched.Note != "" {
		t.Errorf("explicit empty note must clear, got %q", patched.Note)
	}
}

// TestIntegrationFindingStore exercises the FindingStore against a real
// Postgres (skipped without AGENTHOUND_PG_URI; CI's test-integration job
// wires it). It is the regression guard for the ListLatestPerFingerprint
// outer-SELECT alias bug, where the triage columns referenced the inner
// subquery alias `t` from the outer query and produced
// "missing FROM-clause entry for table t" on every findings read.
func TestIntegrationFindingStore(t *testing.T) {
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

	scanStore := NewScanStore(pool)
	fs := NewFindingStore(pool)

	fpA := "aaaaaaaaaaaaaaaa"
	fpB := "bbbbbbbbbbbbbbbb"
	fpD := "dddddddddddddddd"

	// Make the test hermetic regardless of leftover state: clear any prior
	// fs-test scans (cascade-deletes their findings) and the fixed triage
	// fingerprints up front. finding_triage has no FK, so it survives scan
	// deletion and must be cleared explicitly.
	cleanup := func() {
		_, _ = pool.Exec(ctx, "DELETE FROM scans WHERE id LIKE 'fs-test-%'")
		_, _ = pool.Exec(ctx, "DELETE FROM finding_triage WHERE fingerprint = ANY($1)", []string{fpA, fpB, fpD})
	}
	cleanup()
	// Use defer (not t.Cleanup) so this runs BEFORE the deferred pool.Close()
	// above (defers are LIFO) — the t.Cleanup variant would run after the
	// pool is already closed and silently no-op.
	defer cleanup()

	// ListLatestPerFingerprint is global (not generation-scoped), so on a
	// persistent dev Postgres it also returns unrelated findings from other
	// scans. Scope every count assertion to the fingerprints this test owns so
	// it stays hermetic without wiping data the operator asked us to preserve.
	ownedSet := map[string]bool{fpA: true, fpB: true, fpD: true}
	owned := func(in []model.Finding) []model.Finding {
		out := make([]model.Finding, 0, len(in))
		for _, f := range in {
			if ownedSet[f.ID] {
				out = append(out, f)
			}
		}
		return out
	}

	scanID := "fs-test-" + time.Now().Format("20060102150405.000000")
	scanID2 := scanID + "-2"
	mustScan := func(id string) {
		if err := scanStore.CreateScan(ctx, &model.Scan{
			ID: id, Collector: "mcp", Status: model.ScanStatusRunning, StartedAt: time.Now().UTC(),
		}); err != nil {
			t.Fatalf("create scan %s: %v", id, err)
		}
	}
	mustScan(scanID)
	mustScan(scanID2)

	findings := []model.Finding{
		{ID: fpA, Severity: "critical", Category: "Data Exfiltration", Title: "exfil", EdgeKind: "CAN_EXFILTRATE_VIA",
			SourceID: "s1", SourceName: "agent", SourceKind: "AgentInstance", TargetID: "t1", TargetName: "tool", TargetKind: "MCPTool",
			Confidence: 0.9, OWASPMap: []string{"MCP04", "ASI08"}},
		{ID: fpB, Severity: "high", Category: "Tool Shadowing", Title: "shadow", EdgeKind: "SHADOWS",
			SourceKind: "MCPTool", TargetKind: "MCPTool", Confidence: 0.6},
	}
	if err := fs.InsertFindings(ctx, scanID, findings); err != nil {
		t.Fatalf("insert findings: %v", err)
	}

	// The load-bearing assertion: this read regressed to a 500 before the
	// alias fix.
	all, err := fs.ListLatestPerFingerprint(ctx, "", false)
	if err != nil {
		t.Fatalf("ListLatestPerFingerprint: %v", err)
	}
	if got := owned(all); len(got) != 2 {
		t.Fatalf("expected 2 owned findings, got %d (of %d total)", len(got), len(all))
	}

	crit, err := fs.ListLatestPerFingerprint(ctx, "critical", false)
	if err != nil {
		t.Fatalf("list critical: %v", err)
	}
	if got := owned(crit); len(got) != 1 || got[0].Severity != "critical" {
		t.Fatalf("severity filter: got %+v", got)
	}

	// Suppression: a false-positive is hidden by default, shown with the flag.
	if _, err := fs.UpsertTriage(ctx, fpA, "false-positive", "benign"); err != nil {
		t.Fatalf("upsert triage: %v", err)
	}
	visible, err := fs.ListLatestPerFingerprint(ctx, "", false)
	if err != nil {
		t.Fatalf("list after suppress: %v", err)
	}
	if got := owned(visible); len(got) != 1 {
		t.Fatalf("suppressed finding should be hidden by default; got %d owned visible", len(got))
	}
	withSupp, err := fs.ListLatestPerFingerprint(ctx, "", true)
	if err != nil {
		t.Fatalf("list include-suppressed: %v", err)
	}
	if got := owned(withSupp); len(got) != 2 {
		t.Fatalf("include_suppressed should show all owned; got %d", len(got))
	}
	var sawInlineTriage bool
	for _, f := range withSupp {
		if f.ID == fpA {
			if f.Triage == nil || f.Triage.Status != "false-positive" || f.Triage.Note != "benign" {
				t.Fatalf("expected inline triage {false-positive, benign}, got %+v", f.Triage)
			}
			sawInlineTriage = true
		}
	}
	if !sawInlineTriage {
		t.Fatal("suppressed finding not returned with include_suppressed")
	}

	// GetTriage: present and absent.
	ts, err := fs.GetTriage(ctx, fpA)
	if err != nil || ts == nil || ts.Status != "false-positive" {
		t.Fatalf("GetTriage(fpA): ts=%+v err=%v", ts, err)
	}
	if none, err := fs.GetTriage(ctx, "cccccccccccccccc"); err != nil || none != nil {
		t.Fatalf("GetTriage(unknown): want (nil,nil), got (%+v,%v)", none, err)
	}

	// Diff: scan2 keeps fpA, drops fpB, adds fpD.
	findings2 := []model.Finding{
		findings[0],
		{ID: fpD, Severity: "high", Category: "Cross-Tool Taint", Title: "taint", EdgeKind: "TAINTS",
			SourceKind: "MCPTool", TargetKind: "MCPTool", Confidence: 0.7},
	}
	if err := fs.InsertFindings(ctx, scanID2, findings2); err != nil {
		t.Fatalf("insert findings2: %v", err)
	}
	diff, err := fs.Diff(ctx, scanID, scanID2, false)
	if err != nil {
		t.Fatalf("Diff: %v", err)
	}
	if len(diff.Added) != 1 || diff.Added[0].ID != fpD {
		t.Fatalf("diff.Added = %+v, want [%s]", diff.Added, fpD)
	}
	if len(diff.Removed) != 1 || diff.Removed[0].ID != fpB {
		t.Fatalf("diff.Removed = %+v, want [%s]", diff.Removed, fpB)
	}
	if len(diff.Unchanged) != 1 || diff.Unchanged[0].ID != fpA {
		t.Fatalf("diff.Unchanged = %+v, want [%s]", diff.Unchanged, fpA)
	}
}
