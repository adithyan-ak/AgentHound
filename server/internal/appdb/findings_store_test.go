package appdb

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/adithyan-ak/agenthound/server/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type emptyReplacementTx struct {
	pgx.Tx
	query string
	args  []any
}

func (tx *emptyReplacementTx) Exec(
	_ context.Context,
	query string,
	args ...any,
) (pgconn.CommandTag, error) {
	tx.query = query
	tx.args = args
	return pgconn.NewCommandTag("DELETE 1"), nil
}

func TestReplaceFindingsTxEmptyDeletesPriorSnapshot(t *testing.T) {
	tx := &emptyReplacementTx{}
	if err := replaceFindingsTx(
		context.Background(),
		tx,
		"same-scan-id",
		[]model.Finding{},
	); err != nil {
		t.Fatalf("replace empty findings: %v", err)
	}
	if tx.query != `DELETE FROM findings WHERE scan_id = $1` {
		t.Fatalf("replacement query = %q, want per-scan delete", tx.query)
	}
	if len(tx.args) != 1 || tx.args[0] != "same-scan-id" {
		t.Fatalf("replacement args = %#v, want [same-scan-id]", tx.args)
	}
}

// TestIntegrationFindingStore exercises immutable per-scan finding snapshots
// against a real Postgres (skipped without AGENTHOUND_PG_URI).
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
	replaceFindings := func(id string, snapshot []model.Finding) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin findings replacement: %v", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := replaceFindingsTx(ctx, tx, id, snapshot); err != nil {
			t.Fatalf("replace findings for %s: %v", id, err)
		}
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit findings replacement for %s: %v", id, err)
		}
	}

	findings := []model.Finding{
		{ID: fpA, Severity: "critical", Category: "Data Exfiltration", Title: "exfil", EdgeKind: "CAN_EXFILTRATE_VIA",
			SourceID: "s1", SourceName: "agent", SourceKind: "AgentInstance", TargetID: "t1", TargetName: "tool", TargetKind: "MCPTool",
			Confidence: 0.9, Variant: model.FindingVariantDefault,
			Evidence: model.FindingEvidence{
				State: model.FindingEvidenceInferred, Detector: "mcp",
				Channels: []string{"file_write"},
			},
			ExactEvidence: &model.ExactFindingEvidence{
				Version: 1, Complete: true, Reasons: []string{},
				Nodes: []model.ExactFindingEvidenceNode{
					{ID: "s1", Kinds: []string{"AgentInstance"}, Properties: map[string]any{"name": "agent"}},
					{ID: "t1", Kinds: []string{"MCPTool"}, Properties: map[string]any{"name": "tool"}},
				},
				Edges: []model.ExactFindingEvidenceEdge{{
					Source: "s1", Target: "t1", Kind: "PROVIDES_TOOL",
					Properties: map[string]any{"risk_weight": 0.1},
				}},
			},
			OWASPMap: []string{"MCP04", "ASI08"}, ATLASMap: []string{"AML.T0086"}},
		{ID: fpB, Severity: "high", Category: "Tool Shadowing", Title: "shadow", EdgeKind: "SHADOWS",
			SourceKind: "MCPTool", TargetKind: "MCPTool", Confidence: 0.6},
	}
	replaceFindings(scanID, findings)

	// The load-bearing assertion: this read regressed to a 500 before the
	// alias fix.
	all, err := fs.ListForScan(ctx, scanID, "", false)
	if err != nil {
		t.Fatalf("ListForScan: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("expected 2 findings, got %d", len(all))
	}
	var foundATLAS bool
	for _, f := range all {
		if f.ID == fpA {
			if len(f.ATLASMap) != 1 || f.ATLASMap[0] != "AML.T0086" {
				t.Fatalf("persisted atlas_map = %v, want [AML.T0086]", f.ATLASMap)
			}
			if f.Variant != model.FindingVariantDefault ||
				f.Evidence.State != model.FindingEvidenceInferred ||
				len(f.Evidence.Channels) != 1 ||
				f.Evidence.Channels[0] != "file_write" {
				t.Fatalf("persisted finding evidence = %+v", f)
			}
			if f.ExactEvidence == nil ||
				!f.ExactEvidence.Complete ||
				len(f.ExactEvidence.Nodes) != 2 ||
				len(f.ExactEvidence.Edges) != 1 {
				t.Fatalf("persisted exact evidence = %+v", f.ExactEvidence)
			}
			foundATLAS = true
		}
	}
	if !foundATLAS {
		t.Fatal("ATLAS-mapped finding not returned from persisted list")
	}

	crit, err := fs.ListForScan(ctx, scanID, "critical", false)
	if err != nil {
		t.Fatalf("list critical: %v", err)
	}
	if len(crit) != 1 || crit[0].Severity != "critical" {
		t.Fatalf("severity filter: got %+v", crit)
	}

	// Suppression: a false-positive is hidden by default, shown with the flag.
	if _, err := fs.UpsertTriage(ctx, fpA, "false-positive", "benign"); err != nil {
		t.Fatalf("upsert triage: %v", err)
	}
	visible, err := fs.ListForScan(ctx, scanID, "", false)
	if err != nil {
		t.Fatalf("list after suppress: %v", err)
	}
	if len(visible) != 1 {
		t.Fatalf("suppressed finding should be hidden by default; got %d visible", len(visible))
	}
	withSupp, err := fs.ListForScan(ctx, scanID, "", true)
	if err != nil {
		t.Fatalf("list include-suppressed: %v", err)
	}
	if len(withSupp) != 2 {
		t.Fatalf("include_suppressed should show all; got %d", len(withSupp))
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

	// A real-store status-only update must preserve the existing note. The
	// handler's pointer semantics are insufficient if the SQL conflict clause
	// still overwrites note.
	statusOnly, err := fs.UpdateTriageStatus(ctx, fpA, "confirmed")
	if err != nil {
		t.Fatalf("UpdateTriageStatus: %v", err)
	}
	if statusOnly.Status != "confirmed" || statusOnly.Note != "benign" {
		t.Fatalf("status-only update = %+v, want confirmed with preserved note", statusOnly)
	}
	persistedTriage, err := fs.GetTriage(ctx, fpA)
	if err != nil {
		t.Fatalf("GetTriage after status-only update: %v", err)
	}
	if persistedTriage == nil || persistedTriage.Status != "confirmed" || persistedTriage.Note != "benign" {
		t.Fatalf("persisted triage after status-only update = %+v", persistedTriage)
	}

	// Diff: scan2 keeps fpA, drops fpB, adds fpD.
	findings2 := []model.Finding{
		findings[0],
		{ID: fpD, Severity: "high", Category: "Cross-Tool Taint", Title: "taint", EdgeKind: "TAINTS",
			SourceKind: "MCPTool", TargetKind: "MCPTool", Confidence: 0.7},
	}
	replaceFindings(scanID2, findings2)
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

	// A successful same-ID empty retry is an atomic replacement, not a no-op.
	replaceFindings(scanID2, []model.Finding{})
	empty, err := fs.ListForScan(ctx, scanID2, "", true)
	if err != nil {
		t.Fatalf("list after empty replacement: %v", err)
	}
	if len(empty) != 0 {
		t.Fatalf("empty replacement retained %d stale findings", len(empty))
	}
}
