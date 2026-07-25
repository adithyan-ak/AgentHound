package appdb

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestIntegrationPublicationLifecycle(t *testing.T) {
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

	scans := NewScanStore(pool)
	findings := NewFindingStore(pool)
	prefix := "publication-test-" + time.Now().Format("20060102150405.000000")
	publishedID := prefix + "-published"
	comparableID := prefix + "-comparable"
	headID := prefix + "-head"
	pendingID := prefix + "-pending"
	cleanup := func() {
		_, _ = pool.Exec(ctx, `UPDATE posture_state SET
		    published_revision = NULL, published_scan_id = NULL, published_at = NULL,
		    dirty_coverage = '[]'::jsonb, projection_error = NULL
		    WHERE singleton = TRUE`)
		_, _ = pool.Exec(ctx, `DELETE FROM coverage_heads WHERE scan_id LIKE $1`, prefix+"%")
		_, _ = pool.Exec(ctx, `DELETE FROM scans WHERE id LIKE $1`, prefix+"%")
	}
	cleanup()
	defer cleanup()

	started := time.Now().UTC()
	observed := started.Add(-time.Minute)
	mustCreateScan := func(id, status string) {
		t.Helper()
		if err := scans.CreateScan(ctx, &model.Scan{
			ID:                 id,
			Collector:          "mcp",
			Status:             status,
			StartedAt:          started,
			ArtifactObservedAt: &observed,
		}); err != nil {
			t.Fatalf("create scan %s: %v", id, err)
		}
	}
	mustCreateScan(publishedID, model.ScanStatusRunning)

	completed := time.Now().UTC()
	graphBefore := &model.GraphSnapshot{
		NodeCounts: map[string]int64{"MCPServer": 1},
		EdgeCounts: map[string]int64{},
		TotalNodes: 1,
	}
	graphAfter := &model.GraphSnapshot{
		NodeCounts: map[string]int64{"MCPServer": 2},
		EdgeCounts: map[string]int64{"PROVIDES_TOOL": 1},
		TotalNodes: 2,
		TotalEdges: 1,
	}
	finding := model.Finding{
		ID:         "aaaaaaaaaaaaaaaa",
		Severity:   "high",
		Category:   "test",
		Title:      "persisted",
		EdgeKind:   "CAN_REACH",
		SourceID:   "source",
		TargetID:   "target",
		Confidence: 0.9,
		Variant:    model.FindingVariantCrossProtocolHostCorrelation,
		Evidence: model.FindingEvidence{
			State:       model.FindingEvidenceHypothesis,
			Correlation: "shared_host",
		},
	}
	result, err := findings.FinalizeScan(ctx, FinalizeScanParams{
		Scan: model.Scan{
			ID:                 publishedID,
			Collector:          "mcp",
			Status:             model.ScanStatusCompleted,
			StartedAt:          started,
			CompletedAt:        &completed,
			ArtifactObservedAt: &observed,
			NodeWriteRows:      2,
			EdgeWriteRows:      1,
			CollectionStatus:   model.LifecycleComplete,
			GraphStatus:        model.LifecycleComplete,
			AnalysisStatus:     model.LifecycleComplete,
			SnapshotStatus:     model.LifecycleComplete,
			ProjectionStatus:   model.ProjectionComplete,
			ComparisonKey:      "sha256:test-comparison",
		},
		Findings:        []model.Finding{finding},
		Stages:          []sdkingest.StageResult{},
		CoverageKeys:    []string{"mcp"},
		CompleteDomains: []string{"mcp"},
		GraphBefore:     graphBefore,
		GraphAfter:      graphAfter,
		Publish:         true,
	})
	if err != nil {
		t.Fatalf("FinalizeScan published: %v", err)
	}
	if result.Revision == nil {
		t.Fatal("published revision is nil")
	}

	export, err := findings.GetPublishedExport(ctx)
	if err != nil {
		t.Fatalf("GetPublishedExport: %v", err)
	}
	if export == nil || export.Scope.ScanID != publishedID || len(export.Findings) != 1 {
		t.Fatalf("published export = %+v", export)
	}
	if export.Findings[0].Variant != model.FindingVariantCrossProtocolHostCorrelation ||
		export.Findings[0].Evidence.State != model.FindingEvidenceHypothesis {
		t.Fatalf("published export lost finding evidence: %+v", export.Findings[0])
	}
	scoped, scope, err := findings.ListPublished(ctx, "", true)
	if err != nil {
		t.Fatalf("ListPublished: %v", err)
	}
	if !scope.Available || scope.Stale || len(scoped) != 1 {
		t.Fatalf("published scope = %+v findings=%v", scope, scoped)
	}

	// A degraded retry of the currently published scan does not replace the
	// prior published rows or persisted export.
	if _, err := scans.BeginScan(ctx, &model.Scan{
		ID:                 publishedID,
		Collector:          "mcp",
		Status:             model.ScanStatusRunning,
		StartedAt:          started,
		ArtifactObservedAt: &observed,
		CollectionStatus:   model.LifecyclePartial,
	}, []string{"mcp"}, nil); err != nil {
		t.Fatalf("BeginScan published retry: %v", err)
	}
	if _, err := findings.FinalizeScan(ctx, FinalizeScanParams{
		Scan: model.Scan{
			ID:                 publishedID,
			Collector:          "mcp",
			Status:             model.ScanStatusCompletedWithErrors,
			StartedAt:          started,
			CompletedAt:        &completed,
			ArtifactObservedAt: &observed,
			CollectionStatus:   model.LifecyclePartial,
			GraphStatus:        model.LifecyclePartial,
			AnalysisStatus:     model.LifecycleComplete,
			SnapshotStatus:     model.LifecycleComplete,
			ProjectionStatus:   model.ProjectionIncomplete,
			Error:              "partial retry",
		},
		Findings:      []model.Finding{},
		Stages:        []sdkingest.StageResult{},
		DirtyCoverage: []string{"mcp"},
		GraphAfter:    graphAfter,
		Publish:       false,
	}); err != nil {
		t.Fatalf("FinalizeScan degraded retry: %v", err)
	}
	scoped, scope, err = findings.ListPublished(ctx, "", true)
	if err != nil {
		t.Fatalf("ListPublished after retry: %v", err)
	}
	if !scope.Stale || len(scoped) != 1 || scoped[0].ID != finding.ID {
		t.Fatalf("degraded retry replaced published snapshot: scope=%+v findings=%v", scope, scoped)
	}
	exportAfter, err := findings.GetPublishedExport(ctx)
	if err != nil {
		t.Fatalf("GetPublishedExport after retry: %v", err)
	}
	if exportAfter == nil || exportAfter.Scope.Revision != export.Scope.Revision ||
		len(exportAfter.Findings) != 1 {
		t.Fatalf("persisted export changed after degraded retry: %+v", exportAfter)
	}
	preservedScan, err := scans.GetScan(ctx, publishedID)
	if err != nil {
		t.Fatalf("GetScan after degraded retry: %v", err)
	}
	if preservedScan.GraphTotalNodesAfter == nil ||
		*preservedScan.GraphTotalNodesAfter != graphAfter.TotalNodes ||
		preservedScan.PublishedRevision == nil ||
		*preservedScan.PublishedRevision != *result.Revision {
		t.Fatalf("published totals/revision changed after degraded retry: %+v", preservedScan)
	}

	if err := scans.DeleteScan(ctx, publishedID); err == nil {
		t.Fatal("currently published scan deletion succeeded")
	} else {
		var conflict *ScanDeleteConflictError
		if !errors.As(err, &conflict) {
			t.Fatalf("published delete error = %T %v", err, err)
		}
	}

	mustCreateScan(comparableID, model.ScanStatusRunning)
	comparableGraph := &model.GraphSnapshot{
		NodeCounts: map[string]int64{"MCPServer": 3, "MCPTool": 1},
		EdgeCounts: map[string]int64{"PROVIDES_TOOL": 2},
		TotalNodes: 4,
		TotalEdges: 2,
	}
	comparableResult, err := findings.FinalizeScan(ctx, FinalizeScanParams{
		Scan: model.Scan{
			ID:                 comparableID,
			Collector:          "mcp",
			Status:             model.ScanStatusCompleted,
			StartedAt:          started,
			CompletedAt:        &completed,
			ArtifactObservedAt: &observed,
			CollectionStatus:   model.LifecycleComplete,
			GraphStatus:        model.LifecycleComplete,
			AnalysisStatus:     model.LifecycleComplete,
			SnapshotStatus:     model.LifecycleComplete,
			ProjectionStatus:   model.ProjectionComplete,
			ComparisonKey:      "sha256:test-comparison",
		},
		Findings:        []model.Finding{},
		Stages:          []sdkingest.StageResult{},
		CoverageKeys:    []string{"mcp"},
		CompleteDomains: []string{"mcp"},
		GraphBefore:     graphAfter,
		GraphAfter:      comparableGraph,
		Publish:         true,
	})
	if err != nil {
		t.Fatalf("FinalizeScan comparable: %v", err)
	}
	if comparableResult.ComparableToScanID != publishedID {
		t.Fatalf("comparable_to = %q, want %q", comparableResult.ComparableToScanID, publishedID)
	}
	if comparableResult.Export == nil ||
		!comparableResult.Export.Comparison.Comparable ||
		comparableResult.Export.Comparison.NodeDelta == nil ||
		*comparableResult.Export.Comparison.NodeDelta != 2 ||
		comparableResult.Export.Comparison.EdgeDelta == nil ||
		*comparableResult.Export.Comparison.EdgeDelta != 1 {
		t.Fatalf("comparison = %+v", comparableResult.Export)
	}
	priorScan, err := scans.GetScan(ctx, publishedID)
	if err != nil {
		t.Fatalf("GetScan prior publication: %v", err)
	}
	if priorScan.PublicationStatus != model.PublicationSuperseded {
		t.Fatalf("prior publication status = %q, want superseded", priorScan.PublicationStatus)
	}

	mustCreateScan(headID, model.ScanStatusCompleted)
	if _, err := pool.Exec(ctx, `INSERT INTO coverage_heads (coverage_key, scan_id)
		VALUES ('config', $1) ON CONFLICT (coverage_key) DO UPDATE SET scan_id = EXCLUDED.scan_id`,
		headID); err != nil {
		t.Fatalf("create coverage head: %v", err)
	}
	if err := scans.DeleteScan(ctx, headID); err == nil {
		t.Fatal("active coverage-head deletion succeeded")
	}

	mustCreateScan(pendingID, model.ScanStatusPending)
	if err := scans.DeleteScan(ctx, pendingID); err == nil {
		t.Fatal("pending scan deletion succeeded")
	}
}

func TestIntegrationAuthoritativeRootRetiresRemovedChildHeadAndDirtyKey(t *testing.T) {
	skipIfNoPG(t)
	ctx := context.Background()
	pgURI := os.Getenv("AGENTHOUND_PG_URI")
	admin, err := NewPool(pgURI)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("agenthound_authoritative_root_%d", time.Now().UnixNano())
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatalf("create isolated schema: %v", err)
	}
	defer func() {
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+quotedSchema+" CASCADE"); err != nil {
			t.Errorf("drop isolated schema: %v", err)
		}
	}()
	config, err := pgxpool.ParseConfig(pgURI)
	if err != nil {
		t.Fatalf("parse postgres config: %v", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect isolated schema: %v", err)
	}
	defer pool.Close()
	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	scans := NewScanStore(pool)
	findings := NewFindingStore(pool)
	prefix := "authoritative-root-" + time.Now().Format("20060102150405.000000")
	firstID := prefix + "-first"
	secondID := prefix + "-second"
	targetedID := prefix + "-targeted"
	failedID := prefix + "-failed-unheaded"
	emptyID := prefix + "-empty"
	root := sdkingest.CollectorRootCoverageKey("mcp")
	childA := sdkingest.CanonicalCoverageKey("mcp", "target", prefix+"-a")
	childB := sdkingest.CanonicalCoverageKey("mcp", "target", prefix+"-b")
	childC := sdkingest.CanonicalCoverageKey("mcp", "target", prefix+"-c")
	childD := sdkingest.CanonicalCoverageKey("mcp", "target", prefix+"-d")
	cleanup := func() {
		_, _ = pool.Exec(ctx, `UPDATE posture_state SET
		    published_revision = NULL, published_scan_id = NULL, published_at = NULL,
		    dirty_coverage = '[]'::jsonb, projection_error = NULL
		    WHERE singleton = TRUE`)
		_, _ = pool.Exec(
			ctx,
			`DELETE FROM coverage_heads WHERE coverage_key = ANY($1::text[])`,
			[]string{root, childA, childB, childC, childD},
		)
		_, _ = pool.Exec(ctx, `DELETE FROM scans WHERE id LIKE $1`, prefix+"%")
	}
	cleanup()
	defer cleanup()

	now := time.Now().UTC()
	observed := now.Add(-time.Second)
	createRunning := func(id string) {
		t.Helper()
		if err := scans.CreateScan(ctx, &model.Scan{
			ID:                 id,
			Collector:          "mcp",
			Status:             model.ScanStatusRunning,
			StartedAt:          now,
			ArtifactObservedAt: &observed,
		}); err != nil {
			t.Fatalf("create scan %s: %v", id, err)
		}
	}
	finalScan := func(id string) model.Scan {
		completed := now.Add(time.Second)
		return model.Scan{
			ID:                 id,
			Collector:          "mcp",
			Status:             model.ScanStatusCompleted,
			StartedAt:          now,
			CompletedAt:        &completed,
			ArtifactObservedAt: &observed,
			CollectionStatus:   model.LifecycleComplete,
			GraphStatus:        model.LifecycleComplete,
			AnalysisStatus:     model.LifecycleComplete,
			SnapshotStatus:     model.LifecycleComplete,
			ProjectionStatus:   model.ProjectionComplete,
		}
	}
	graphAfter := &model.GraphSnapshot{
		NodeCounts: map[string]int64{},
		EdgeCounts: map[string]int64{},
	}

	createRunning(firstID)
	if _, err := findings.FinalizeScan(ctx, FinalizeScanParams{
		Scan:            finalScan(firstID),
		CoverageKeys:    []string{root, childA, childB},
		CompleteDomains: []string{root, childA, childB},
		AuthoritativeRoots: []sdkingest.CoverageRoot{{
			CoverageKey:       root,
			ChildCoverageKeys: []string{childA, childB},
		}},
		GraphAfter: graphAfter,
		Publish:    true,
	}); err != nil {
		t.Fatalf("finalize first active set: %v", err)
	}

	retired, err := scans.ResolveRetiredCoverage(ctx, []sdkingest.CoverageRoot{{
		CoverageKey:       root,
		ChildCoverageKeys: []string{childB},
	}})
	if err != nil {
		t.Fatalf("resolve removed child: %v", err)
	}
	if len(retired) != 1 || retired[0] != childA {
		t.Fatalf("retired children = %v, want [%s]", retired, childA)
	}

	if _, err := scans.BeginScan(ctx, &model.Scan{
		ID:                 secondID,
		Collector:          "mcp",
		Status:             model.ScanStatusRunning,
		StartedAt:          now,
		ArtifactObservedAt: &observed,
		CollectionStatus:   model.LifecycleComplete,
	}, []string{root, childB, childA}, map[string]string{childB: root}); err != nil {
		t.Fatalf("begin replacement scan: %v", err)
	}
	result, err := findings.FinalizeScan(ctx, FinalizeScanParams{
		Scan:                  finalScan(secondID),
		CoverageKeys:          []string{root, childB},
		CompleteDomains:       []string{root, childB},
		ResolvedDirtyCoverage: retired,
		AuthoritativeRoots: []sdkingest.CoverageRoot{{
			CoverageKey:       root,
			ChildCoverageKeys: []string{childB},
		}},
		GraphAfter: graphAfter,
		Publish:    true,
	})
	if err != nil {
		t.Fatalf("finalize replacement active set: %v", err)
	}
	if !result.Published || len(result.DirtyCoverage) != 0 {
		t.Fatalf("replacement publication = %+v, want clean published state", result)
	}

	var removedCount int
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*) FROM coverage_heads WHERE coverage_key = $1`,
		childA,
	).Scan(&removedCount); err != nil {
		t.Fatalf("query removed head: %v", err)
	}
	if removedCount != 0 {
		t.Fatalf("removed child head count = %d, want 0", removedCount)
	}
	var (
		headScanID string
		headRoot   *string
	)
	if err := pool.QueryRow(
		ctx,
		`SELECT scan_id, root_key FROM coverage_heads WHERE coverage_key = $1`,
		childB,
	).Scan(&headScanID, &headRoot); err != nil {
		t.Fatalf("query retained child head: %v", err)
	}
	if headScanID != secondID || headRoot == nil || *headRoot != root {
		t.Fatalf(
			"retained child head = scan %q root %v, want scan %q root %q",
			headScanID,
			headRoot,
			secondID,
			root,
		)
	}

	// A targeted run records child membership but is not itself
	// authoritative. A later exhaustive complete-empty run can therefore
	// retire both the previously exhaustive child and this targeted-only child.
	createRunning(targetedID)
	if _, err := findings.FinalizeScan(ctx, FinalizeScanParams{
		Scan:            finalScan(targetedID),
		CoverageKeys:    []string{childC},
		CompleteDomains: []string{childC},
		CoverageParents: map[string]string{childC: root},
		GraphAfter:      graphAfter,
		Publish:         true,
	}); err != nil {
		t.Fatalf("finalize targeted child: %v", err)
	}
	if err := pool.QueryRow(
		ctx,
		`SELECT root_key FROM coverage_heads WHERE coverage_key = $1`,
		childC,
	).Scan(&headRoot); err != nil {
		t.Fatalf("query targeted child membership: %v", err)
	}
	if headRoot == nil || *headRoot != root {
		t.Fatalf("targeted child root = %v, want explicit root %q", headRoot, root)
	}

	// A failed child has no promoted coverage head. Its inherited dirty key
	// must still be retired by a later complete exhaustive active set, including
	// when that later run is handled by a newly constructed store.
	if _, err := scans.BeginScan(ctx, &model.Scan{
		ID:                 failedID,
		Collector:          "mcp",
		Status:             model.ScanStatusRunning,
		StartedAt:          now,
		ArtifactObservedAt: &observed,
		CollectionStatus:   model.LifecycleFailed,
	}, []string{childD}, map[string]string{childD: root}); err != nil {
		t.Fatalf("begin failed unheaded child: %v", err)
	}
	if err := scans.RecordFailure(ctx, ScanFailure{
		ID:               failedID,
		Status:           model.ScanStatusFailed,
		Error:            "collector failed",
		CollectionStatus: model.LifecycleFailed,
		GraphStatus:      model.LifecycleFailed,
		AnalysisStatus:   model.LifecycleNotApplicable,
		SnapshotStatus:   model.LifecycleNotApplicable,
		ProjectionStatus: model.ProjectionIncomplete,
		DirtyCoverage:    []string{childD},
	}); err != nil {
		t.Fatalf("record failed unheaded child: %v", err)
	}
	var failedHeadCount int
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*) FROM coverage_heads WHERE coverage_key = $1`,
		childD,
	).Scan(&failedHeadCount); err != nil {
		t.Fatalf("query failed child head: %v", err)
	}
	if failedHeadCount != 0 {
		t.Fatalf("failed child head count = %d, want 0", failedHeadCount)
	}
	scans = NewScanStore(pool)

	emptyRoot := sdkingest.CollectorRootCoverageKey("mcp")
	retired, err = scans.ResolveRetiredCoverage(ctx, []sdkingest.CoverageRoot{{
		CoverageKey: emptyRoot,
	}})
	if err != nil {
		t.Fatalf("resolve complete-empty active set: %v", err)
	}
	wantRetired := normalizeCoverageKeys([]string{childB, childC, childD})
	if len(retired) != len(wantRetired) {
		t.Fatalf("complete-empty retired children = %v, want %v", retired, wantRetired)
	}
	for i := range wantRetired {
		if retired[i] != wantRetired[i] {
			t.Fatalf("complete-empty retired children = %v, want %v", retired, wantRetired)
		}
	}
	if _, err := scans.BeginScan(ctx, &model.Scan{
		ID:                 emptyID,
		Collector:          "mcp",
		Status:             model.ScanStatusRunning,
		StartedAt:          now,
		ArtifactObservedAt: &observed,
		CollectionStatus:   model.LifecycleComplete,
	}, append([]string{emptyRoot}, retired...), nil); err != nil {
		t.Fatalf("begin complete-empty scan: %v", err)
	}
	emptyResult, err := findings.FinalizeScan(ctx, FinalizeScanParams{
		Scan:                  finalScan(emptyID),
		CoverageKeys:          []string{emptyRoot},
		CompleteDomains:       []string{emptyRoot},
		ResolvedDirtyCoverage: retired,
		AuthoritativeRoots: []sdkingest.CoverageRoot{{
			CoverageKey: emptyRoot,
		}},
		GraphAfter: graphAfter,
		Publish:    true,
	})
	if err != nil {
		t.Fatalf("finalize complete-empty active set: %v", err)
	}
	if !emptyResult.Published || len(emptyResult.DirtyCoverage) != 0 {
		t.Fatalf("complete-empty publication = %+v", emptyResult)
	}
	var survivingChildren int
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*) FROM coverage_heads
		 WHERE coverage_key = ANY($1::text[])`,
		[]string{childA, childB, childC, childD},
	).Scan(&survivingChildren); err != nil {
		t.Fatalf("query complete-empty heads: %v", err)
	}
	if survivingChildren != 0 {
		t.Fatalf("complete-empty surviving child heads = %d, want 0", survivingChildren)
	}
}

func TestIntegrationIncompleteInstructionRootPreservesChildrenUntilComplete(t *testing.T) {
	skipIfNoPG(t)
	ctx := context.Background()
	pgURI := os.Getenv("AGENTHOUND_PG_URI")
	admin, err := NewPool(pgURI)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer admin.Close()
	schema := fmt.Sprintf("agenthound_instruction_root_%d", time.Now().UnixNano())
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatalf("create isolated schema: %v", err)
	}
	defer func() {
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+quotedSchema+" CASCADE"); err != nil {
			t.Errorf("drop isolated schema: %v", err)
		}
	}()
	config, err := pgxpool.ParseConfig(pgURI)
	if err != nil {
		t.Fatalf("parse postgres config: %v", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect isolated schema: %v", err)
	}
	defer pool.Close()
	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	scans := NewScanStore(pool)
	findings := NewFindingStore(pool)
	now := time.Now().UTC()
	observed := now.Add(-time.Second)
	graphAfter := &model.GraphSnapshot{
		NodeCounts: map[string]int64{},
		EdgeCounts: map[string]int64{},
	}
	root := sdkingest.CanonicalCoverageKey(
		"config",
		"instruction-exact-user",
		"/home/op",
	)
	currentChild := sdkingest.CanonicalCoverageKey(
		"config",
		"instruction-source",
		root+"\x00AGENTS.md",
	)
	priorSibling := sdkingest.CanonicalCoverageKey(
		"config",
		"instruction-source",
		root+"\x00prior/CLAUDE.md",
	)
	contract := sdkingest.CurrentInstructionRegistryContract()
	makeCollection := func(
		state sdkingest.OutcomeState,
		children ...string,
	) *sdkingest.CollectionReport {
		report := &sdkingest.CollectionReport{
			State:        state,
			CoverageKeys: append([]string{root}, children...),
			AuthoritativeRoots: []sdkingest.CoverageRoot{{
				CoverageKey:       root,
				ChildCoverageKeys: append([]string(nil), children...),
				RegistryContract:  &contract,
			}},
			Outcomes: []sdkingest.CollectionOutcome{{
				Collector: "config", CoverageKey: root,
				Method: sdkingest.InstructionMethodExactUser, State: state,
			}},
		}
		for _, child := range children {
			report.Outcomes = append(report.Outcomes, sdkingest.CollectionOutcome{
				Collector: "config", CoverageKey: child, ParentCoverageKey: root,
				Method: sdkingest.InstructionMethodSource, State: sdkingest.OutcomeComplete,
			})
		}
		report.State = sdkingest.AggregateOutcomeState(report.Outcomes)
		return report
	}
	createRunning := func(id string) {
		t.Helper()
		if err := scans.CreateScan(ctx, &model.Scan{
			ID: id, Collector: "config", Status: model.ScanStatusRunning,
			StartedAt: now, ArtifactObservedAt: &observed,
		}); err != nil {
			t.Fatalf("create scan %s: %v", id, err)
		}
	}
	finalScan := func(id string) model.Scan {
		completed := now.Add(time.Second)
		return model.Scan{
			ID: id, Collector: "config", Status: model.ScanStatusCompleted,
			StartedAt: now, CompletedAt: &completed, ArtifactObservedAt: &observed,
			CollectionStatus: model.LifecycleComplete,
			GraphStatus:      model.LifecycleComplete,
			AnalysisStatus:   model.LifecycleComplete,
			SnapshotStatus:   model.LifecycleComplete,
			ProjectionStatus: model.ProjectionComplete,
			ComparisonKey:    "sha256:instruction-root",
		}
	}
	finalize := func(
		id string,
		state sdkingest.OutcomeState,
		authoritative bool,
		children ...string,
	) *PublicationResult {
		t.Helper()
		createRunning(id)
		report := makeCollection(state, children...)
		completeDomains := append([]string(nil), children...)
		if state == sdkingest.OutcomeComplete {
			completeDomains = append(completeDomains, root)
		}
		rootSet := []sdkingest.CoverageRoot{report.AuthoritativeRoots[0]}
		var authoritativeRoots []sdkingest.CoverageRoot
		if authoritative {
			authoritativeRoots = rootSet
		}
		parents := make(map[string]string)
		for _, child := range children {
			parents[child] = root
		}
		scan := finalScan(id)
		scan.CollectionStatus = string(report.State)
		result, err := findings.FinalizeScan(ctx, FinalizeScanParams{
			Scan:               scan,
			Collection:         report,
			CoverageKeys:       report.CoverageKeys,
			CoverageParents:    parents,
			CompleteDomains:    completeDomains,
			CoverageRoots:      rootSet,
			AuthoritativeRoots: authoritativeRoots,
			GraphAfter:         graphAfter,
			Publish:            true,
		})
		if err != nil {
			t.Fatalf("finalize scan %s: %v", id, err)
		}
		return result
	}

	firstID := "instruction-root-first"
	finalize(firstID, sdkingest.OutcomeComplete, true, currentChild, priorSibling)
	partialID := "instruction-root-partial"
	finalize(partialID, sdkingest.OutcomePartial, false, currentChild)

	var (
		rootState     sdkingest.OutcomeState
		rootScanID    string
		childScanID   string
		siblingScanID string
		comparisonKey *string
	)
	if err := pool.QueryRow(
		ctx,
		`SELECT state, scan_id FROM coverage_heads WHERE coverage_key = $1`,
		root,
	).Scan(&rootState, &rootScanID); err != nil {
		t.Fatalf("read partial root head: %v", err)
	}
	if err := pool.QueryRow(
		ctx,
		`SELECT scan_id FROM coverage_heads WHERE coverage_key = $1`,
		currentChild,
	).Scan(&childScanID); err != nil {
		t.Fatalf("read current child head: %v", err)
	}
	if err := pool.QueryRow(
		ctx,
		`SELECT scan_id FROM coverage_heads WHERE coverage_key = $1`,
		priorSibling,
	).Scan(&siblingScanID); err != nil {
		t.Fatalf("read prior sibling head: %v", err)
	}
	if err := pool.QueryRow(
		ctx,
		`SELECT comparison_key FROM scans WHERE id = $1`,
		partialID,
	).Scan(&comparisonKey); err != nil {
		t.Fatalf("read partial comparison key: %v", err)
	}
	if rootState != sdkingest.OutcomePartial ||
		rootScanID != partialID ||
		childScanID != partialID ||
		siblingScanID != firstID ||
		comparisonKey != nil {
		t.Fatalf(
			"partial heads root=(%s,%s) child=%s sibling=%s comparison=%v",
			rootState,
			rootScanID,
			childScanID,
			siblingScanID,
			comparisonKey,
		)
	}

	failedID := "instruction-root-failed"
	finalize(failedID, sdkingest.OutcomeFailed, false, currentChild)
	if err := pool.QueryRow(
		ctx,
		`SELECT state FROM coverage_heads WHERE coverage_key = $1`,
		root,
	).Scan(&rootState); err != nil {
		t.Fatalf("read failed root head: %v", err)
	}
	if rootState != sdkingest.OutcomeFailed {
		t.Fatalf("failed root state = %q", rootState)
	}

	completeID := "instruction-root-complete"
	finalize(completeID, sdkingest.OutcomeComplete, true, currentChild)
	var siblingCount int
	if err := pool.QueryRow(
		ctx,
		`SELECT count(*) FROM coverage_heads WHERE coverage_key = $1`,
		priorSibling,
	).Scan(&siblingCount); err != nil {
		t.Fatalf("count retired sibling: %v", err)
	}
	if err := pool.QueryRow(
		ctx,
		`SELECT state FROM coverage_heads WHERE coverage_key = $1`,
		root,
	).Scan(&rootState); err != nil {
		t.Fatalf("read complete root state: %v", err)
	}
	if err := pool.QueryRow(
		ctx,
		`SELECT comparison_key FROM scans WHERE id = $1`,
		completeID,
	).Scan(&comparisonKey); err != nil {
		t.Fatalf("read complete comparison key: %v", err)
	}
	if siblingCount != 0 ||
		rootState != sdkingest.OutcomeComplete ||
		comparisonKey == nil ||
		*comparisonKey == "" {
		t.Fatalf(
			"complete root sibling_count=%d state=%q comparison=%v",
			siblingCount,
			rootState,
			comparisonKey,
		)
	}

	stable := finalize(
		"instruction-root-stable",
		sdkingest.OutcomeComplete,
		true,
		currentChild,
	)
	if stable.ComparableToScanID != completeID {
		t.Fatalf(
			"restored comparison = %q, want %q",
			stable.ComparableToScanID,
			completeID,
		)
	}
}

func TestBuildPostureExportDeclaresHealthAndCompleteState(t *testing.T) {
	now := time.Now().UTC()
	params := FinalizeScanParams{
		Scan: model.Scan{
			ID:                 "scan-export-state",
			StartedAt:          now.Add(-time.Minute),
			CompletedAt:        &now,
			CollectionStatus:   model.LifecycleComplete,
			GraphStatus:        model.LifecycleComplete,
			AnalysisStatus:     model.LifecycleComplete,
			SnapshotStatus:     model.LifecycleComplete,
			ProjectionStatus:   model.ProjectionComplete,
			ComparisonKey:      "sha256:scope",
			ArtifactObservedAt: &now,
		},
		Stages: []sdkingest.StageResult{{
			Name:     "normalize",
			State:    sdkingest.OutcomeComplete,
			Required: true,
		}},
		NormalizationStatus: sdkingest.NormalizationStatusWarning,
		NormalizationWarnings: []sdkingest.NormalizationWarning{{
			Code:              "complex_property_serialized",
			Status:            sdkingest.NormalizationStatusWarning,
			Message:           "lossless serialization",
			PublicationUnsafe: false,
		}},
		ObservationStatus:  model.LifecycleComplete,
		ObservationDetails: model.PostureObservationCompleteness{},
		CoverageKeys: []string{
			"config:path:sha256:current",
		},
		GraphAfter: &model.GraphSnapshot{
			NodeCounts: map[string]int64{},
			EdgeCounts: map[string]int64{},
		},
	}
	export := buildPostureExport(
		params,
		9,
		now,
		[]model.Finding{{ID: "finding-1"}},
		model.PostureComparison{},
		[]string{
			"config:path:sha256:current",
			"mcp:target:sha256:prior",
		},
		nil,
	)

	if export.SchemaVersion != model.PostureExportSchemaVersion ||
		export.Health.State != "not_captured" ||
		export.Health.Captured {
		t.Fatalf("health/schema state = %+v", export)
	}
	if export.Completeness.Normalization != sdkingest.NormalizationStatusWarning ||
		export.Completeness.Observation != model.LifecycleComplete ||
		len(export.Completeness.Warnings) != 1 ||
		len(export.Completeness.Stages) != 1 {
		t.Fatalf("completeness metadata = %+v", export.Completeness)
	}
	if len(export.Scope.DirtyCoverage) != 0 ||
		len(export.Scope.ActiveCoverageKeys) != 2 {
		t.Fatalf("coverage scope = %+v", export.Scope)
	}
	if export.Limits.Findings.Returned != 1 ||
		export.Limits.Findings.Total != 1 ||
		!export.Limits.Findings.Complete {
		t.Fatalf("export cardinality = %+v", export.Limits)
	}
}

func TestCoverageRootHeadsAcceptsRegisteredInstructionRootStates(t *testing.T) {
	contract := sdkingest.CurrentInstructionRegistryContract()
	for _, mode := range []struct {
		name   string
		method string
		kind   string
		want   sdkingest.InstructionCoverageMode
	}{
		{"exact_user", sdkingest.InstructionMethodExactUser, "instruction-exact-user", sdkingest.InstructionCoverageExactUser},
		{"exact_project", sdkingest.InstructionMethodExactProject, "instruction-exact-project", sdkingest.InstructionCoverageExactProject},
		{"deep", sdkingest.InstructionMethodDeep, "instruction-deep", sdkingest.InstructionCoverageDeep},
	} {
		for _, state := range []sdkingest.OutcomeState{
			sdkingest.OutcomeComplete,
			sdkingest.OutcomeTruncated,
			sdkingest.OutcomePartial,
			sdkingest.OutcomeFailed,
		} {
			t.Run(mode.name+"/"+string(state), func(t *testing.T) {
				rootKey := sdkingest.CanonicalCoverageKey("config", mode.kind, "/home/op")
				report := &sdkingest.CollectionReport{
					CoverageKeys: []string{rootKey},
					Outcomes: []sdkingest.CollectionOutcome{{
						Collector: "config", CoverageKey: rootKey,
						Method: mode.method, State: state,
					}},
				}
				heads, err := coverageRootHeads(report, []sdkingest.CoverageRoot{{
					CoverageKey: rootKey, RegistryContract: &contract,
				}})
				if err != nil {
					t.Fatalf("coverageRootHeads: %v", err)
				}
				head := heads[rootKey]
				if head.Key != rootKey ||
					head.State != state ||
					head.Mode != mode.want ||
					head.RegistryContract == nil ||
					!head.RegistryContract.Equal(contract) {
					t.Fatalf("coverage root head = %+v", head)
				}
			})
		}
	}

	nonInstruction := sdkingest.CollectorRootCoverageKey("mcp")
	report := &sdkingest.CollectionReport{
		CoverageKeys: []string{nonInstruction},
		Outcomes: []sdkingest.CollectionOutcome{{
			Collector: "mcp", CoverageKey: nonInstruction,
			Method: "collect", State: sdkingest.OutcomePartial,
		}},
	}
	if _, err := coverageRootHeads(report, []sdkingest.CoverageRoot{{
		CoverageKey: nonInstruction,
	}}); err == nil || !strings.Contains(err.Error(), "cannot promote state") {
		t.Fatalf("partial non-instruction root error = %v", err)
	}
}
