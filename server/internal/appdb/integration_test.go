package appdb

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/adithyan-ak/agenthound/server/internal/binding"
	"github.com/adithyan-ak/agenthound/server/model"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const integrationStoragePairID = "7bc1f56e-c890-4de5-9cc5-921797176fa6"

func skipIfNoPG(t *testing.T) {
	t.Helper()
	if os.Getenv("AGENTHOUND_PG_URI") == "" {
		t.Skip("skipping integration test: AGENTHOUND_PG_URI not set")
	}
}

func TestIntegrationMigrations(t *testing.T) {
	skipIfNoPG(t)
	ctx := context.Background()

	admin, err := NewPool(os.Getenv("AGENTHOUND_PG_URI"))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer admin.Close()

	schema := fmt.Sprintf("agenthound_migration_test_%d", time.Now().UnixNano())
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatalf("create isolated schema: %v", err)
	}
	defer func() {
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+quotedSchema+" CASCADE"); err != nil {
			t.Errorf("drop isolated schema: %v", err)
		}
	}()

	config, err := pgxpool.ParseConfig(os.Getenv("AGENTHOUND_PG_URI"))
	if err != nil {
		t.Fatalf("parse connection config: %v", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect isolated schema: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		t.Fatalf("ping isolated schema: %v", err)
	}

	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatalf("migrate (idempotent): %v", err)
	}

	rows, err := pool.Query(ctx, `SELECT table_name
		FROM information_schema.tables
		WHERE table_schema = current_schema()
		ORDER BY table_name`)
	if err != nil {
		t.Fatalf("list fresh schema tables: %v", err)
	}
	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			rows.Close()
			t.Fatalf("scan fresh schema table: %v", err)
		}
		tables = append(tables, table)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		t.Fatalf("list fresh schema tables: %v", err)
	}
	wantTables := []string{
		"coverage_heads",
		"coverage_limitations",
		"coverage_memberships",
		"finding_triage",
		"findings",
		"posture_publications",
		"posture_state",
		"scans",
		"schema_migrations",
		"storage_binding",
	}
	if !reflect.DeepEqual(tables, wantTables) {
		t.Fatalf("fresh schema tables = %v, want %v", tables, wantTables)
	}

	var versions []int
	versionRows, err := pool.Query(ctx, "SELECT version FROM schema_migrations ORDER BY version")
	if err != nil {
		t.Fatalf("list migration versions: %v", err)
	}
	for versionRows.Next() {
		var version int
		if err := versionRows.Scan(&version); err != nil {
			versionRows.Close()
			t.Fatalf("scan migration version: %v", err)
		}
		versions = append(versions, version)
	}
	versionRows.Close()
	if err := versionRows.Err(); err != nil {
		t.Fatalf("list migration versions: %v", err)
	}
	migrations, err := availableMigrations()
	if err != nil {
		t.Fatalf("discover embedded migrations: %v", err)
	}
	want := make([]int, 0, len(migrations))
	for _, migration := range migrations {
		want = append(want, migration.version)
	}
	if !reflect.DeepEqual(versions, want) {
		t.Fatalf("migration versions = %v, want %v", versions, want)
	}

	var postureRows int
	if err := pool.QueryRow(ctx,
		"SELECT count(*) FROM posture_state WHERE singleton = TRUE",
	).Scan(&postureRows); err != nil {
		t.Fatalf("read posture singleton: %v", err)
	}
	if postureRows != 1 {
		t.Fatalf("posture singleton rows = %d, want 1", postureRows)
	}

}

func TestIntegrationInstructionEvidenceMigrationRewritesLegacyPublication(t *testing.T) {
	skipIfNoPG(t)
	ctx := context.Background()
	admin, err := NewPool(os.Getenv("AGENTHOUND_PG_URI"))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer admin.Close()

	schema := fmt.Sprintf("agenthound_instruction_migration_%d", time.Now().UnixNano())
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatalf("create isolated schema: %v", err)
	}
	defer func() {
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+quotedSchema+" CASCADE"); err != nil {
			t.Errorf("drop isolated schema: %v", err)
		}
	}()

	config, err := pgxpool.ParseConfig(os.Getenv("AGENTHOUND_PG_URI"))
	if err != nil {
		t.Fatalf("parse connection config: %v", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect isolated schema: %v", err)
	}
	defer pool.Close()

	for _, name := range []string{"001_initial_v1.sql", "002_remove_campaign_verification.sql"} {
		migrationSQL, readErr := migrationFS.ReadFile("migrations/" + name)
		if readErr != nil {
			t.Fatalf("read %s: %v", name, readErr)
		}
		if _, err := pool.Exec(ctx, string(migrationSQL)); err != nil {
			t.Fatalf("apply %s: %v", name, err)
		}
	}
	if _, err := pool.Exec(ctx, `INSERT INTO schema_migrations (version) VALUES (1), (2)`); err != nil {
		t.Fatalf("record legacy schema: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO scans (id, collector) VALUES ('legacy-instruction-scan', 'config')`); err != nil {
		t.Fatalf("seed scan: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO findings
        (scan_id, fingerprint, edge_kind, evidence, exact_evidence)
        VALUES
        ('legacy-instruction-scan', 'legacypoison0001', 'POISONED_INSTRUCTIONS', '{"state":"observed_signal"}', '{"nodes":[{"id":"sha256:legacy"}],"edges":[]}'),
        ('legacy-instruction-scan', 'currentsignal001', 'INSTRUCTION_SIGNAL', '{"state":"observed_signal"}', '{"nodes":[{"id":"sha256:current"}],"edges":[]}')`); err != nil {
		t.Fatalf("seed findings: %v", err)
	}
	if _, err := pool.Exec(ctx, `INSERT INTO finding_triage (fingerprint, status)
        VALUES ('legacypoison0001', 'confirmed'), ('currentsignal001', 'confirmed')`); err != nil {
		t.Fatalf("seed triage: %v", err)
	}
	export := `{
      "findings":[
        {"id":"legacy","edge_kind":"POISONED_INSTRUCTIONS"},
        {"id":"current","edge_kind":"INSTRUCTION_SIGNAL"}
      ],
      "limits":{"findings":{"returned":2,"total":2,"complete":true}},
      "graph_before":{"total_edges":2,"edge_counts":{"POISONED_INSTRUCTIONS":1,"INSTRUCTION_SIGNAL":1}},
      "graph_after":{"total_edges":2,"edge_counts":{"POISONED_INSTRUCTIONS":1,"INSTRUCTION_SIGNAL":1}}
    }`
	graphStats := `{"total_edges":2,"edge_counts":{"POISONED_INSTRUCTIONS":1,"INSTRUCTION_SIGNAL":1}}`
	if _, err := pool.Exec(ctx, `INSERT INTO posture_publications (scan_id, export, graph_stats)
        VALUES ('legacy-instruction-scan', $1::jsonb, $2::jsonb)`, export, graphStats); err != nil {
		t.Fatalf("seed publication: %v", err)
	}

	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatalf("apply instruction migration: %v", err)
	}

	var poisonFindings, poisonTriage, currentFindings, currentTriage int
	if err := pool.QueryRow(ctx, `SELECT
        count(*) FILTER (WHERE edge_kind = 'POISONED_INSTRUCTIONS'),
        count(*) FILTER (WHERE edge_kind = 'INSTRUCTION_SIGNAL')
        FROM findings`).Scan(&poisonFindings, &currentFindings); err != nil {
		t.Fatalf("read migrated findings: %v", err)
	}
	if err := pool.QueryRow(ctx, `SELECT
        count(*) FILTER (WHERE fingerprint = 'legacypoison0001'),
        count(*) FILTER (WHERE fingerprint = 'currentsignal001')
        FROM finding_triage`).Scan(&poisonTriage, &currentTriage); err != nil {
		t.Fatalf("read migrated triage: %v", err)
	}
	if poisonFindings != 0 || poisonTriage != 0 || currentFindings != 1 || currentTriage != 1 {
		t.Fatalf("migration rows poison=(%d,%d) current=(%d,%d)", poisonFindings, poisonTriage, currentFindings, currentTriage)
	}

	var findingsCount, returned, total, beforeEdges, afterEdges, statsEdges int
	var hasBeforePoison, hasAfterPoison, hasStatsPoison bool
	if err := pool.QueryRow(ctx, `SELECT
        jsonb_array_length(export->'findings'),
        (export #>> '{limits,findings,returned}')::int,
        (export #>> '{limits,findings,total}')::int,
        (export #>> '{graph_before,total_edges}')::int,
        (export #>> '{graph_after,total_edges}')::int,
        (graph_stats ->> 'total_edges')::int,
        (export #> '{graph_before,edge_counts}') ? 'POISONED_INSTRUCTIONS',
        (export #> '{graph_after,edge_counts}') ? 'POISONED_INSTRUCTIONS',
        (graph_stats -> 'edge_counts') ? 'POISONED_INSTRUCTIONS'
        FROM posture_publications`).Scan(
		&findingsCount, &returned, &total, &beforeEdges, &afterEdges, &statsEdges,
		&hasBeforePoison, &hasAfterPoison, &hasStatsPoison,
	); err != nil {
		t.Fatalf("read migrated publication: %v", err)
	}
	if findingsCount != 1 || returned != 1 || total != 1 ||
		beforeEdges != 1 || afterEdges != 1 || statsEdges != 1 ||
		hasBeforePoison || hasAfterPoison || hasStatsPoison {
		t.Fatalf("publication rewrite = findings:%d limits:%d/%d edges:%d/%d/%d legacy:%t/%t/%t",
			findingsCount, returned, total, beforeEdges, afterEdges, statsEdges,
			hasBeforePoison, hasAfterPoison, hasStatsPoison)
	}
}

func TestIntegrationStorageBindingLifecycle(t *testing.T) {
	skipIfNoPG(t)
	ctx := context.Background()

	admin, err := NewPool(os.Getenv("AGENTHOUND_PG_URI"))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer admin.Close()

	schema := fmt.Sprintf("agenthound_binding_test_%d", time.Now().UnixNano())
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatalf("create isolated schema: %v", err)
	}
	defer func() {
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+quotedSchema+" CASCADE"); err != nil {
			t.Errorf("drop isolated schema: %v", err)
		}
	}()

	config, err := pgxpool.ParseConfig(os.Getenv("AGENTHOUND_PG_URI"))
	if err != nil {
		t.Fatalf("parse connection config: %v", err)
	}
	config.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, config)
	if err != nil {
		t.Fatalf("connect isolated schema: %v", err)
	}
	defer pool.Close()
	store := NewStorageBindingStore(pool)

	inspection, err := store.Inspect(ctx)
	if err != nil {
		t.Fatalf("inspect pristine schema: %v", err)
	}
	if inspection.Marker != nil || !inspection.ProductEmpty {
		t.Fatalf("pristine inspection = %+v, want unbound and product-empty", inspection)
	}
	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	marker, err := binding.NewMarker(integrationStoragePairID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Install(ctx, marker); err != nil {
		t.Fatalf("install marker: %v", err)
	}
	if err := store.Install(ctx, marker); err != nil {
		t.Fatalf("idempotent marker install: %v", err)
	}
	actual, err := store.ReadStorageBinding(ctx)
	if err != nil || !actual.Equal(marker) {
		t.Fatalf("read marker = %+v, %v", actual, err)
	}
	other, err := binding.NewMarker("ee2f3afe-209e-42fb-8685-af55caa7e58d")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Install(ctx, other); err == nil {
		t.Fatal("conflicting storage pair unexpectedly replaced immutable marker")
	}

	if _, err := pool.Exec(ctx, "INSERT INTO scans (id, collector) VALUES ('binding-product-row', 'scan')"); err != nil {
		t.Fatalf("insert product row: %v", err)
	}
	if _, err := pool.Exec(ctx, "DELETE FROM storage_binding"); err != nil {
		t.Fatalf("remove marker for unbound-state proof: %v", err)
	}
	inspection, err = store.Inspect(ctx)
	if err != nil {
		t.Fatalf("inspect unbound state: %v", err)
	}
	if inspection.Marker != nil || inspection.ProductEmpty {
		t.Fatalf("unbound inspection = %+v, want unbound and nonempty", inspection)
	}
}

func TestIntegrationScansCRUD(t *testing.T) {
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

	scanID := "test-scan-" + time.Now().Format("20060102150405")

	// Create
	scan := &model.Scan{
		ID:        scanID,
		Collector: "mcp",
		Status:    model.ScanStatusRunning,
		StartedAt: time.Now().UTC(),
		Metadata: map[string]any{
			"ruleset": map[string]any{
				"authenticity": "unverified",
				"entries": []any{map[string]any{
					"id": "persisted-rule",
					"effective_matcher": map[string]any{
						"type":     "keyword",
						"keywords": []any{"persisted"},
					},
				}},
			},
		},
	}
	if err := store.CreateScan(ctx, scan); err != nil {
		t.Fatalf("create: %v", err)
	}

	// Read
	got, err := store.GetScan(ctx, scanID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Collector != "mcp" {
		t.Errorf("collector: got %q, want mcp", got.Collector)
	}
	if got.Status != model.ScanStatusRunning {
		t.Errorf("status: got %q, want running", got.Status)
	}
	ruleset, ok := got.Metadata["ruleset"].(map[string]any)
	if !ok {
		t.Fatalf("persisted ruleset metadata = %#v", got.Metadata["ruleset"])
	}
	entries, ok := ruleset["entries"].([]any)
	if !ok || len(entries) != 1 {
		t.Fatalf("persisted ruleset entries = %#v", ruleset["entries"])
	}
	entry, ok := entries[0].(map[string]any)
	if !ok {
		t.Fatalf("persisted ruleset entry = %#v", entries[0])
	}
	matcher, ok := entry["effective_matcher"].(map[string]any)
	if !ok || matcher["type"] != "keyword" {
		t.Fatalf("persisted canonical matcher = %#v", entry["effective_matcher"])
	}

	// List
	scans, err := store.ListScans(ctx, 10, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(scans) == 0 {
		t.Error("expected at least 1 scan in list")
	}

	// Cleanup
	_, _ = pool.Exec(ctx, "DELETE FROM scans WHERE id = $1", scanID)
}

func TestIntegrationRecoverInterruptedIngests(t *testing.T) {
	skipIfNoPG(t)
	ctx := context.Background()

	admin, err := NewPool(os.Getenv("AGENTHOUND_PG_URI"))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer admin.Close()

	schema := fmt.Sprintf("agenthound_recovery_test_%d", time.Now().UnixNano())
	quotedSchema := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quotedSchema); err != nil {
		t.Fatalf("create isolated schema: %v", err)
	}
	defer func() {
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+quotedSchema+" CASCADE"); err != nil {
			t.Errorf("drop isolated schema: %v", err)
		}
	}()

	config, err := pgxpool.ParseConfig(os.Getenv("AGENTHOUND_PG_URI"))
	if err != nil {
		t.Fatalf("parse connection config: %v", err)
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
	started := time.Now().UTC()
	publishedID := "published-before-interruption"
	interruptedID := "interrupted-ingest"
	pendingID := "intentionally-pending"
	if err := scans.CreateScan(ctx, &model.Scan{
		ID:                publishedID,
		Collector:         "mcp",
		Status:            model.ScanStatusCompleted,
		StartedAt:         started.Add(-time.Minute),
		CollectionStatus:  model.LifecycleComplete,
		GraphStatus:       model.LifecycleComplete,
		AnalysisStatus:    model.LifecycleComplete,
		SnapshotStatus:    model.LifecycleComplete,
		ProjectionStatus:  model.ProjectionComplete,
		PublicationStatus: model.PublicationPublished,
	}); err != nil {
		t.Fatalf("create prior published scan: %v", err)
	}
	var revision int64
	var publishedAt time.Time
	if err := pool.QueryRow(ctx, `INSERT INTO posture_publications (scan_id)
		VALUES ($1) RETURNING revision, published_at`,
		publishedID,
	).Scan(&revision, &publishedAt); err != nil {
		t.Fatalf("create prior publication: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE scans SET
	    published_revision = $1,
	    published_at = $2
	WHERE id = $3`,
		revision,
		publishedAt,
		publishedID,
	); err != nil {
		t.Fatalf("attach prior publication to scan: %v", err)
	}
	if _, err := pool.Exec(ctx, `UPDATE posture_state SET
	    projection_status = $1,
	    projection_scan_id = $2,
	    published_revision = $3,
	    published_scan_id = $2,
	    published_at = $4
	WHERE singleton = TRUE`,
		model.ProjectionComplete,
		publishedID,
		revision,
		publishedAt,
	); err != nil {
		t.Fatalf("select prior publication: %v", err)
	}

	dirtyCoverage := []string{"mcp:target:sha256:interrupted"}
	if _, err := scans.BeginScan(ctx, &model.Scan{
		ID:                interruptedID,
		Collector:         "mcp",
		Status:            model.ScanStatusRunning,
		StartedAt:         started,
		CollectionStatus:  model.LifecycleComplete,
		GraphStatus:       model.LifecyclePending,
		AnalysisStatus:    model.LifecyclePending,
		SnapshotStatus:    model.LifecyclePending,
		ProjectionStatus:  model.ProjectionUpdating,
		PublicationStatus: model.PublicationUnpublished,
	}, dirtyCoverage, nil); err != nil {
		t.Fatalf("begin interrupted scan: %v", err)
	}
	if err := scans.CreateScan(ctx, &model.Scan{
		ID:                pendingID,
		Collector:         "a2a",
		Status:            model.ScanStatusPending,
		StartedAt:         started,
		CollectionStatus:  model.LifecyclePending,
		GraphStatus:       model.LifecyclePending,
		AnalysisStatus:    model.LifecyclePending,
		SnapshotStatus:    model.LifecyclePending,
		ProjectionStatus:  model.ProjectionUnknown,
		PublicationStatus: model.PublicationUnpublished,
	}); err != nil {
		t.Fatalf("create pending scan: %v", err)
	}

	recovered, err := scans.RecoverInterruptedIngests(ctx)
	if err != nil {
		t.Fatalf("recover interrupted ingests: %v", err)
	}
	if !reflect.DeepEqual(recovered, []string{interruptedID}) {
		t.Fatalf("recovered scans = %v", recovered)
	}
	interrupted, err := scans.GetScan(ctx, interruptedID)
	if err != nil {
		t.Fatalf("get interrupted scan: %v", err)
	}
	if interrupted.Status != model.ScanStatusFailed ||
		interrupted.CompletedAt == nil ||
		interrupted.CollectionStatus != model.LifecycleComplete ||
		interrupted.GraphStatus != model.LifecycleFailed ||
		interrupted.AnalysisStatus != model.LifecycleFailed ||
		interrupted.SnapshotStatus != model.LifecycleFailed ||
		interrupted.ProjectionStatus != model.ProjectionIncomplete ||
		interrupted.Error != interruptedIngestError {
		t.Fatalf("recovered interrupted scan = %+v", interrupted)
	}
	pending, err := scans.GetScan(ctx, pendingID)
	if err != nil {
		t.Fatalf("get pending scan: %v", err)
	}
	if pending.Status != model.ScanStatusPending || pending.CompletedAt != nil {
		t.Fatalf("pending scan changed during recovery: %+v", pending)
	}
	state, err := findings.GetProjectionState(ctx)
	if err != nil {
		t.Fatalf("get recovered projection state: %v", err)
	}
	if state.Status != model.ProjectionIncomplete ||
		state.ScanID != interruptedID ||
		state.Error != interruptedIngestError ||
		state.PublishedScanID != publishedID ||
		state.PublishedRevision == nil ||
		*state.PublishedRevision != revision ||
		!reflect.DeepEqual(state.DirtyCoverage, dirtyCoverage) {
		t.Fatalf("recovered projection state = %+v", state)
	}

	recovered, err = scans.RecoverInterruptedIngests(ctx)
	if err != nil {
		t.Fatalf("repeat recovery: %v", err)
	}
	if len(recovered) != 0 {
		t.Fatalf("repeat recovery changed scans: %v", recovered)
	}
}
