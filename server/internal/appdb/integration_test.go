package appdb

import (
	"context"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
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
	if want := []int{1, 2}; !reflect.DeepEqual(versions, want) {
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

func TestIntegrationMigrationsUpgradeProductEmptyV1Schema(t *testing.T) {
	skipIfNoPG(t)
	ctx := context.Background()

	admin, err := NewPool(os.Getenv("AGENTHOUND_PG_URI"))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer admin.Close()

	schema := fmt.Sprintf("agenthound_migration_upgrade_test_%d", time.Now().UnixNano())
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

	initialSQL, err := migrationFS.ReadFile("migrations/001_initial.sql")
	if err != nil {
		t.Fatalf("read initial migration: %v", err)
	}
	if _, err := pool.Exec(ctx, string(initialSQL)); err != nil {
		t.Fatalf("install pre-binding v1 schema: %v", err)
	}
	if _, err := pool.Exec(ctx, "INSERT INTO schema_migrations (version) VALUES (1)"); err != nil {
		t.Fatalf("record pre-binding migration version: %v", err)
	}

	store := NewStorageBindingStore(pool)
	inspection, err := store.Inspect(ctx)
	if err != nil {
		t.Fatalf("inspect pre-binding v1 schema: %v", err)
	}
	if inspection.Marker != nil || !inspection.ProductEmpty {
		t.Fatalf("pre-binding v1 inspection = %+v, want unbound and product-empty", inspection)
	}

	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatalf("upgrade pre-binding v1 schema: %v", err)
	}
	markerTable, err := relationExists(ctx, pool, "storage_binding")
	if err != nil {
		t.Fatalf("inspect upgraded storage-binding table: %v", err)
	}
	if !markerTable {
		t.Fatal("upgrade left the product-empty v1 schema without storage_binding")
	}

	origin := sdkingest.CollectionOrigin{HostID: "upgrade-host", NetworkRealmID: "upgrade-realm"}
	marker, err := binding.NewMarker(origin, integrationStoragePairID)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Install(ctx, marker); err != nil {
		t.Fatalf("install marker after v1 upgrade: %v", err)
	}
	actual, err := store.ReadStorageBinding(ctx)
	if err != nil || !actual.Equal(marker) {
		t.Fatalf("read upgraded marker = %+v, %v", actual, err)
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

	origin := sdkingest.CollectionOrigin{HostID: "host-a", NetworkRealmID: "realm-a"}
	marker, err := binding.NewMarker(origin, integrationStoragePairID)
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
	other, err := binding.NewMarker(origin, "ee2f3afe-209e-42fb-8685-af55caa7e58d")
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
		t.Fatalf("remove marker for legacy-state proof: %v", err)
	}
	inspection, err = store.Inspect(ctx)
	if err != nil {
		t.Fatalf("inspect legacy state: %v", err)
	}
	if inspection.Marker != nil || inspection.ProductEmpty {
		t.Fatalf("legacy inspection = %+v, want unbound and nonempty", inspection)
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
