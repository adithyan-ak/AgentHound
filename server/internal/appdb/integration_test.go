package appdb

import (
	"context"
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/adithyan-ak/agenthound/server/model"
)

func skipIfNoPG(t *testing.T) {
	t.Helper()
	if os.Getenv("AGENTHOUND_PG_URI") == "" {
		t.Skip("skipping integration test: AGENTHOUND_PG_URI not set")
	}
}

func TestIntegrationMigrations(t *testing.T) {
	skipIfNoPG(t)
	ctx := context.Background()

	pool, err := NewPool(os.Getenv("AGENTHOUND_PG_URI"))
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	// Should succeed
	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatalf("migrate: %v", err)
	}

	// Should be idempotent
	if err := RunMigrations(ctx, pool); err != nil {
		t.Fatalf("migrate (idempotent): %v", err)
	}

	// scans + schema_migrations must exist after migrations.
	// users / api_tokens / audit_log were created by 001 then dropped by
	// 002_remove_multiuser.sql, so they must NOT exist on a fresh install.
	mustExist := []string{
		"scans",
		"schema_migrations",
		"coverage_heads",
		"posture_publications",
		"posture_state",
	}
	mustNotExist := []string{"users", "api_tokens", "audit_log"}

	for _, table := range mustExist {
		var exists bool
		err := pool.QueryRow(ctx,
			"SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)", table).Scan(&exists)
		if err != nil {
			t.Errorf("check table %s: %v", table, err)
		}
		if !exists {
			t.Errorf("table %s does not exist after migrations", table)
		}
	}
	for _, table := range mustNotExist {
		var exists bool
		err := pool.QueryRow(ctx,
			"SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = $1)", table).Scan(&exists)
		if err != nil {
			t.Errorf("check table %s: %v", table, err)
		}
		if exists {
			t.Errorf("table %s should have been dropped by 002_remove_multiuser.sql", table)
		}
	}
}

func TestIntegrationMigration008BackfillsHistoricalATLASMappings(t *testing.T) {
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

	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("begin upgrade fixture: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	scanID := "atlas-upgrade-" + time.Now().Format("20060102150405.000000")
	if _, err := tx.Exec(ctx, `INSERT INTO scans (id, collector, status, started_at)
		VALUES ($1, 'mcp', 'completed', NOW())`, scanID); err != nil {
		t.Fatalf("insert upgrade scan: %v", err)
	}
	fixtures := []struct {
		fingerprint string
		edgeKind    string
		atlas       string
	}{
		{"atlas-map-000001", "CAN_EXFILTRATE_VIA", `[]`},
		{"atlas-map-000002", "POISONED_DESCRIPTION", `[]`},
		{"atlas-map-000003", "SHADOWS", `[]`},
		{"atlas-map-000004", "POISONED_INSTRUCTIONS", `[]`},
		{"atlas-map-000005", "TAINTS", `[]`},
		{"atlas-map-000006", "IFC_VIOLATION", `[]`},
		{"atlas-map-000007", "POISONS_CONTEXT", `[]`},
		{"atlas-map-000008", "CAN_REACH", `[]`},
		{"atlas-map-000009", "CAN_EXFILTRATE_VIA", `["AML.CUSTOM"]`},
	}
	for _, fixture := range fixtures {
		if _, err := tx.Exec(ctx, `INSERT INTO findings
			(scan_id, fingerprint, edge_kind, atlas_map)
			VALUES ($1, $2, $3, $4::jsonb)`,
			scanID,
			fixture.fingerprint,
			fixture.edgeKind,
			fixture.atlas,
		); err != nil {
			t.Fatalf("insert historical finding %s: %v", fixture.edgeKind, err)
		}
	}

	migration, err := migrationFS.ReadFile("migrations/008_atlas_rules_compat.sql")
	if err != nil {
		t.Fatalf("read migration 008: %v", err)
	}
	if _, err := tx.Exec(ctx, string(migration)); err != nil {
		t.Fatalf("apply migration 008 to historical rows: %v", err)
	}
	if _, err := tx.Exec(ctx, string(migration)); err != nil {
		t.Fatalf("reapply migration 008: %v", err)
	}

	want := map[string][]string{
		"CAN_EXFILTRATE_VIA":    {"AML.T0086"},
		"POISONED_DESCRIPTION":  {"AML.T0051", "AML.T0110"},
		"SHADOWS":               {"AML.T0110"},
		"POISONED_INSTRUCTIONS": {"AML.T0051"},
		"TAINTS":                {"AML.T0051"},
		"IFC_VIOLATION":         {"AML.T0057", "AML.T0086"},
		"POISONS_CONTEXT":       {"AML.T0051", "AML.T0110"},
		"CAN_REACH":             {},
	}
	rows, err := tx.Query(ctx, `SELECT fingerprint, edge_kind, atlas_map
		FROM findings WHERE scan_id = $1 ORDER BY fingerprint`, scanID)
	if err != nil {
		t.Fatalf("read upgraded findings: %v", err)
	}
	defer rows.Close()
	seen := 0
	for rows.Next() {
		seen++
		var fingerprint, edgeKind string
		var encoded []byte
		if err := rows.Scan(&fingerprint, &edgeKind, &encoded); err != nil {
			t.Fatalf("scan upgraded finding: %v", err)
		}
		var got []string
		if err := json.Unmarshal(encoded, &got); err != nil {
			t.Fatalf("decode upgraded atlas_map for %s: %v", fingerprint, err)
		}
		if fingerprint == "atlas-map-000009" {
			if !reflect.DeepEqual(got, []string{"AML.CUSTOM"}) {
				t.Fatalf("non-empty ATLAS evidence overwritten: %v", got)
			}
			continue
		}
		if !reflect.DeepEqual(got, want[edgeKind]) {
			t.Fatalf("atlas_map for %s = %v, want %v", edgeKind, got, want[edgeKind])
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("read upgraded findings: %v", err)
	}
	if seen != len(fixtures) {
		t.Fatalf("upgraded finding rows = %d, want %d", seen, len(fixtures))
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

	// Update
	if err := store.UpdateScan(ctx, scanID, model.ScanStatusCompleted, 10, 5, ""); err != nil {
		t.Fatalf("update: %v", err)
	}

	got, err = store.GetScan(ctx, scanID)
	if err != nil {
		t.Fatalf("get after update: %v", err)
	}
	if got.Status != model.ScanStatusCompleted {
		t.Errorf("status: got %q, want completed", got.Status)
	}
	if got.NodeCount != 10 {
		t.Errorf("node_count: got %d, want 10", got.NodeCount)
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
