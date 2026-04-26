package appdb

import (
	"context"
	"os"
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
	mustExist := []string{"scans", "schema_migrations"}
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
