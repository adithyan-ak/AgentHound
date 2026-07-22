package appdb

import (
	"reflect"
	"strings"
	"testing"
)

func TestMigrationsContainCurrentSchemaAndBindingUpgrade(t *testing.T) {
	entries, err := migrationFS.ReadDir("migrations")
	if err != nil {
		t.Fatalf("read migrations: %v", err)
	}
	var names []string
	for _, entry := range entries {
		if !entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	if want := []string{"001_initial.sql", "002_storage_binding.sql", "003_zero_config_storage_binding.sql"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("migration files = %v, want %v", names, want)
	}

	data, err := migrationFS.ReadFile("migrations/001_initial.sql")
	if err != nil {
		t.Fatalf("read initial migration: %v", err)
	}
	sql := string(data)
	for _, expected := range []string{
		"CREATE TABLE IF NOT EXISTS scans",
		"artifact_observed_at",
		"publication_status",
		"CREATE TABLE IF NOT EXISTS findings",
		"atlas_map",
		"exact_evidence",
		"CREATE TABLE IF NOT EXISTS finding_triage",
		"CREATE TABLE IF NOT EXISTS coverage_heads",
		"root_key",
		"CREATE TABLE IF NOT EXISTS posture_publications",
		"CREATE TABLE IF NOT EXISTS posture_state",
		"ON CONFLICT (singleton) DO NOTHING",
	} {
		if !strings.Contains(sql, expected) {
			t.Errorf("initial migration missing %q", expected)
		}
	}
	for _, forbidden := range []string{
		"ALTER TABLE",
		"DROP TABLE",
		"\nUPDATE ",
		"CREATE TABLE IF NOT EXISTS users",
		"CREATE TABLE IF NOT EXISTS api_tokens",
		"CREATE TABLE IF NOT EXISTS audit_log",
		"CREATE TABLE storage_binding",
	} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("initial migration contains historical schema operation %q", forbidden)
		}
	}

	data, err = migrationFS.ReadFile("migrations/002_storage_binding.sql")
	if err != nil {
		t.Fatalf("read storage-binding migration: %v", err)
	}
	upgradeSQL := string(data)
	for _, expected := range []string{
		"CREATE TABLE IF NOT EXISTS storage_binding",
		"storage_pair_id",
		"network_realm_id",
		"realm_sha256",
	} {
		if !strings.Contains(upgradeSQL, expected) {
			t.Errorf("storage-binding migration missing %q", expected)
		}
	}

	data, err = migrationFS.ReadFile("migrations/003_zero_config_storage_binding.sql")
	if err != nil {
		t.Fatalf("read ingest-v4 migration: %v", err)
	}
	v4SQL := string(data)
	for _, expected := range []string{
		"DROP COLUMN IF EXISTS host_id",
		"DROP COLUMN IF EXISTS network_realm_id",
		"CREATE TABLE IF NOT EXISTS coverage_memberships",
		"parent_key",
	} {
		if !strings.Contains(v4SQL, expected) {
			t.Errorf("ingest-v4 migration missing %q", expected)
		}
	}
}
