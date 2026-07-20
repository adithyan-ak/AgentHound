package appdb

import (
	"reflect"
	"strings"
	"testing"
)

func TestMigrationsContainOnlyCurrentInitialSchema(t *testing.T) {
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
	if want := []string{"001_initial.sql"}; !reflect.DeepEqual(names, want) {
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
		"CREATE TABLE storage_binding",
		"storage_pair_id",
		"network_realm_id",
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
	} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("initial migration contains historical schema operation %q", forbidden)
		}
	}
}
