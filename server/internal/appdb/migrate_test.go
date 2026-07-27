package appdb

import (
	"reflect"
	"strings"
	"testing"
)

func TestMigrationsContainCanonicalV1Schema(t *testing.T) {
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
	if want := []string{"001_initial_v1.sql"}; !reflect.DeepEqual(names, want) {
		t.Fatalf("migration files = %v, want %v", names, want)
	}

	data, err := migrationFS.ReadFile("migrations/001_initial_v1.sql")
	if err != nil {
		t.Fatalf("read initial V1 migration: %v", err)
	}
	sql := string(data)
	for _, expected := range []string{
		"CREATE TABLE IF NOT EXISTS scans",
		"artifact_observed_at",
		"publication_status",
		"CREATE TABLE IF NOT EXISTS findings",
		"exact_evidence",
		"CREATE TABLE IF NOT EXISTS finding_triage",
		"CREATE TABLE IF NOT EXISTS coverage_heads",
		"coverage_heads_root_metadata_check",
		"contract_generation",
		"CREATE TABLE IF NOT EXISTS coverage_memberships",
		"CREATE TABLE IF NOT EXISTS coverage_limitations",
		"parent_coverage_key",
		"CREATE TABLE IF NOT EXISTS storage_binding",
		"storage_pair_id",
		"CREATE TABLE IF NOT EXISTS posture_publications",
		"CREATE TABLE IF NOT EXISTS posture_state",
		"ON CONFLICT (singleton) DO NOTHING",
	} {
		if !strings.Contains(sql, expected) {
			t.Errorf("initial V1 migration missing %q", expected)
		}
	}
	for _, forbidden := range []string{
		"ALTER TABLE",
		"DROP TABLE",
		"FROM coverage_heads",
	} {
		if strings.Contains(sql, forbidden) {
			t.Errorf("initial V1 migration contains non-initialization operation %q", forbidden)
		}
	}
}
