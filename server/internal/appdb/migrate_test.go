package appdb

import (
	"strings"
	"testing"
)

func TestMigration008CarriesCompleteDeterministicATLASBackfill(t *testing.T) {
	data, err := migrationFS.ReadFile("migrations/008_atlas_rules_compat.sql")
	if err != nil {
		t.Fatalf("read migration 008: %v", err)
	}
	sql := string(data)
	for _, expected := range []string{
		`WHEN 'CAN_EXFILTRATE_VIA' THEN '["AML.T0086"]'::jsonb`,
		`WHEN 'POISONED_DESCRIPTION' THEN '["AML.T0051","AML.T0110"]'::jsonb`,
		`WHEN 'SHADOWS' THEN '["AML.T0110"]'::jsonb`,
		`WHEN 'POISONED_INSTRUCTIONS' THEN '["AML.T0051"]'::jsonb`,
		`WHEN 'TAINTS' THEN '["AML.T0051"]'::jsonb`,
		`WHEN 'IFC_VIOLATION' THEN '["AML.T0057","AML.T0086"]'::jsonb`,
		`WHEN 'POISONS_CONTEXT' THEN '["AML.T0051","AML.T0110"]'::jsonb`,
	} {
		if !strings.Contains(sql, expected) {
			t.Errorf("migration 008 missing deterministic mapping %q", expected)
		}
	}
	if !strings.Contains(sql, `WHERE atlas_map = '[]'::jsonb`) {
		t.Fatal("migration 008 can overwrite non-empty ATLAS evidence")
	}
}
