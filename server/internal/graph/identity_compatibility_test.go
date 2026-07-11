package graph

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
)

func TestReconcileMCPStdioIdentitiesQuarantinesPersistedFanIn(t *testing.T) {
	db := &MockGraphDB{
		QueryResult: []map[string]any{{
			"legacy_id":     "legacy",
			"legacy_exists": true,
			"current_ids":   []any{"current-b", "current-a"},
		}},
		ExecuteWriteFunc: func(
			_ context.Context,
			query string,
			_ map[string]any,
		) (int, error) {
			if query == persistLegacyMCPIdentityCompatibilityCypher {
				return 1, nil
			}
			return 2, nil
		},
	}

	resolved, stats, err := ReconcileMCPStdioIdentities(
		context.Background(),
		db,
		[]sdkingest.IdentityAlias{{
			LegacyID:   "legacy",
			CurrentIDs: []string{"current-a"},
			State:      sdkingest.IdentityAliasOneToOne,
		}},
	)
	if err != nil {
		t.Fatalf("ReconcileMCPStdioIdentities: %v", err)
	}
	if len(resolved) != 1 ||
		resolved[0].State != sdkingest.IdentityAliasAmbiguous ||
		!reflect.DeepEqual(resolved[0].CurrentIDs, []string{"current-a", "current-b"}) {
		t.Fatalf("resolved aliases = %+v", resolved)
	}
	if stats.AmbiguousAliases != 1 ||
		stats.OneToOneAliases != 0 ||
		stats.LegacyNodesUpdated != 1 ||
		stats.CurrentNodesUpdated != 2 ||
		stats.LegacyNodesMigrated != 0 {
		t.Fatalf("stats = %+v", stats)
	}

	writes := db.CallsTo("ExecuteWrite")
	if len(writes) != 2 {
		t.Fatalf("compatibility writes = %d, want 2", len(writes))
	}
	params, ok := writes[0].Args[1].(map[string]any)
	if !ok {
		t.Fatalf("write params type = %T", writes[0].Args[1])
	}
	persisted, ok := params["aliases"].([]map[string]any)
	if !ok || len(persisted) != 1 {
		t.Fatalf("persisted aliases = %#v", params["aliases"])
	}
	if persisted[0]["state"] != string(sdkingest.IdentityAliasAmbiguous) ||
		persisted[0]["quarantined"] != true ||
		persisted[0]["alias_target"] != nil {
		t.Fatalf("persisted quarantine = %#v", persisted[0])
	}
	for _, call := range writes {
		query, _ := call.Args[0].(string)
		if strings.Contains(query, "CREATE") ||
			strings.Contains(query, "MERGE") ||
			strings.Contains(query, "DELETE") ||
			strings.Contains(query, "]-") {
			t.Fatalf("compatibility reconciliation rewires graph relationships: %s", query)
		}
	}
}

func TestReconcileMCPStdioIdentitiesAliasesOnlyProvenOneToOne(t *testing.T) {
	tests := []struct {
		name       string
		claim      sdkingest.IdentityAliasState
		wantState  sdkingest.IdentityAliasState
		wantTarget any
		wantWrites int
	}{
		{
			name:       "complete collector claim",
			claim:      sdkingest.IdentityAliasOneToOne,
			wantState:  sdkingest.IdentityAliasOneToOne,
			wantTarget: "current",
			wantWrites: 3,
		},
		{
			name:       "incomplete collector claim",
			claim:      sdkingest.IdentityAliasUnresolved,
			wantState:  sdkingest.IdentityAliasUnresolved,
			wantTarget: nil,
			wantWrites: 2,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := &MockGraphDB{QueryResult: []map[string]any{{
				"legacy_id":     "legacy",
				"legacy_exists": true,
				"current_ids":   []any{"current"},
			}}, ExecuteWriteFunc: func(
				_ context.Context,
				query string,
				_ map[string]any,
			) (int, error) {
				if query == migrateLegacyMCPIdentityCypher {
					return 1, nil
				}
				return 0, nil
			}}
			resolved, _, err := ReconcileMCPStdioIdentities(
				context.Background(),
				db,
				[]sdkingest.IdentityAlias{{
					LegacyID:   "legacy",
					CurrentIDs: []string{"current"},
					State:      tt.claim,
				}},
			)
			if err != nil {
				t.Fatalf("ReconcileMCPStdioIdentities: %v", err)
			}
			if len(resolved) != 1 || resolved[0].State != tt.wantState {
				t.Fatalf("resolved aliases = %+v, want %q", resolved, tt.wantState)
			}
			calls := db.CallsTo("ExecuteWrite")
			if len(calls) != tt.wantWrites {
				t.Fatalf("ExecuteWrite calls = %d, want %d", len(calls), tt.wantWrites)
			}
			params, ok := calls[0].Args[1].(map[string]any)
			if !ok {
				t.Fatalf("ExecuteWrite params = %#v, want map[string]any", calls[0].Args[1])
			}
			persisted, ok := params["aliases"].([]map[string]any)
			if !ok || len(persisted) != 1 {
				t.Fatalf("persisted aliases = %#v, want one alias", params["aliases"])
			}
			if persisted[0]["alias_target"] != tt.wantTarget {
				t.Fatalf("alias target = %#v, want %#v", persisted[0]["alias_target"], tt.wantTarget)
			}
			if tt.wantWrites == 3 {
				migrationQuery, _ := calls[2].Args[0].(string)
				if migrationQuery != migrateLegacyMCPIdentityCypher {
					t.Fatal("one-to-one alias did not use transactional migration query")
				}
			}
		})
	}
}

func TestReconcileMCPStdioIdentitiesMigratesOnlyPersistedOneToOneLegacy(t *testing.T) {
	db := &MockGraphDB{
		QueryResult: []map[string]any{
			{
				"legacy_id":     "ambiguous-legacy",
				"legacy_exists": true,
				"current_ids":   []any{"ambiguous-a", "ambiguous-b"},
			},
			{
				"legacy_id":     "one-legacy",
				"legacy_exists": true,
				"current_ids":   []any{"one-current"},
			},
			{
				"legacy_id":     "retired-legacy",
				"legacy_exists": false,
				"current_ids":   []any{"retired-current"},
			},
		},
		ExecuteWriteFunc: func(
			_ context.Context,
			query string,
			_ map[string]any,
		) (int, error) {
			if query == migrateLegacyMCPIdentityCypher {
				return 1, nil
			}
			return 0, nil
		},
	}
	aliases := []sdkingest.IdentityAlias{
		{
			LegacyID:   "ambiguous-legacy",
			CurrentIDs: []string{"ambiguous-a"},
			State:      sdkingest.IdentityAliasOneToOne,
		},
		{
			LegacyID:   "one-legacy",
			CurrentIDs: []string{"one-current"},
			State:      sdkingest.IdentityAliasOneToOne,
		},
		{
			LegacyID:   "retired-legacy",
			CurrentIDs: []string{"retired-current"},
			State:      sdkingest.IdentityAliasOneToOne,
		},
	}

	resolved, stats, err := ReconcileMCPStdioIdentities(
		context.Background(),
		db,
		aliases,
	)
	if err != nil {
		t.Fatalf("ReconcileMCPStdioIdentities: %v", err)
	}
	if len(resolved) != 3 ||
		stats.OneToOneAliases != 2 ||
		stats.AmbiguousAliases != 1 ||
		stats.LegacyNodesMigrated != 1 {
		t.Fatalf("resolved = %+v, stats = %+v", resolved, stats)
	}

	writes := db.CallsTo("ExecuteWrite")
	if len(writes) != 3 {
		t.Fatalf("ExecuteWrite calls = %d, want 3", len(writes))
	}
	migrationParams, ok := writes[2].Args[1].(map[string]any)
	if !ok {
		t.Fatalf("migration params type = %T", writes[2].Args[1])
	}
	migrationAliases, ok := migrationParams["aliases"].([]map[string]any)
	if !ok || len(migrationAliases) != 1 {
		t.Fatalf("migration aliases = %#v, want one", migrationParams["aliases"])
	}
	if migrationAliases[0]["legacy_id"] != "one-legacy" ||
		migrationAliases[0]["state"] != string(sdkingest.IdentityAliasOneToOne) {
		t.Fatalf("unsafe migration alias = %#v", migrationAliases[0])
	}
	if got := migrationParams["allowed_relationship_kinds"]; !reflect.DeepEqual(
		got,
		mcpIdentityMigrationRelationshipKinds,
	) {
		t.Fatalf("allowed relationship kinds = %#v", got)
	}
}

func TestReconcileMCPStdioIdentitiesFailsClosedWhenMigrationGuardRejectsAlias(t *testing.T) {
	db := &MockGraphDB{QueryResult: []map[string]any{{
		"legacy_id":     "legacy",
		"legacy_exists": true,
		"current_ids":   []any{"current"},
	}}}

	_, stats, err := ReconcileMCPStdioIdentities(
		context.Background(),
		db,
		[]sdkingest.IdentityAlias{{
			LegacyID:   "legacy",
			CurrentIDs: []string{"current"},
			State:      sdkingest.IdentityAliasOneToOne,
		}},
	)
	if err == nil || !strings.Contains(err.Error(), "migrated 0 of 1 aliases") {
		t.Fatalf("migration guard error = %v", err)
	}
	if stats.LegacyNodesMigrated != 0 {
		t.Fatalf("stats = %+v", stats)
	}
	if writes := db.CallsTo("ExecuteWrite"); len(writes) != 3 {
		t.Fatalf("ExecuteWrite calls = %d, want 3", len(writes))
	}
}

func TestMigrateLegacyMCPIdentityCypherContract(t *testing.T) {
	query := migrateLegacyMCPIdentityCypher
	for _, forbidden := range []string{"apoc.", "DETACH DELETE"} {
		if strings.Contains(query, forbidden) {
			t.Fatalf("migration query contains forbidden %q", forbidden)
		}
	}
	for _, required := range []string{
		"alias.state = $one_to_one_state",
		"size(alias.current_ids) = 1",
		"MATCH (current:MCPServer {objectid: alias.current_ids[0]})",
		"current.legacy_objectid = alias.legacy_id",
		"candidate_count = 1",
		"legacy.identity_quarantined, false",
		"current.legacy_identity_quarantined, false",
		"kind IN $allowed_relationship_kinds",
		"size(migrations) = size(requested_aliases)",
		"SET current += legacy {.*",
		"current.observation_tokens = reduce(",
		"SET replacement += properties(old)",
		"replacement.observation_tokens = reduce(",
		"DELETE old",
		"DELETE legacy",
	} {
		if !strings.Contains(query, required) {
			t.Fatalf("migration query missing contract %q", required)
		}
	}

	wantKinds := make([]string, 0, len(sdkingest.AllowedEdgeKinds))
	for kind := range sdkingest.AllowedEdgeKinds {
		wantKinds = append(wantKinds, kind)
	}
	sort.Strings(wantKinds)
	if !reflect.DeepEqual(mcpIdentityMigrationRelationshipKinds, wantKinds) {
		t.Fatalf(
			"migration relationship kinds = %q, want %q",
			mcpIdentityMigrationRelationshipKinds,
			wantKinds,
		)
	}
	for _, kind := range wantKinds {
		for _, pattern := range []string{
			"MATCH (legacy)-[old:" + kind + "]->(legacy)",
			"MERGE (current)-[replacement:" + kind + "]->(current)",
			"MATCH (legacy)-[old:" + kind + "]->(other)",
			"MERGE (current)-[replacement:" + kind + "]->(other)",
			"MATCH (other)-[old:" + kind + "]->(legacy)",
			"MERGE (other)-[replacement:" + kind + "]->(current)",
		} {
			if !strings.Contains(query, pattern) {
				t.Fatalf("migration query does not rewire %s: missing %q", kind, pattern)
			}
		}
	}
}
