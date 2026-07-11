package graph

import (
	"context"
	"fmt"
	"sort"
	"strings"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
)

type IdentityCompatibilityStats struct {
	AliasesEvaluated    int `json:"aliases_evaluated"`
	OneToOneAliases     int `json:"one_to_one_aliases"`
	AmbiguousAliases    int `json:"ambiguous_aliases"`
	UnresolvedAliases   int `json:"unresolved_aliases"`
	LegacyNodesUpdated  int `json:"legacy_nodes_updated"`
	CurrentNodesUpdated int `json:"current_nodes_updated"`
	LegacyNodesMigrated int `json:"legacy_nodes_migrated"`
}

const discoverMCPIdentityCandidatesCypher = `
UNWIND $legacy_ids AS legacy_id
OPTIONAL MATCH (legacy:MCPServer {objectid: legacy_id})
WHERE coalesce(legacy.transport, 'stdio') = 'stdio'
  AND coalesce(legacy.id_scheme, $v1_scheme) = $v1_scheme
WITH legacy_id, count(DISTINCT legacy) > 0 AS legacy_exists
OPTIONAL MATCH (current:MCPServer {legacy_objectid: legacy_id})
WHERE coalesce(current.id_scheme, $v2_scheme) = $v2_scheme
RETURN legacy_id,
       legacy_exists,
       collect(DISTINCT current.objectid) AS current_ids`

const persistLegacyMCPIdentityCompatibilityCypher = `
UNWIND $aliases AS alias
MATCH (legacy:MCPServer {objectid: alias.legacy_id})
WHERE coalesce(legacy.transport, 'stdio') = 'stdio'
  AND coalesce(legacy.id_scheme, $v1_scheme) = $v1_scheme
SET legacy.id_scheme = $v1_scheme,
    legacy.identity_compatibility = alias.state,
    legacy.identity_quarantined = alias.quarantined,
    legacy.identity_alias_candidates = alias.current_ids,
    legacy.identity_alias_target = alias.alias_target
RETURN count(legacy) AS updated`

const persistCurrentMCPIdentityCompatibilityCypher = `
UNWIND $aliases AS alias
MATCH (current:MCPServer)
WHERE current.objectid IN alias.current_ids
  AND current.legacy_objectid = alias.legacy_id
  AND coalesce(current.id_scheme, $v2_scheme) = $v2_scheme
SET current.id_scheme = $v2_scheme,
    current.legacy_alias_state = alias.state,
    current.legacy_identity_quarantined = alias.quarantined
RETURN count(current) AS updated`

var mcpIdentityMigrationRelationshipKinds = sortedAllowedRelationshipKinds()

var migrateLegacyMCPIdentityCypher = buildMigrateLegacyMCPIdentityCypher(
	mcpIdentityMigrationRelationshipKinds,
)

type identityAliasAccumulator struct {
	currentIDs        map[string]bool
	claimedOneToOne   bool
	claimedAmbiguous  bool
	claimedUnresolved bool
	legacyExists      bool
}

// ReconcileMCPStdioIdentities resolves collector-provided v1/v2 compatibility
// claims against every v2 candidate already persisted in the graph. It never
// rewires ambiguous v1 aggregates, which remain quarantined. When complete
// collector coverage proves a single persisted v2 target, it transactionally
// moves the v1 node's properties, observation owners, and allowed relationships
// to that target before deleting the v1 node.
func ReconcileMCPStdioIdentities(
	ctx context.Context,
	db GraphDB,
	aliases []sdkingest.IdentityAlias,
) ([]sdkingest.IdentityAlias, IdentityCompatibilityStats, error) {
	var stats IdentityCompatibilityStats
	if len(aliases) == 0 {
		return []sdkingest.IdentityAlias{}, stats, nil
	}
	if db == nil {
		return nil, stats, fmt.Errorf("graph database unavailable")
	}

	byLegacy := make(map[string]*identityAliasAccumulator, len(aliases))
	for _, alias := range aliases {
		if alias.LegacyID == "" {
			continue
		}
		acc := byLegacy[alias.LegacyID]
		if acc == nil {
			acc = &identityAliasAccumulator{currentIDs: make(map[string]bool)}
			byLegacy[alias.LegacyID] = acc
		}
		for _, currentID := range alias.CurrentIDs {
			if currentID != "" {
				acc.currentIDs[currentID] = true
			}
		}
		switch alias.State {
		case sdkingest.IdentityAliasOneToOne:
			acc.claimedOneToOne = true
		case sdkingest.IdentityAliasAmbiguous:
			acc.claimedAmbiguous = true
		default:
			acc.claimedUnresolved = true
		}
	}
	if len(byLegacy) == 0 {
		return []sdkingest.IdentityAlias{}, stats, nil
	}

	legacyIDs := make([]string, 0, len(byLegacy))
	for legacyID := range byLegacy {
		legacyIDs = append(legacyIDs, legacyID)
	}
	sort.Strings(legacyIDs)

	rows, err := db.Query(ctx, discoverMCPIdentityCandidatesCypher, map[string]any{
		"legacy_ids": legacyIDs,
		"v1_scheme":  sdkingest.MCPStdioIdentitySchemeV1,
		"v2_scheme":  sdkingest.MCPStdioIdentitySchemeV2,
	})
	if err != nil {
		return nil, stats, fmt.Errorf("discover persisted MCP identity candidates: %w", err)
	}
	for _, row := range rows {
		legacyID, _ := row["legacy_id"].(string)
		acc := byLegacy[legacyID]
		if acc == nil {
			continue
		}
		acc.legacyExists, _ = row["legacy_exists"].(bool)
		for _, currentID := range stringValues(row["current_ids"]) {
			if currentID != "" {
				acc.currentIDs[currentID] = true
			}
		}
	}

	resolved := make([]sdkingest.IdentityAlias, 0, len(legacyIDs))
	persisted := make([]map[string]any, 0, len(legacyIDs))
	migratable := make([]map[string]any, 0, len(legacyIDs))
	for _, legacyID := range legacyIDs {
		acc := byLegacy[legacyID]
		currentIDs := make([]string, 0, len(acc.currentIDs))
		for currentID := range acc.currentIDs {
			currentIDs = append(currentIDs, currentID)
		}
		sort.Strings(currentIDs)

		state := sdkingest.IdentityAliasUnresolved
		switch {
		case len(currentIDs) > 1 || acc.claimedAmbiguous:
			state = sdkingest.IdentityAliasAmbiguous
			stats.AmbiguousAliases++
		case len(currentIDs) == 1 &&
			acc.claimedOneToOne &&
			!acc.claimedUnresolved:
			state = sdkingest.IdentityAliasOneToOne
			stats.OneToOneAliases++
		default:
			stats.UnresolvedAliases++
		}
		var aliasTarget any
		if state == sdkingest.IdentityAliasOneToOne {
			aliasTarget = currentIDs[0]
		}
		resolved = append(resolved, sdkingest.IdentityAlias{
			LegacyID:   legacyID,
			CurrentIDs: currentIDs,
			State:      state,
		})
		entry := map[string]any{
			"legacy_id":    legacyID,
			"current_ids":  currentIDs,
			"state":        string(state),
			"quarantined":  state == sdkingest.IdentityAliasAmbiguous,
			"alias_target": aliasTarget,
		}
		persisted = append(persisted, entry)
		if state == sdkingest.IdentityAliasOneToOne && acc.legacyExists {
			migratable = append(migratable, entry)
		}
	}
	stats.AliasesEvaluated = len(resolved)

	params := map[string]any{
		"aliases":   persisted,
		"v1_scheme": sdkingest.MCPStdioIdentitySchemeV1,
		"v2_scheme": sdkingest.MCPStdioIdentitySchemeV2,
	}
	updated, err := db.ExecuteWrite(
		ctx,
		persistLegacyMCPIdentityCompatibilityCypher,
		params,
	)
	if err != nil {
		return resolved, stats, fmt.Errorf("persist legacy MCP identity compatibility: %w", err)
	}
	stats.LegacyNodesUpdated = updated
	updated, err = db.ExecuteWrite(
		ctx,
		persistCurrentMCPIdentityCompatibilityCypher,
		params,
	)
	if err != nil {
		return resolved, stats, fmt.Errorf("persist current MCP identity compatibility: %w", err)
	}
	stats.CurrentNodesUpdated = updated
	if len(migratable) == 0 {
		return resolved, stats, nil
	}

	updated, err = db.ExecuteWrite(
		ctx,
		migrateLegacyMCPIdentityCypher,
		map[string]any{
			"aliases":                    migratable,
			"v1_scheme":                  sdkingest.MCPStdioIdentitySchemeV1,
			"v2_scheme":                  sdkingest.MCPStdioIdentitySchemeV2,
			"one_to_one_state":           string(sdkingest.IdentityAliasOneToOne),
			"allowed_relationship_kinds": append([]string(nil), mcpIdentityMigrationRelationshipKinds...),
		},
	)
	if err != nil {
		return resolved, stats, fmt.Errorf("migrate one-to-one legacy MCP identities: %w", err)
	}
	stats.LegacyNodesMigrated = updated
	if updated != len(migratable) {
		return resolved, stats, fmt.Errorf(
			"migrate one-to-one legacy MCP identities: migrated %d of %d aliases",
			updated,
			len(migratable),
		)
	}
	return resolved, stats, nil
}

func sortedAllowedRelationshipKinds() []string {
	kinds := make([]string, 0, len(sdkingest.AllowedEdgeKinds))
	for kind := range sdkingest.AllowedEdgeKinds {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	return kinds
}

// buildMigrateLegacyMCPIdentityCypher emits one static MERGE clause per
// allowlisted relationship type because Cypher cannot parameterize a
// relationship type. The allowlist is trusted ingest schema, not caller input.
// Every alias and every relationship is migrated by one ExecuteWrite call, so a
// failed DELETE (for example, because an unknown relationship remains) rolls
// the complete migration back.
func buildMigrateLegacyMCPIdentityCypher(relationshipKinds []string) string {
	var query strings.Builder
	query.WriteString(`WITH $aliases AS requested_aliases
UNWIND requested_aliases AS alias
WITH requested_aliases, alias
WHERE alias.state = $one_to_one_state
  AND size(alias.current_ids) = 1
MATCH (legacy:MCPServer {objectid: alias.legacy_id})
WHERE legacy.objectid <> alias.current_ids[0]
  AND coalesce(legacy.transport, 'stdio') = 'stdio'
  AND coalesce(legacy.id_scheme, $v1_scheme) = $v1_scheme
  AND legacy.identity_compatibility = $one_to_one_state
  AND coalesce(legacy.identity_quarantined, false) = false
MATCH (current:MCPServer {objectid: alias.current_ids[0]})
WHERE current.legacy_objectid = alias.legacy_id
  AND coalesce(current.id_scheme, $v2_scheme) = $v2_scheme
  AND current.legacy_alias_state = $one_to_one_state
  AND coalesce(current.legacy_identity_quarantined, false) = false
OPTIONAL MATCH (candidate:MCPServer {legacy_objectid: alias.legacy_id})
WHERE coalesce(candidate.id_scheme, $v2_scheme) = $v2_scheme
WITH requested_aliases, alias, legacy, current,
     count(DISTINCT candidate) AS candidate_count
WHERE candidate_count = 1
OPTIONAL MATCH (legacy)-[connected]-()
WITH requested_aliases, alias, legacy, current,
     collect(DISTINCT type(connected)) AS relationship_kinds
WHERE all(kind IN relationship_kinds
          WHERE kind IN $allowed_relationship_kinds)
WITH requested_aliases,
     collect({alias: alias, legacy: legacy, current: current}) AS migrations
WHERE size(migrations) = size(requested_aliases)
UNWIND migrations AS migration
WITH migration.alias AS alias,
     migration.legacy AS legacy,
     migration.current AS current
WITH alias, legacy, current,
     properties(current) AS current_properties,
     coalesce(current.observation_tokens, []) AS current_tokens,
     coalesce(legacy.observation_tokens, []) AS legacy_tokens,
     coalesce(current.observation_managed, false) AS current_managed,
     coalesce(legacy.observation_managed, false) AS legacy_managed,
     coalesce(current.legacy_observation,
              NOT coalesce(current.observation_managed, false)) AS current_legacy,
     coalesce(current.observation_properties_complete, false) AS current_complete
SET current += legacy {.*,
  objectid: alias.current_ids[0],
  id_scheme: $v2_scheme,
  legacy_objectid: alias.legacy_id
}
SET current += current_properties
SET current.objectid = alias.current_ids[0],
    current.id_scheme = $v2_scheme,
    current.legacy_objectid = alias.legacy_id,
    current.identity_compatibility = $one_to_one_state,
    current.identity_alias_target = alias.current_ids[0],
    current.identity_quarantined = false,
    current.legacy_alias_state = $one_to_one_state,
    current.legacy_identity_quarantined = false,
    current.observation_tokens = reduce(
      tokens = current_tokens, token IN legacy_tokens |
      CASE WHEN token IN tokens THEN tokens ELSE tokens + token END),
    current.observation_managed = current_managed OR legacy_managed,
    current.legacy_observation = current_legacy,
    current.observation_properties_complete = current_complete
WITH alias, legacy, current
`)
	for _, kind := range relationshipKinds {
		appendIdentityRelationshipMigration(&query, kind, "self")
		appendIdentityRelationshipMigration(&query, kind, "outgoing")
		appendIdentityRelationshipMigration(&query, kind, "incoming")
	}
	query.WriteString(`DELETE legacy
RETURN count(*) AS migrated`)
	return query.String()
}

func appendIdentityRelationshipMigration(
	query *strings.Builder,
	kind string,
	direction string,
) {
	query.WriteString("CALL {\n  WITH legacy, current\n")
	switch direction {
	case "self":
		fmt.Fprintf(query, "  MATCH (legacy)-[old:%s]->(legacy)\n", kind)
		fmt.Fprintf(query, "  MERGE (current)-[replacement:%s]->(current)\n", kind)
	case "outgoing":
		fmt.Fprintf(query, "  MATCH (legacy)-[old:%s]->(other)\n", kind)
		query.WriteString("  WHERE other <> legacy\n")
		fmt.Fprintf(query, "  MERGE (current)-[replacement:%s]->(other)\n", kind)
	case "incoming":
		fmt.Fprintf(query, "  MATCH (other)-[old:%s]->(legacy)\n", kind)
		query.WriteString("  WHERE other <> legacy\n")
		fmt.Fprintf(query, "  MERGE (other)-[replacement:%s]->(current)\n", kind)
	default:
		panic("unsupported identity relationship migration direction: " + direction)
	}
	query.WriteString(`  ON CREATE SET replacement.__agenthound_identity_migration_created = true
  WITH old, replacement,
       coalesce(replacement.__agenthound_identity_migration_created, false) AS replacement_created,
       properties(replacement) AS replacement_properties,
       coalesce(replacement.observation_tokens, []) AS replacement_tokens,
       coalesce(old.observation_tokens, []) AS old_tokens,
       coalesce(replacement.observation_managed, false) AS replacement_managed,
       coalesce(old.observation_managed, false) AS old_managed,
       coalesce(replacement.legacy_observation,
                NOT coalesce(replacement.observation_managed, false)) AS replacement_legacy,
       coalesce(old.legacy_observation,
                NOT coalesce(old.observation_managed, false)) AS old_legacy,
       coalesce(replacement.observation_properties_complete, false) AS replacement_complete,
       coalesce(old.observation_properties_complete, false) AS old_complete
  SET replacement += properties(old)
  FOREACH (_ IN CASE WHEN replacement_created THEN [] ELSE [1] END |
    SET replacement += replacement_properties)
  SET replacement.observation_tokens = reduce(
        tokens = replacement_tokens, token IN old_tokens |
        CASE WHEN token IN tokens THEN tokens ELSE tokens + token END),
      replacement.observation_managed = replacement_managed OR old_managed,
      replacement.legacy_observation = CASE
        WHEN replacement_created THEN old_legacy
        ELSE replacement_legacy AND old_legacy
      END,
      replacement.observation_properties_complete = CASE
        WHEN replacement_created THEN old_complete
        ELSE replacement_complete OR old_complete
      END
  REMOVE replacement.__agenthound_identity_migration_created
  DELETE old
  RETURN count(*) AS migrated_relationships
}
WITH alias, legacy, current
`)
}

func stringValues(value any) []string {
	switch values := value.(type) {
	case []string:
		return append([]string(nil), values...)
	case []any:
		out := make([]string, 0, len(values))
		for _, value := range values {
			if text, ok := value.(string); ok {
				out = append(out, text)
			}
		}
		return out
	default:
		return nil
	}
}
