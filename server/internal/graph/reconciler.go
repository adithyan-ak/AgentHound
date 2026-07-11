package graph

import (
	"context"
	"fmt"
	"sort"
	"strings"
)

type ReconciliationStats struct {
	RelationshipOwnersRetired int `json:"relationship_owners_retired"`
	RelationshipsDeleted      int `json:"relationships_deleted"`
	NodeOwnersRetired         int `json:"node_owners_retired"`
	NodesDeleted              int `json:"nodes_deleted"`
}

type ObservationCompleteness struct {
	LegacyNodes                     int64 `json:"legacy_nodes"`
	LegacyRelationships             int64 `json:"legacy_relationships"`
	UnscopedNodes                   int64 `json:"unscoped_nodes"`
	UnscopedRelationships           int64 `json:"unscoped_relationships"`
	IncompletePropertyNodes         int64 `json:"incomplete_property_nodes"`
	IncompletePropertyRelationships int64 `json:"incomplete_property_relationships"`
	IdentityQuarantinedNodes        int64 `json:"identity_quarantined_nodes"`
}

func (c ObservationCompleteness) Complete() bool {
	return c.LegacyNodes == 0 &&
		c.LegacyRelationships == 0 &&
		c.UnscopedNodes == 0 &&
		c.UnscopedRelationships == 0 &&
		c.IncompletePropertyNodes == 0 &&
		c.IncompletePropertyRelationships == 0 &&
		c.IdentityQuarantinedNodes == 0
}

const observationCompletenessCypher = `
CALL {
  MATCH (n)
  RETURN count(CASE
           WHEN coalesce(n.observation_managed, false) = false
             OR coalesce(n.legacy_observation, false) = true
           THEN 1
         END) AS legacy_nodes,
         count(CASE
           WHEN any(token IN coalesce(n.observation_tokens, [])
                    WHERE any(prefix IN $unscoped_prefixes
                              WHERE token STARTS WITH prefix))
           THEN 1
         END) AS unscoped_nodes,
         count(CASE
           WHEN coalesce(n.observation_properties_complete, false) = false
           THEN 1
         END) AS incomplete_property_nodes,
         count(CASE
           WHEN coalesce(n.identity_quarantined, false) = true
             OR coalesce(n.legacy_identity_quarantined, false) = true
           THEN 1
         END) AS identity_quarantined_nodes
}
CALL {
  MATCH ()-[r]->()
  WHERE coalesce(r.is_composite, false) = false
  RETURN count(CASE
           WHEN coalesce(r.observation_managed, false) = false
             OR coalesce(r.legacy_observation, false) = true
           THEN 1
         END) AS legacy_relationships,
         count(CASE
           WHEN any(token IN coalesce(r.observation_tokens, [])
                    WHERE any(prefix IN $unscoped_prefixes
                              WHERE token STARTS WITH prefix))
           THEN 1
         END) AS unscoped_relationships,
         count(CASE
           WHEN coalesce(r.observation_properties_complete, false) = false
           THEN 1
         END) AS incomplete_property_relationships
}
RETURN legacy_nodes, legacy_relationships,
       unscoped_nodes, unscoped_relationships,
       incomplete_property_nodes, incomplete_property_relationships,
       identity_quarantined_nodes`

const retireRelationshipOwnersCypher = `
MATCH ()-[r]->()
WHERE r.observation_managed = true
  AND any(token IN coalesce(r.observation_tokens, [])
          WHERE any(prefix IN $domain_prefixes WHERE token STARTS WITH prefix))
SET r.observation_tokens = [
  token IN coalesce(r.observation_tokens, [])
  WHERE none(prefix IN $domain_prefixes WHERE token STARTS WITH prefix)
     OR token IN $current_tokens
]
RETURN count(r) AS retired`

const deleteUnownedRelationshipsCypher = `
MATCH ()-[r]->()
WHERE r.observation_managed = true
  AND size(coalesce(r.observation_tokens, [])) = 0
  AND coalesce(r.legacy_observation, false) = false
DELETE r
RETURN count(r) AS deleted`

const retireNodeOwnersCypher = `
MATCH (n)
WHERE n.observation_managed = true
  AND any(token IN coalesce(n.observation_tokens, [])
          WHERE any(prefix IN $domain_prefixes WHERE token STARTS WITH prefix))
SET n.observation_tokens = [
  token IN coalesce(n.observation_tokens, [])
  WHERE none(prefix IN $domain_prefixes WHERE token STARTS WITH prefix)
     OR token IN $current_tokens
]
RETURN count(n) AS retired`

const deleteUnownedNodesCypher = `
MATCH (n)
WHERE n.observation_managed = true
  AND size(coalesce(n.observation_tokens, [])) = 0
  AND coalesce(n.legacy_observation, false) = false
  AND NOT EXISTS { MATCH (n)--() }
DELETE n
RETURN count(n) AS deleted`

// ReconcileObservations promotes only the explicitly complete domains supplied
// by the caller. Unknown, partial, failed, and legacy observations are never
// retired. Shared facts survive while any active owner token remains.
func ReconcileObservations(
	ctx context.Context,
	db GraphDB,
	scanID string,
	domains []string,
) (ReconciliationStats, error) {
	var stats ReconciliationStats
	domains = normalizedDomains(domains)
	if db == nil || scanID == "" || len(domains) == 0 {
		return stats, nil
	}

	prefixes := make([]string, 0, len(domains))
	currentTokens := make([]string, 0, len(domains))
	for _, domain := range domains {
		prefixes = append(prefixes, observationDomainPrefix(domain))
		currentTokens = append(currentTokens, observationToken(domain, scanID))
	}
	params := map[string]any{
		"domain_prefixes": prefixes,
		"current_tokens":  currentTokens,
	}

	var err error
	stats.RelationshipOwnersRetired, err = db.ExecuteWrite(ctx, retireRelationshipOwnersCypher, params)
	if err != nil {
		return stats, fmt.Errorf("retire relationship observation owners: %w", err)
	}
	stats.RelationshipsDeleted, err = db.ExecuteWrite(ctx, deleteUnownedRelationshipsCypher, nil)
	if err != nil {
		return stats, fmt.Errorf("delete unowned relationships: %w", err)
	}
	stats.NodeOwnersRetired, err = db.ExecuteWrite(ctx, retireNodeOwnersCypher, params)
	if err != nil {
		return stats, fmt.Errorf("retire node observation owners: %w", err)
	}
	stats.NodesDeleted, err = db.ExecuteWrite(ctx, deleteUnownedNodesCypher, nil)
	if err != nil {
		return stats, fmt.Errorf("delete unowned nodes: %w", err)
	}
	return stats, nil
}

// PruneUnownedObservationNodes is run again after successful composite
// cleanup. A stale composite edge may have kept an otherwise-unowned raw node
// connected during the first reconciliation pass.
func PruneUnownedObservationNodes(ctx context.Context, db GraphDB) (int, error) {
	if db == nil {
		return 0, nil
	}
	deleted, err := db.ExecuteWrite(ctx, deleteUnownedNodesCypher, nil)
	if err != nil {
		return deleted, fmt.Errorf("prune post-analysis unowned nodes: %w", err)
	}
	return deleted, nil
}

// GetObservationCompleteness makes pre-lifecycle/unknown graph facts explicit.
// Such facts remain non-destructive, but no publication may claim a complete
// global projection until they are re-observed into managed ownership or
// migrated.
func GetObservationCompleteness(
	ctx context.Context,
	db GraphDB,
) (ObservationCompleteness, error) {
	var completeness ObservationCompleteness
	if db == nil {
		return completeness, fmt.Errorf("graph database unavailable")
	}
	rows, err := db.Query(ctx, observationCompletenessCypher, map[string]any{
		"unscoped_prefixes": []string{
			observationDomainPrefix("mcp"),
			observationDomainPrefix("a2a"),
			observationDomainPrefix("config"),
		},
	})
	if err != nil {
		return completeness, fmt.Errorf("query observation completeness: %w", err)
	}
	if len(rows) == 0 {
		return completeness, fmt.Errorf("query observation completeness returned no row")
	}
	completeness.LegacyNodes = int64Value(rows[0]["legacy_nodes"])
	completeness.LegacyRelationships = int64Value(rows[0]["legacy_relationships"])
	completeness.UnscopedNodes = int64Value(rows[0]["unscoped_nodes"])
	completeness.UnscopedRelationships = int64Value(rows[0]["unscoped_relationships"])
	completeness.IncompletePropertyNodes = int64Value(rows[0]["incomplete_property_nodes"])
	completeness.IncompletePropertyRelationships = int64Value(
		rows[0]["incomplete_property_relationships"],
	)
	completeness.IdentityQuarantinedNodes = int64Value(
		rows[0]["identity_quarantined_nodes"],
	)
	return completeness, nil
}

func int64Value(value any) int64 {
	switch typed := value.(type) {
	case int64:
		return typed
	case int:
		return int64(typed)
	case int32:
		return int64(typed)
	case float64:
		return int64(typed)
	default:
		return 0
	}
}

func normalizedDomains(domains []string) []string {
	seen := make(map[string]bool, len(domains))
	out := make([]string, 0, len(domains))
	for _, domain := range domains {
		domain = strings.TrimSpace(domain)
		if domain == "" || strings.Contains(domain, observationTokenSeparator) || seen[domain] {
			continue
		}
		seen[domain] = true
		out = append(out, domain)
	}
	sort.Strings(out)
	return out
}
