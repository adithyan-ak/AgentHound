package graph

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

type ReconciliationStats struct {
	RelationshipOwnersRetired int `json:"relationship_owners_retired"`
	RelationshipsDeleted      int `json:"relationships_deleted"`
	NodeOwnersRetired         int `json:"node_owners_retired"`
	NodesDeleted              int `json:"nodes_deleted"`
}

type ObservationCompleteness struct {
	IncompletePropertyNodes         int64 `json:"incomplete_property_nodes"`
	IncompletePropertyRelationships int64 `json:"incomplete_property_relationships"`
	TokenlessNodes                  int64 `json:"tokenless_nodes"`
	TokenlessIncidentRelationships  int64 `json:"tokenless_incident_relationships"`
}

func (c ObservationCompleteness) Complete() bool {
	return c.IncompletePropertyNodes == 0 &&
		c.IncompletePropertyRelationships == 0 &&
		c.TokenlessNodes == 0 &&
		c.TokenlessIncidentRelationships == 0
}

const observationCompletenessCypher = `
CALL {
  MATCH (n)
  WHERE any(label IN labels(n) WHERE label IN $public_kinds)
    AND size(coalesce(n.observation_tokens, [])) > 0
  RETURN count(CASE
           WHEN coalesce(n.observation_properties_complete, false) = false
           THEN 1
         END) AS incomplete_property_nodes
}
CALL {
  MATCH (source)-[r]->(target)
  WHERE type(r) IN $raw_edge_kinds
    AND any(label IN labels(source) WHERE label IN $public_kinds)
    AND any(label IN labels(target) WHERE label IN $public_kinds)
    AND (size(coalesce(r.observation_tokens, [])) > 0
         OR size(coalesce(r.observation_dependency_tokens, [])) > 0)
  RETURN count(CASE
           WHEN coalesce(r.observation_properties_complete, false) = false
           THEN 1
         END) AS incomplete_property_relationships
}
CALL {
  MATCH (n)
  WHERE any(label IN labels(n) WHERE label IN $public_kinds)
    AND size(coalesce(n.observation_tokens, [])) = 0
  RETURN count(n) AS tokenless_nodes
}
CALL {
  MATCH (source)-[r]->(target)
  WHERE type(r) IN $raw_edge_kinds
    AND (
      (any(label IN labels(source) WHERE label IN $public_kinds)
       AND size(coalesce(source.observation_tokens, [])) = 0)
      OR
      (any(label IN labels(target) WHERE label IN $public_kinds)
       AND size(coalesce(target.observation_tokens, [])) = 0)
    )
  RETURN count(r) AS tokenless_incident_relationships
}
RETURN incomplete_property_nodes, incomplete_property_relationships,
       tokenless_nodes, tokenless_incident_relationships`

const deleteMissingDependencyRelationshipsCypher = `
MATCH ()-[r]->()
WHERE type(r) IN $raw_edge_kinds
  AND r.observation_semantics = $all_dependencies_semantics
  AND any(prefix IN $domain_prefixes WHERE
        any(token IN coalesce(r.observation_dependency_tokens, [])
            WHERE token STARTS WITH prefix)
        AND none(token IN coalesce(r.observation_dependency_tokens, [])
                 WHERE token STARTS WITH prefix
                   AND token IN $current_tokens))
DELETE r
RETURN count(r) AS deleted`

const retireDependencyOwnersCypher = `
MATCH ()-[r]->()
WHERE type(r) IN $raw_edge_kinds
  AND r.observation_semantics = $all_dependencies_semantics
  AND any(token IN coalesce(r.observation_dependency_tokens, [])
          WHERE any(prefix IN $domain_prefixes WHERE token STARTS WITH prefix))
WITH r, [
  token IN coalesce(r.observation_dependency_tokens, [])
  WHERE none(prefix IN $domain_prefixes WHERE token STARTS WITH prefix)
     OR token IN $current_tokens
] AS remaining_tokens
WITH r, remaining_tokens,
     [token IN remaining_tokens | split(token, $token_separator)[0]] AS remaining_domains
SET r.observation_dependency_tokens = remaining_tokens,
    r.observation_fact_fingerprints = [
      fingerprint IN coalesce(r.observation_fact_fingerprints, [])
      WHERE split(fingerprint, $fingerprint_separator)[0] IN remaining_domains
    ]
RETURN count(r) AS retired`

// Owner retirement normally makes a retained property union incomplete: the
// removed owner may have contributed unique fields. The one safe exception is
// an exact ownership transfer, proven when every removed owner fingerprint has
// the same semantic digest under a surviving owner. Missing fingerprints and
// non-identical contributions deliberately remain fail-closed. Node retirement
// below applies the same proof to authoritative (non-reference) owners.
const retireRelationshipOwnersCypher = `
MATCH ()-[r]->()
WHERE type(r) IN $raw_edge_kinds
  AND coalesce(r.observation_semantics, '') <> $all_dependencies_semantics
  AND any(token IN coalesce(r.observation_tokens, [])
          WHERE any(prefix IN $domain_prefixes WHERE token STARTS WITH prefix))
WITH r, coalesce(r.observation_tokens, []) AS old_tokens,
     coalesce(r.observation_fact_fingerprints, []) AS old_fact_fingerprints,
     coalesce(r.observation_properties_complete, false) AS old_properties_complete,
     [token IN coalesce(r.observation_tokens, [])
      WHERE none(prefix IN $domain_prefixes WHERE token STARTS WITH prefix)
         OR token IN $current_tokens] AS remaining_tokens
WITH r, old_tokens, old_fact_fingerprints, old_properties_complete, remaining_tokens,
     [token IN old_tokens | split(token, $token_separator)[0]] AS old_domains,
     [token IN remaining_tokens | split(token, $token_separator)[0]] AS remaining_domains
WITH r, old_tokens, old_fact_fingerprints, old_properties_complete, remaining_tokens,
     remaining_domains,
     [domain IN old_domains WHERE NOT domain IN remaining_domains] AS removed_domains,
     [fingerprint IN old_fact_fingerprints
      WHERE split(fingerprint, $fingerprint_separator)[0] IN remaining_domains
     ] AS remaining_fact_fingerprints
WITH r, old_properties_complete, remaining_tokens, removed_domains,
     remaining_fact_fingerprints,
     size(removed_domains) > 0
       AND all(domain IN removed_domains WHERE
         any(fingerprint IN old_fact_fingerprints WHERE
           split(fingerprint, $fingerprint_separator)[0] = domain))
       AND all(fingerprint IN [
         candidate IN old_fact_fingerprints
         WHERE split(candidate, $fingerprint_separator)[0] IN removed_domains
       ] WHERE
         any(remaining IN remaining_fact_fingerprints WHERE
           split(remaining, $fingerprint_separator)[1] =
             split(fingerprint, $fingerprint_separator)[1]))
       AS removed_facts_redundant
SET r.observation_tokens = remaining_tokens,
    r.observation_fact_fingerprints = remaining_fact_fingerprints,
    r.observation_properties_complete = CASE
      WHEN size(remaining_tokens) > 0
       AND size(removed_domains) > 0
       AND NOT removed_facts_redundant
      THEN false
      ELSE old_properties_complete
    END
RETURN count(r) AS retired`

const deleteUnownedRelationshipsCypher = `
MATCH ()-[r]->()
WHERE type(r) IN $raw_edge_kinds
  AND coalesce(r.observation_semantics, '') <> $all_dependencies_semantics
  AND size(coalesce(r.observation_tokens, [])) = 0
DELETE r
RETURN count(r) AS deleted`

const retireNodeOwnersCypher = `
MATCH (n)
WHERE any(label IN labels(n) WHERE label IN $public_kinds)
  AND any(token IN coalesce(n.observation_tokens, [])
          WHERE any(prefix IN $domain_prefixes WHERE token STARTS WITH prefix))
WITH n,
     coalesce(n.observation_tokens, []) AS old_tokens,
     coalesce(n.observation_reference_tokens, []) AS old_reference_tokens,
     n.objectid AS objectid,
     n.scan_id AS scan_id,
     n.first_seen AS first_seen,
     n.last_seen AS last_seen,
     coalesce(n.observation_fact_fingerprints, []) AS old_fact_fingerprints,
     coalesce(n.observation_properties_complete, false) AS old_properties_complete
WITH n, old_tokens, old_reference_tokens,
     objectid, scan_id, first_seen, last_seen,
     old_fact_fingerprints, old_properties_complete,
     [token IN old_tokens
      WHERE none(prefix IN $domain_prefixes WHERE token STARTS WITH prefix)
         OR token IN $current_tokens] AS remaining_tokens,
     [token IN old_reference_tokens
      WHERE none(prefix IN $domain_prefixes WHERE token STARTS WITH prefix)
         OR token IN $current_tokens] AS remaining_reference_tokens
WITH n, remaining_tokens, remaining_reference_tokens,
     objectid, scan_id, first_seen, last_seen,
     old_fact_fingerprints, old_properties_complete,
     [token IN old_tokens
      WHERE NOT token IN old_reference_tokens] AS old_authoritative_tokens,
     [token IN remaining_tokens
      WHERE NOT token IN remaining_reference_tokens] AS remaining_authoritative_tokens
WITH n, remaining_tokens, remaining_reference_tokens,
     objectid, scan_id, first_seen, last_seen,
     old_fact_fingerprints, old_properties_complete,
     old_authoritative_tokens, remaining_authoritative_tokens,
     [token IN old_authoritative_tokens |
       split(token, $token_separator)[0]] AS old_authoritative_domains,
     [token IN remaining_authoritative_tokens |
       split(token, $token_separator)[0]] AS remaining_authoritative_domains
WITH n, remaining_tokens, remaining_reference_tokens,
     objectid, scan_id, first_seen, last_seen,
     old_fact_fingerprints, old_properties_complete,
     old_authoritative_tokens, remaining_authoritative_tokens,
     [domain IN old_authoritative_domains
      WHERE NOT domain IN remaining_authoritative_domains
     ] AS removed_authoritative_domains,
     [fingerprint IN old_fact_fingerprints
      WHERE split(fingerprint, $fingerprint_separator)[0]
        IN remaining_authoritative_domains
     ] AS remaining_fact_fingerprints
WITH n, remaining_tokens, remaining_reference_tokens,
     objectid, scan_id, first_seen, last_seen, old_properties_complete,
     old_authoritative_tokens, remaining_authoritative_tokens,
     removed_authoritative_domains, remaining_fact_fingerprints,
     size(removed_authoritative_domains) > 0
       AND all(domain IN removed_authoritative_domains WHERE
         any(fingerprint IN old_fact_fingerprints WHERE
           split(fingerprint, $fingerprint_separator)[0] = domain))
       AND all(fingerprint IN [
         candidate IN old_fact_fingerprints
         WHERE split(candidate, $fingerprint_separator)[0]
           IN removed_authoritative_domains
       ] WHERE
         any(remaining IN remaining_fact_fingerprints WHERE
           split(remaining, $fingerprint_separator)[1] =
             split(fingerprint, $fingerprint_separator)[1]))
       AS removed_facts_redundant
SET n.observation_tokens = remaining_tokens,
    n.observation_reference_tokens = remaining_reference_tokens,
    n.observation_fact_fingerprints = remaining_fact_fingerprints,
    n.observation_properties_complete = CASE
      WHEN size(remaining_authoritative_tokens) > 0
       AND size(removed_authoritative_domains) > 0
       AND NOT removed_facts_redundant
      THEN false
      ELSE old_properties_complete
    END
FOREACH (_ IN CASE
  WHEN size(old_authoritative_tokens) > 0
   AND size(remaining_authoritative_tokens) = 0
   AND size(remaining_tokens) > 0
  THEN [1] ELSE [] END |
  SET n = {
    objectid: objectid,
    scan_id: scan_id,
    first_seen: first_seen,
    last_seen: last_seen,
    observation_tokens: remaining_tokens,
    observation_reference_tokens: remaining_reference_tokens,
    observation_properties_complete: true
  })
RETURN count(n) AS retired`

const deleteUnownedNodesCypher = `
MATCH (n)
WHERE any(label IN labels(n) WHERE label IN $public_kinds)
  AND size(coalesce(n.observation_tokens, [])) = 0
  AND NOT EXISTS { MATCH (n)--() }
DELETE n
RETURN count(n) AS deleted`

// ReconcileObservations retires only the explicitly complete domains supplied
// by the caller. Unknown, partial, and failed observations are never retired.
// Shared facts survive while any active owner token remains.
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
		"domain_prefixes":       prefixes,
		"current_tokens":        currentTokens,
		"public_kinds":          ingest.PublicNodeLabels,
		"raw_edge_kinds":        rawEdgeKinds(),
		"token_separator":       observationTokenSeparator,
		"fingerprint_separator": observationFactFingerprintSeparator,
		"all_dependencies_semantics": string(
			ingest.ObservationSemanticsAllDependencies,
		),
	}

	var err error
	stats.RelationshipsDeleted, err = db.ExecuteWrite(
		ctx,
		deleteMissingDependencyRelationshipsCypher,
		params,
	)
	if err != nil {
		return stats, fmt.Errorf("delete stale dependency relationships: %w", err)
	}
	stats.RelationshipOwnersRetired, err = db.ExecuteWrite(
		ctx,
		retireDependencyOwnersCypher,
		params,
	)
	if err != nil {
		return stats, fmt.Errorf("retire dependency relationship observations: %w", err)
	}
	ordinaryOwnersRetired, err := db.ExecuteWrite(ctx, retireRelationshipOwnersCypher, params)
	if err != nil {
		return stats, fmt.Errorf("retire relationship observation owners: %w", err)
	}
	stats.RelationshipOwnersRetired += ordinaryOwnersRetired
	unownedDeleted, err := db.ExecuteWrite(ctx, deleteUnownedRelationshipsCypher, params)
	if err != nil {
		return stats, fmt.Errorf("delete unowned relationships: %w", err)
	}
	stats.RelationshipsDeleted += unownedDeleted
	stats.NodeOwnersRetired, err = db.ExecuteWrite(ctx, retireNodeOwnersCypher, params)
	if err != nil {
		return stats, fmt.Errorf("retire node observation owners: %w", err)
	}
	stats.NodesDeleted, err = db.ExecuteWrite(ctx, deleteUnownedNodesCypher, params)
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
	deleted, err := db.ExecuteWrite(ctx, deleteUnownedNodesCypher, map[string]any{
		"public_kinds": ingest.PublicNodeLabels,
	})
	if err != nil {
		return deleted, fmt.Errorf("prune post-analysis unowned nodes: %w", err)
	}
	return deleted, nil
}

// GetObservationCompleteness checks property completeness only for public,
// managed raw facts. Internal graph nodes and derived relationships cannot
// block publication.
func GetObservationCompleteness(
	ctx context.Context,
	db GraphDB,
) (ObservationCompleteness, error) {
	var completeness ObservationCompleteness
	if db == nil {
		return completeness, fmt.Errorf("graph database unavailable")
	}
	rows, err := db.Query(ctx, observationCompletenessCypher, map[string]any{
		"public_kinds":   ingest.PublicNodeLabels,
		"raw_edge_kinds": rawEdgeKinds(),
	})
	if err != nil {
		return completeness, fmt.Errorf("query observation completeness: %w", err)
	}
	if len(rows) == 0 {
		return completeness, fmt.Errorf("query observation completeness returned no row")
	}
	completeness.IncompletePropertyNodes = int64Value(rows[0]["incomplete_property_nodes"])
	completeness.IncompletePropertyRelationships = int64Value(
		rows[0]["incomplete_property_relationships"],
	)
	completeness.TokenlessNodes = int64Value(rows[0]["tokenless_nodes"])
	completeness.TokenlessIncidentRelationships = int64Value(
		rows[0]["tokenless_incident_relationships"],
	)
	return completeness, nil
}

func rawEdgeKinds() []string {
	kinds := make([]string, 0, len(ingest.RawEdgeKinds))
	for kind := range ingest.RawEdgeKinds {
		kinds = append(kinds, kind)
	}
	sort.Strings(kinds)
	return kinds
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
