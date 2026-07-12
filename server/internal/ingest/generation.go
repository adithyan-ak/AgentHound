package ingest

import (
	"context"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/google/uuid"
)

// generation.go holds the generation-scoped substrate helpers used by the
// ingest pipeline: assigning a per-ingest generation id, tagging the graph
// facts an ingest touched with that id, computing accurate inventory deltas,
// and coverage-aware retention of prior-generation facts.
//
// Every helper here goes through the graph.GraphDB Query/ExecuteWrite seam so
// the whole flow is unit-testable with graph.MockGraphDB and never has to
// change the Writer/GraphDB signatures the analysis phase depends on.

// newGenerationID returns a fresh generation identifier for one ingest run.
func newGenerationID() string { return uuid.NewString() }

// Scope keys for the merged `agenthound scan` bundle. Both a local bundle and
// a network sweep carry collector "scan"; without discrimination they would
// share one current-generation pointer and retention domain, so a network
// sweep of remote hosts could demote/retire a local-host bundle (and vice
// versa). We split them into independent scopes.
const (
	scopeScanLocal   = "scan:local"
	scopeScanNetwork = "scan:network"
	// scopeLootPrefix namespaces looter artifacts. A `loot` run ships as a
	// Collector "scan" envelope (see collector/cli/loot.go) watermarked with
	// Extra["loot_type"]; without discrimination it would collapse into the
	// scan:local scope and demote/retire a local config+mcp+a2a bundle (and
	// vice versa). Each loot type gets its own scope so an ollama loot never
	// demotes a litellm loot, while the scope stays COMPATIBLE with the
	// cross-service credential chain: the chain selects current generations by
	// membership, not by scope equality, so a loot generation and a config
	// generation still join by value_hash.
	scopeLootPrefix = "loot:"
)

// collectorScope is the comparable-scope key that a current-generation pointer
// is tracked under. Generations of the same scope share one current pointer; a
// re-ingest of that scope promotes over the prior one, while a different scope
// is independent.
//
// A single-collector artifact (mcp/a2a/config) scopes to its collector. The
// merged "scan" bundle is split by locality: a network sweep (identified by the
// network_scan_spec watermark on Meta.Extra) scopes to scan:network, and a
// local bundle to scan:local, so the two never demote or retire each other.
func collectorScope(meta sdkingest.IngestMeta) string {
	if meta.Collector == "scan" {
		// A loot artifact is a "scan" envelope watermarked with loot_type.
		// Resolve it FIRST so it never falls through to a scan:* bundle scope.
		if lt := lootType(meta); lt != "" {
			return scopeLootPrefix + lt
		}
		if isNetworkScanArtifact(meta) {
			return scopeScanNetwork
		}
		return scopeScanLocal
	}
	return meta.Collector
}

// lootType returns the looter target ("litellm", "ollama", ...) recorded on a
// loot artifact's Meta.Extra, or "" when the artifact is not a loot run.
func lootType(meta sdkingest.IngestMeta) string {
	if meta.Extra == nil {
		return ""
	}
	if v, ok := meta.Extra["loot_type"]; ok {
		if s, ok := v.(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// isNetworkScanArtifact reports whether a merged "scan" artifact came from
// network mode. The network-scan envelope stamps Meta.Extra["network_scan_spec"]
// (see collector/cli/scan.go buildNetworkScanEnvelope); a local bundle never
// sets it.
func isNetworkScanArtifact(meta sdkingest.IngestMeta) bool {
	if meta.Extra == nil {
		return false
	}
	_, ok := meta.Extra["network_scan_spec"]
	return ok
}

// appendUnique appends s to gens when not already present.
func appendUnique(gens []string, s string) []string {
	if s == "" {
		return gens
	}
	for _, g := range gens {
		if g == s {
			return gens
		}
	}
	return append(gens, s)
}

// coverageStatusFor derives the roll-up collection status for an artifact.
// A nil manifest is StatusUnknown (never clean): absence is only evidence when
// the producer positively reports completion.
func coverageStatusFor(meta sdkingest.IngestMeta) sdkingest.CollectionStatus {
	if meta.Coverage == nil {
		return sdkingest.StatusUnknown
	}
	if meta.Coverage.Status.Valid() {
		return meta.Coverage.Status
	}
	return sdkingest.StatusUnknown
}

// queryCount runs a count query returning a single integer column and returns
// it as an int. A nil/empty result (e.g. the default MockGraphDB) yields 0.
func queryCount(ctx context.Context, db graph.GraphDB, cypher string, params map[string]any) (int, error) {
	rows, err := db.Query(ctx, cypher, params)
	if err != nil {
		return 0, err
	}
	for _, row := range rows {
		for _, v := range row {
			return toInt(v), nil
		}
	}
	return 0, nil
}

// toInt coerces the numeric shapes Neo4j / drivers return (int64, int, float64)
// into an int. Unknown shapes yield 0.
func toInt(v any) int {
	switch n := v.(type) {
	case int64:
		return int(n)
	case int:
		return n
	case float64:
		return int(n)
	case int32:
		return int(n)
	default:
		return 0
	}
}

const (
	// Internal :SchemaVersion migration markers are excluded so they never
	// inflate the user-facing inventory totals. These count the whole graph.
	cypherCountNodes = `MATCH (n) WHERE NOT n:SchemaVersion RETURN count(n) AS c`
	cypherCountEdges = `MATCH ()-[r]->() RETURN count(r) AS c`

	// Per-generation inventory counts. Because retention is non-destructive
	// (see below), the whole-graph counts include demoted generations; the
	// before/after totals for THIS scope's current view are the facts a
	// specific generation observed. BeforeTotal counts the prior generation,
	// AfterTotal the new one, so BeforeTotal + Created - Retired == AfterTotal
	// holds for the promoted view.
	cypherCountNodesInGen = `MATCH (n) WHERE NOT n:SchemaVersion AND $gen IN coalesce(n.generations, []) RETURN count(DISTINCT n.objectid) AS c`
	// Edge inventory is counted as DISTINCT logical (source objectid, kind,
	// target objectid) triples within a generation, not physical relationships
	// (F6). A relationship duplicated across the physical observations of a
	// merged logical node, or re-observed by multiple generations, counts once.
	cypherCountEdgeTriplesInGen = `MATCH (a)-[r]->(b) WHERE $gen IN coalesce(r.generations, []) RETURN count(DISTINCT [a.objectid, type(r), b.objectid]) AS c`
	// cypherKeptEdgeTriples counts distinct logical triples present in BOTH the
	// new generation and the prior current generation — the "re-observed"
	// (updated) edge set. Created = after-total - kept; retired = before-total -
	// kept. Comparing against the prior CURRENT generation (not "exists
	// anywhere") is what makes the delta a truthful current-view diff.
	cypherKeptEdgeTriples = `MATCH (a)-[r]->(b) WHERE $gen IN coalesce(r.generations, [])
WITH DISTINCT a.objectid AS s, type(r) AS k, b.objectid AS t
MATCH (a2)-[r2]->(b2)
WHERE a2.objectid = s AND type(r2) = k AND b2.objectid = t AND $prior IN coalesce(r2.generations, [])
RETURN count(DISTINCT [s, k, t]) AS c`

	cypherExistingNodes = `UNWIND $ids AS id MATCH (n {objectid: id}) RETURN count(DISTINCT id) AS c`

	// Generation tagging: every node/edge this ingest MERGE'd carries
	// scan_id = the current scan (ON CREATE and ON MATCH both set it). Tagging
	// is ADDITIVE — it unions $gen into the fact's generations set rather than
	// overwriting a scalar. A fact observed by both a prior generation and this
	// one therefore ends up attributed to BOTH (generations = [prior, new]),
	// which is what lets a later delete of one generation restore the other.
	// The scalar generation_id is kept as the latest-writer marker for
	// debugging; scoping and retention key on the generations set.
	cypherTagNodes = `MATCH (n) WHERE n.scan_id = $scan_id
SET n.generation_id = $gen,
    n.generations = CASE WHEN $gen IN coalesce(n.generations, []) THEN n.generations ELSE coalesce(n.generations, []) + $gen END
RETURN count(n) AS c`
	cypherTagEdges = `MATCH ()-[r]->() WHERE r.scan_id = $scan_id
SET r.generation_id = $gen,
    r.generations = CASE WHEN $gen IN coalesce(r.generations, []) THEN r.generations ELSE coalesce(r.generations, []) + $gen END
RETURN count(r) AS c`

	// Retention is NON-DESTRUCTIVE. A prior-generation fact the new complete
	// generation did not re-observe is not deleted — it simply loses currency
	// when the prior generation is demoted (default reads scope to the promoted
	// generations' sets, so an absent fact drops out of the current view
	// without being destroyed). Keeping it means a subsequent delete of the new
	// generation can rematerialize the prior one with its facts intact. These
	// queries only COUNT the retired facts (prior gen observed, new gen did
	// not) so the inventory delta stays truthful.
	cypherRetiredEdgeCount = `MATCH ()-[r]->() WHERE $prior IN coalesce(r.generations, []) AND NOT $gen IN coalesce(r.generations, [])
RETURN count(r) AS c`
	cypherRetiredNodeCount = `MATCH (n) WHERE $prior IN coalesce(n.generations, []) AND NOT $gen IN coalesce(n.generations, [])
RETURN count(n) AS c`
)

// distinctNodeIDs returns the unique objectids in a node slice.
func distinctNodeIDs(nodes []sdkingest.Node) []string {
	seen := make(map[string]struct{}, len(nodes))
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		if n.ID == "" {
			continue
		}
		if _, ok := seen[n.ID]; ok {
			continue
		}
		seen[n.ID] = struct{}{}
		out = append(out, n.ID)
	}
	return out
}

// countExistingNodes returns how many of the incoming distinct objectids
// already exist in the graph (before this ingest writes).
func countExistingNodes(ctx context.Context, db graph.GraphDB, nodes []sdkingest.Node) (int, error) {
	ids := distinctNodeIDs(nodes)
	if len(ids) == 0 {
		return 0, nil
	}
	return queryCount(ctx, db, cypherExistingNodes, map[string]any{"ids": ids})
}

// tagGeneration stamps generation_id onto every node and edge this scan
// touched. Errors are returned so the caller can mark the write stage
// degraded, but tagging failure is not fatal to already-committed writes.
func tagGeneration(ctx context.Context, db graph.GraphDB, scanID, generationID string) error {
	if _, err := db.ExecuteWrite(ctx, cypherTagNodes, map[string]any{"scan_id": scanID, "gen": generationID}); err != nil {
		return err
	}
	if _, err := db.ExecuteWrite(ctx, cypherTagEdges, map[string]any{"scan_id": scanID, "gen": generationID}); err != nil {
		return err
	}
	return nil
}

// countRetiredGeneration counts the facts of a prior generation that the new
// (complete) generation did not re-observe, returning the retired node/edge
// counts WITHOUT deleting anything. Retention is non-destructive: an absent
// fact loses currency via demotion (default reads scope to the promoted
// generations' sets) but survives in the graph so a delete of the new
// generation can rematerialize the prior one. MUST only be invoked when the
// new generation's coverage is complete for the domains it owns.
func countRetiredGeneration(ctx context.Context, db graph.GraphDB, priorGenerationID, newGenerationID string) (nodesRetired, edgesRetired int, err error) {
	if priorGenerationID == "" {
		return 0, 0, nil
	}
	params := map[string]any{"prior": priorGenerationID, "gen": newGenerationID}
	edgesRetired, err = queryCount(ctx, db, cypherRetiredEdgeCount, params)
	if err != nil {
		return 0, 0, err
	}
	nodesRetired, err = queryCount(ctx, db, cypherRetiredNodeCount, params)
	if err != nil {
		return 0, edgesRetired, err
	}
	return nodesRetired, edgesRetired, nil
}
