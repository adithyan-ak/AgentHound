package graph

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/neo4j/neo4j-go-driver/v5/neo4j"
)

var indexDefs = []struct{ Label, Property string }{
	{"MCPServer", "name"},
	{"MCPTool", "name"},
	{"MCPTool", "description_hash"},
	{"A2AAgent", "name"},
	{"A2AAgent", "url"},
	{"MCPResource", "uri"},
	{"MCPResource", "sensitivity"},
	{"MCPServer", "is_pinned"},
	{"A2AAgent", "is_signed"},
	{"InstructionFile", "type"},
	// AIService umbrella label gets indexes only (no uniqueness
	// constraint, per ingest.UmbrellaLabels). These power generic
	// post-processors that span all AI service kinds.
	{"AIService", "endpoint"},
	{"AIService", "is_anonymous_loot"},
	{"Credential", "value_hash"},
}

const graphSchemaVersion = 2

const observationFingerprintSchemaStateCypher = `
CALL {
  MATCH (n)
  WHERE any(label IN labels(n) WHERE label IN $public_kinds)
  WITH n, [
    token IN coalesce(n.observation_tokens, [])
    WHERE NOT token IN coalesce(n.observation_reference_tokens, [])
  ] AS ownership_tokens
  WHERE any(token IN ownership_tokens WHERE
    none(fingerprint IN coalesce(n.observation_fact_fingerprints, []) WHERE
      fingerprint STARTS WITH
        split(token, $token_separator)[0] + $fingerprint_separator))
  RETURN count(n) AS unfingerprinted_nodes
}
CALL {
  MATCH ()-[r]->()
  WHERE type(r) IN $raw_edge_kinds
  WITH r, CASE
    WHEN r.observation_semantics = $all_dependencies_semantics
    THEN coalesce(r.observation_dependency_tokens, [])
    ELSE coalesce(r.observation_tokens, [])
  END AS ownership_tokens
  WHERE any(token IN ownership_tokens WHERE
    none(fingerprint IN coalesce(r.observation_fact_fingerprints, []) WHERE
      fingerprint STARTS WITH
        split(token, $token_separator)[0] + $fingerprint_separator))
  RETURN count(r) AS unfingerprinted_relationships
}
OPTIONAL MATCH (schema:SchemaVersion)
RETURN coalesce(max(schema.version), 0) AS version,
       unfingerprinted_nodes,
       unfingerprinted_relationships`

type observationFingerprintSchemaState struct {
	Version                      int64
	UnfingerprintedNodes         int64
	UnfingerprintedRelationships int64
}

func InitSchema(ctx context.Context, driver neo4j.DriverWithContext) error {
	major, minor, err := DetectVersion(ctx, driver)
	if err != nil {
		slog.Warn("failed to detect neo4j version, assuming 4.4", "error", err)
		major, minor = 4, 4
	}
	slog.Info("detected neo4j version", "major", major, "minor", minor)

	fingerprintState, err := readObservationFingerprintSchemaState(ctx, driver)
	if err != nil {
		return fmt.Errorf("inspect observation fingerprint schema: %w", err)
	}
	if fingerprintState.Version > graphSchemaVersion {
		return fmt.Errorf(
			"Neo4j graph schema %d is newer than the maximum schema %d supported by this server; refusing to downgrade the database",
			fingerprintState.Version,
			graphSchemaVersion,
		)
	}
	if fingerprintState.Version < graphSchemaVersion &&
		(fingerprintState.UnfingerprintedNodes > 0 ||
			fingerprintState.UnfingerprintedRelationships > 0) {
		return fmt.Errorf(
			"Neo4j graph schema %d contains %d authoritative nodes and %d raw relationships without per-owner observation fingerprints; automatic upgrade to schema %d cannot preserve shared-owner evidence safely: back up the deployment, recreate the Neo4j and PostgreSQL volumes, and recollect before starting this release",
			fingerprintState.Version,
			fingerprintState.UnfingerprintedNodes,
			fingerprintState.UnfingerprintedRelationships,
			graphSchemaVersion,
		)
	}

	useForRequire := major > 4 || (major == 4 && minor >= 4)

	// Create uniqueness constraints for every per-kind label. Skip umbrella
	// labels (e.g. :AIService) — multiple per-service nodes carry the
	// umbrella, so a uniqueness constraint on it would falsely collide
	// between distinct services. Per-kind uniqueness is the merge key;
	// the umbrella is a query convenience only.
	constraintCount := 0
	for _, label := range ingest.AllNodeLabels {
		if ingest.UmbrellaLabels[label] {
			slog.Debug("skipping umbrella label for constraint", "label", label)
			continue
		}
		cypher := constraintCypher(label, useForRequire)
		if err := runDDL(ctx, driver, cypher); err != nil {
			if isConstraintExistsError(err) {
				slog.Info("constraint already exists", "label", label)
				constraintCount++
				continue
			}
			return fmt.Errorf("create constraint %s: %w", label, err)
		}
		slog.Info("created constraint", "label", label)
		constraintCount++
	}

	// Create indexes
	for _, idx := range indexDefs {
		cypher := indexCypher(idx.Label, idx.Property, useForRequire)
		if err := runDDL(ctx, driver, cypher); err != nil {
			if isConstraintExistsError(err) {
				slog.Info("index already exists", "label", idx.Label, "property", idx.Property)
				continue
			}
			return fmt.Errorf("create index %s.%s: %w", idx.Label, idx.Property, err)
		}
		slog.Info("created index", "label", idx.Label, "property", idx.Property)
	}

	// Schema version 2 introduces per-owner observation fingerprints. Existing
	// schema-1 graphs are advanced only after the compatibility check above.
	if err := runDDL(ctx, driver, fmt.Sprintf(
		"MATCH (schema:SchemaVersion) SET schema.version = %d",
		graphSchemaVersion,
	)); err != nil {
		return fmt.Errorf("update schema version: %w", err)
	}
	if err := runDDL(ctx, driver, fmt.Sprintf(
		"MERGE (:SchemaVersion {version: %d})",
		graphSchemaVersion,
	)); err != nil {
		return fmt.Errorf("schema version: %w", err)
	}

	slog.Info("schema initialization complete", "constraints", constraintCount, "indexes", len(indexDefs))
	return nil
}

func readObservationFingerprintSchemaState(
	ctx context.Context,
	driver neo4j.DriverWithContext,
) (observationFingerprintSchemaState, error) {
	session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		rows, err := tx.Run(ctx, observationFingerprintSchemaStateCypher, map[string]any{
			"public_kinds":          ingest.PublicNodeLabels,
			"raw_edge_kinds":        rawEdgeKinds(),
			"token_separator":       observationTokenSeparator,
			"fingerprint_separator": observationFactFingerprintSeparator,
			"all_dependencies_semantics": string(
				ingest.ObservationSemanticsAllDependencies,
			),
		})
		if err != nil {
			return nil, err
		}
		if !rows.Next(ctx) {
			if err := rows.Err(); err != nil {
				return nil, err
			}
			return nil, fmt.Errorf("schema state query returned no row")
		}
		record := rows.Record()
		readCount := func(key string) (int64, error) {
			value, exists := record.Get(key)
			if !exists {
				return 0, fmt.Errorf("schema state missing %s", key)
			}
			count, ok := value.(int64)
			if !ok {
				return 0, fmt.Errorf("schema state %s has type %T", key, value)
			}
			return count, nil
		}
		version, err := readCount("version")
		if err != nil {
			return nil, err
		}
		nodes, err := readCount("unfingerprinted_nodes")
		if err != nil {
			return nil, err
		}
		relationships, err := readCount("unfingerprinted_relationships")
		if err != nil {
			return nil, err
		}
		return observationFingerprintSchemaState{
			Version:                      version,
			UnfingerprintedNodes:         nodes,
			UnfingerprintedRelationships: relationships,
		}, nil
	})
	if err != nil {
		return observationFingerprintSchemaState{}, err
	}
	state, ok := result.(observationFingerprintSchemaState)
	if !ok {
		return observationFingerprintSchemaState{}, fmt.Errorf(
			"unexpected schema state type %T",
			result,
		)
	}
	return state, nil
}

func constraintCypher(label string, useForRequire bool) string {
	name := fmt.Sprintf("unique_%s_objectid", strings.ToLower(label))
	if useForRequire {
		return fmt.Sprintf("CREATE CONSTRAINT %s IF NOT EXISTS FOR (n:%s) REQUIRE n.objectid IS UNIQUE", name, label)
	}
	return fmt.Sprintf("CREATE CONSTRAINT %s ON (n:%s) ASSERT n.objectid IS UNIQUE", name, label)
}

func indexCypher(label, property string, useForRequire bool) string {
	name := fmt.Sprintf("idx_%s_%s", strings.ToLower(label), property)
	if useForRequire {
		return fmt.Sprintf("CREATE INDEX %s IF NOT EXISTS FOR (n:%s) ON (n.%s)", name, label, property)
	}
	// Neo4j 4.4 index syntax (no IF NOT EXISTS for some older builds)
	return fmt.Sprintf("CREATE INDEX %s IF NOT EXISTS FOR (n:%s) ON (n.%s)", name, label, property)
}

func runDDL(ctx context.Context, driver neo4j.DriverWithContext, cypher string) error {
	session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeWrite})
	defer session.Close(ctx)

	_, err := session.ExecuteWrite(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		_, err := tx.Run(ctx, cypher, nil)
		return nil, err
	})
	return err
}

func isConstraintExistsError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "EquivalentSchemaRuleAlreadyExists") ||
		strings.Contains(msg, "equivalent constraint already exists") ||
		strings.Contains(msg, "An equivalent constraint already exists") ||
		strings.Contains(msg, "already exists")
}
