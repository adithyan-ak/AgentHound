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
	{"Credential", "value_hash"},
}

const graphSchemaVersion = 3

const graphSchemaVersionCypher = `
OPTIONAL MATCH (schema:SchemaVersion)
RETURN count(schema) AS marker_count,
       count(schema.version) AS version_count,
       coalesce(min(schema.version), 0) AS min_version,
       coalesce(max(schema.version), 0) AS max_version`

type graphSchemaState struct {
	MarkerCount  int64
	VersionCount int64
	MinVersion   int64
	MaxVersion   int64
}

func InitSchema(ctx context.Context, driver neo4j.DriverWithContext) error {
	major, minor, err := DetectVersion(ctx, driver)
	if err != nil {
		slog.Warn("failed to detect neo4j version, assuming 4.4", "error", err)
		major, minor = 4, 4
	}
	slog.Info("detected neo4j version", "major", major, "minor", minor)

	schemaState, err := readGraphSchemaState(ctx, driver)
	if err != nil {
		return fmt.Errorf("inspect graph schema version: %w", err)
	}
	if schemaState.MarkerCount > 1 ||
		schemaState.VersionCount != schemaState.MarkerCount ||
		schemaState.MinVersion != schemaState.MaxVersion {
		return fmt.Errorf(
			"Neo4j graph schema marker is malformed; this server requires exactly one V3 marker",
		)
	}
	if schemaState.MarkerCount == 1 && schemaState.MinVersion == 1 {
		if err := migrateGraphV1ToV2(ctx, driver); err != nil {
			return fmt.Errorf("migrate Neo4j graph schema V1 to V2: %w", err)
		}
		schemaState.MinVersion = 2
		schemaState.MaxVersion = 2
	}
	if schemaState.MarkerCount == 1 && schemaState.MinVersion == 2 {
		if err := migrateGraphV2ToV3(ctx, driver); err != nil {
			return fmt.Errorf("migrate Neo4j graph schema V2 to V3: %w", err)
		}
		schemaState.MinVersion = graphSchemaVersion
		schemaState.MaxVersion = graphSchemaVersion
	}
	if schemaState.MarkerCount == 1 &&
		schemaState.MinVersion != graphSchemaVersion {
		return fmt.Errorf(
			"Neo4j graph schema %d is unsupported; this server requires schema %d",
			schemaState.MinVersion,
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

	// A fresh graph and every supported prior graph converge on the same single
	// schema marker.
	if err := runDDL(ctx, driver, fmt.Sprintf(
		"MERGE (:SchemaVersion {version: %d})",
		graphSchemaVersion,
	)); err != nil {
		return fmt.Errorf("schema version: %w", err)
	}

	slog.Info("schema initialization complete", "constraints", constraintCount, "indexes", len(indexDefs))
	return nil
}

func migrateGraphV2ToV3(ctx context.Context, driver neo4j.DriverWithContext) error {
	for _, cypher := range []string{
		`MATCH ()-[legacy:POISONED_INSTRUCTIONS]->() DELETE legacy`,
		`MATCH (instruction:InstructionFile) REMOVE instruction.is_suspicious`,
		`MATCH (schema:SchemaVersion {version: 2}) SET schema.version = 3`,
	} {
		if err := runDDL(ctx, driver, cypher); err != nil {
			return err
		}
	}
	return nil
}

func migrateGraphV1ToV2(ctx context.Context, driver neo4j.DriverWithContext) error {
	// Legacy campaign proof cannot be relabeled as same-scan evidence. Remove the
	// raw relationship and conservatively downgrade its composite projection;
	// the next normal postprocessing epoch recomputes confidence and proof from
	// current graph truth.
	for _, cypher := range []string{
		`MATCH ()-[legacy:CREDENTIAL_REACH_VERIFIED]->() DELETE legacy`,
		`MATCH (legacy:ExtractedTrainingSignal) DETACH DELETE legacy`,
		`MATCH (service:AIService) REMOVE service.is_anonymous_loot`,
		`DROP INDEX idx_aiservice_is_anonymous_loot IF EXISTS`,
		`MATCH ()-[e:CAN_REACH]->()
WHERE e.reach_evidence_state = 'verified'
SET e.reach_evidence_state = 'inferred',
    e.confidence = CASE WHEN coalesce(e.confidence, 0.0) > 0.6 THEN 0.6 ELSE e.confidence END
REMOVE e.verified_outcome, e.verified_scenario_id, e.verified_scenario_version,
       e.verified_run_id, e.verified_at, e.verified_oracle_type,
       e.verified_control_stage, e.verified_control_status,
       e.verified_control_resource_addressed, e.verified_authed_stage,
       e.verified_authed_status, e.verified_authed_resource_addressed,
       e.verified_cleanup_status`,
		`MATCH (schema:SchemaVersion {version: 1}) SET schema.version = 2`,
	} {
		if err := runDDL(ctx, driver, cypher); err != nil {
			return err
		}
	}
	return nil
}

func readGraphSchemaState(
	ctx context.Context,
	driver neo4j.DriverWithContext,
) (graphSchemaState, error) {
	session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	result, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		rows, err := tx.Run(ctx, graphSchemaVersionCypher, nil)
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
				return 0, fmt.Errorf("schema version query omitted %s", key)
			}
			count, ok := value.(int64)
			if !ok {
				return 0, fmt.Errorf("schema version %s has type %T", key, value)
			}
			return count, nil
		}
		markerCount, err := readCount("marker_count")
		if err != nil {
			return nil, err
		}
		versionCount, err := readCount("version_count")
		if err != nil {
			return nil, err
		}
		minVersion, err := readCount("min_version")
		if err != nil {
			return nil, err
		}
		maxVersion, err := readCount("max_version")
		if err != nil {
			return nil, err
		}
		return graphSchemaState{
			MarkerCount:  markerCount,
			VersionCount: versionCount,
			MinVersion:   minVersion,
			MaxVersion:   maxVersion,
		}, nil
	})
	if err != nil {
		return graphSchemaState{}, err
	}
	state, ok := result.(graphSchemaState)
	if !ok {
		return graphSchemaState{}, fmt.Errorf(
			"unexpected graph schema state type %T",
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
