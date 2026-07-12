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
	// v0.2 — AIService umbrella label gets indexes only (no uniqueness
	// constraint, per ingest.UmbrellaLabels). These power generic
	// post-processors that span all AI service kinds.
	{"AIService", "endpoint"},
	{"AIService", "is_anonymous_loot"},
	{"Credential", "value_hash"},
}

// neo4jMigration is one ordered, idempotent schema change. Migrations are
// applied in ascending version order; each successful migration records a
// (:SchemaVersion {version}) marker so re-running InitSchema is a no-op and
// upgrades apply only the pending deltas. This replaces the prior fixed
// "create everything, then MERGE version 1" flow with a real ordered
// mechanism so future schema changes are additive and versioned rather than
// silently folded into init.
type neo4jMigration struct {
	version int
	name    string
	apply   func(ctx context.Context, driver neo4j.DriverWithContext, useForRequire bool) error
}

// neo4jMigrations is the ordered migration list. Append new migrations with the
// next version number; never renumber or mutate a shipped migration (prelaunch
// resets aside — a changed migration would not re-run on an already-migrated
// database).
var neo4jMigrations = []neo4jMigration{
	{
		version: 1,
		name:    "base_constraints_and_indexes",
		apply:   migrateBaseSchema,
	},
	{
		version: 2,
		name:    "immutable_generation_observations",
		apply:   migrateGenerationObservations,
	},
	{
		version: 3,
		name:    "generation_observation_lookup_indexes",
		apply:   migrateGenerationObservationIndexes,
	},
}

// useForRequireSyntax reports whether the connected Neo4j speaks the modern
// `FOR ... REQUIRE` constraint syntax (Neo4j 5.x+) versus the legacy
// `ON ... ASSERT` syntax (Neo4j 4.x, including 4.4).
//
// Per the compatibility contract (CLAUDE.md), 4.4 emits `ON ... ASSERT` and
// 5.x emits `FOR ... REQUIRE`. The prior boundary (`major==4 && minor>=4`)
// incorrectly emitted the 5.x `REQUIRE` form on 4.4; `ASSERT` is the documented
// 4.4 form (it is deprecated-but-supported there, while `REQUIRE` was only
// added mid-4.4 and is not safe on all 4.x builds). Keying strictly on the
// major version makes every 4.x use `ASSERT` and every 5.x+ use `REQUIRE`,
// which is valid on both our 4.4 baseline and modern 5.x deployments.
func useForRequireSyntax(major, minor int) bool {
	_ = minor
	return major >= 5
}

func InitSchema(ctx context.Context, driver neo4j.DriverWithContext) error {
	major, minor, err := DetectVersion(ctx, driver)
	if err != nil {
		slog.Warn("failed to detect neo4j version, assuming 4.4", "error", err)
		major, minor = 4, 4
	}
	slog.Info("detected neo4j version", "major", major, "minor", minor)

	useForRequire := useForRequireSyntax(major, minor)

	current, err := readSchemaVersion(ctx, driver)
	if err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	slog.Info("current neo4j schema version", "version", current)

	applied := 0
	for _, m := range neo4jMigrations {
		if m.version <= current {
			continue
		}
		if err := m.apply(ctx, driver, useForRequire); err != nil {
			return fmt.Errorf("apply neo4j migration %d (%s): %w", m.version, m.name, err)
		}
		if err := recordSchemaVersion(ctx, driver, m.version); err != nil {
			return fmt.Errorf("record neo4j migration %d: %w", m.version, err)
		}
		slog.Info("applied neo4j migration", "version", m.version, "name", m.name)
		applied++
	}

	if applied == 0 {
		slog.Info("neo4j schema up to date", "version", current)
	} else {
		slog.Info("neo4j schema migrations complete", "applied", applied)
	}
	return nil
}

// migrateBaseSchema creates the per-kind uniqueness constraints and the
// property indexes. It is version 1 of the ordered schema and preserves the
// original init behavior exactly.
func migrateBaseSchema(ctx context.Context, driver neo4j.DriverWithContext, useForRequire bool) error {
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

	slog.Info("base schema created", "constraints", constraintCount, "indexes", len(indexDefs))
	return nil
}

// migrateGenerationObservations changes each concrete node kind's uniqueness
// key from logical objectid to physical observation_id. Multiple generations
// may therefore retain independent observations of the same logical node,
// while observation_id (= generation + separator + objectid) remains unique.
// This is a prelaunch reset/re-ingest contract: legacy nodes can coexist but
// are not current-generation observations and should be removed by the normal
// reset/re-ingest workflow.
func migrateGenerationObservations(ctx context.Context, driver neo4j.DriverWithContext, useForRequire bool) error {
	for _, label := range ingest.AllNodeLabels {
		if ingest.UmbrellaLabels[label] {
			continue
		}
		oldName := fmt.Sprintf("unique_%s_objectid", strings.ToLower(label))
		if err := runDDL(ctx, driver, fmt.Sprintf("DROP CONSTRAINT %s IF EXISTS", oldName)); err != nil {
			return fmt.Errorf("drop logical-id constraint %s: %w", label, err)
		}
		name := fmt.Sprintf("unique_%s_observation_id", strings.ToLower(label))
		var cypher string
		if useForRequire {
			cypher = fmt.Sprintf("CREATE CONSTRAINT %s IF NOT EXISTS FOR (n:%s) REQUIRE n.observation_id IS UNIQUE", name, label)
		} else {
			cypher = fmt.Sprintf("CREATE CONSTRAINT %s ON (n:%s) ASSERT n.observation_id IS UNIQUE", name, label)
		}
		if err := runDDL(ctx, driver, cypher); err != nil && !isConstraintExistsError(err) {
			return fmt.Errorf("create observation constraint %s: %w", label, err)
		}
		indexName := fmt.Sprintf("idx_%s_generation_id", strings.ToLower(label))
		indexCypher := fmt.Sprintf("CREATE INDEX %s IF NOT EXISTS FOR (n:%s) ON (n.generation_id)", indexName, label)
		if err := runDDL(ctx, driver, indexCypher); err != nil && !isConstraintExistsError(err) {
			return fmt.Errorf("create generation index %s: %w", label, err)
		}
	}
	return nil
}

// migrateGenerationObservationIndexes adds the composite lookup used by
// scoped detail, edge matching, and processors. Dropping the old objectid
// uniqueness constraint also dropped its backing index, so this replacement
// is required to avoid label scans on every (logical id, generation) lookup.
func migrateGenerationObservationIndexes(ctx context.Context, driver neo4j.DriverWithContext, _ bool) error {
	for _, label := range ingest.AllNodeLabels {
		if ingest.UmbrellaLabels[label] {
			continue
		}
		name := fmt.Sprintf("idx_%s_objectid_generation", strings.ToLower(label))
		cypher := fmt.Sprintf(
			"CREATE INDEX %s IF NOT EXISTS FOR (n:%s) ON (n.objectid, n.generation_id)",
			name, label,
		)
		if err := runDDL(ctx, driver, cypher); err != nil && !isConstraintExistsError(err) {
			return fmt.Errorf("create logical-generation index %s: %w", label, err)
		}
	}
	return nil
}

// readSchemaVersion returns the highest applied migration version, or 0 when no
// migration has run yet. Older databases carry a (:SchemaVersion {version: 1})
// marker from the pre-mechanism init, which this reads correctly.
func readSchemaVersion(ctx context.Context, driver neo4j.DriverWithContext) (int, error) {
	session := driver.NewSession(ctx, neo4j.SessionConfig{AccessMode: neo4j.AccessModeRead})
	defer session.Close(ctx)

	v, err := session.ExecuteRead(ctx, func(tx neo4j.ManagedTransaction) (any, error) {
		res, err := tx.Run(ctx, "MATCH (s:SchemaVersion) RETURN coalesce(max(s.version), 0) AS v", nil)
		if err != nil {
			return 0, err
		}
		rec, err := res.Single(ctx)
		if err != nil {
			return 0, err
		}
		val, _ := rec.Get("v")
		switch n := val.(type) {
		case int64:
			return int(n), nil
		case int:
			return n, nil
		default:
			return 0, nil
		}
	})
	if err != nil {
		return 0, err
	}
	// ExecuteRead's closure always returns an int (via the int64/int/default
	// switch above), but assert defensively so a future closure change can
	// never panic on a bad type — a checked assertion degrades to version 0
	// (re-run all migrations) rather than crashing schema init.
	version, ok := v.(int)
	if !ok {
		return 0, fmt.Errorf("read schema version: unexpected result type %T", v)
	}
	return version, nil
}

// recordSchemaVersion marks a migration version as applied. MERGE keeps it
// idempotent.
func recordSchemaVersion(ctx context.Context, driver neo4j.DriverWithContext, version int) error {
	return runDDL(ctx, driver, fmt.Sprintf("MERGE (:SchemaVersion {version: %d})", version))
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
