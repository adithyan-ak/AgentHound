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
}

func InitSchema(ctx context.Context, driver neo4j.DriverWithContext) error {
	major, minor, err := DetectVersion(ctx, driver)
	if err != nil {
		slog.Warn("failed to detect neo4j version, assuming 4.4", "error", err)
		major, minor = 4, 4
	}
	slog.Info("detected neo4j version", "major", major, "minor", minor)

	useForRequire := major > 4 || (major == 4 && minor >= 4)

	// Create uniqueness constraints for all 14 node labels
	for _, label := range ingest.AllNodeLabels {
		cypher := constraintCypher(label, useForRequire)
		if err := runDDL(ctx, driver, cypher); err != nil {
			if isConstraintExistsError(err) {
				slog.Info("constraint already exists", "label", label)
				continue
			}
			return fmt.Errorf("create constraint %s: %w", label, err)
		}
		slog.Info("created constraint", "label", label)
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

	// Schema version tracking
	if err := runDDL(ctx, driver, "MERGE (:SchemaVersion {version: 1})"); err != nil {
		return fmt.Errorf("schema version: %w", err)
	}

	slog.Info("schema initialization complete", "constraints", len(ingest.AllNodeLabels), "indexes", len(indexDefs))
	return nil
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
