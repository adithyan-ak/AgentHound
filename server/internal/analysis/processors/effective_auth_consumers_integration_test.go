package processors

import (
	"context"
	"os"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

// TestIntegrationCanReachEffectiveAuthProvenance proves the credential-chain
// auth predicate against Neo4j rather than only inspecting its Cypher text.
// Runtime-observed anonymous access and configured weak authentication are
// eligible; a configured no-auth claim without accepted runtime evidence is
// not.
func TestIntegrationCanReachEffectiveAuthProvenance(t *testing.T) {
	ctx, db, writer, cleanup := effectiveAuthIntegrationDB(t, "test-can-reach-effective-auth")
	defer cleanup()

	const scanID = "test-can-reach-effective-auth"
	nodes := []ingest.Node{
		processorFixtureNode("creach-agent-observed", "AgentInstance", "observed-agent", scanID, nil),
		processorFixtureNode("creach-agent-weak", "AgentInstance", "weak-agent", scanID, nil),
		processorFixtureNode("creach-agent-unobserved", "AgentInstance", "unobserved-agent", scanID, nil),
		processorFixtureNode("creach-entry-observed", "MCPServer", "observed-entry", scanID, map[string]any{
			"transport": "http", "status": "reachable",
			"auth_method": "bearer", "auth_assurance": "moderate",
			"auth_evidence":        "configured_credential",
			"observed_auth_method": "none", "observed_auth_assurance": "unauthenticated",
			"observed_auth_evidence": "anonymous_probe_succeeded",
		}),
		processorFixtureNode("creach-entry-weak", "MCPServer", "weak-entry", scanID, map[string]any{
			"transport": "http", "status": "reachable",
			"auth_method": "apiKey", "auth_assurance": "weak",
			"auth_evidence": "configured_credential",
		}),
		processorFixtureNode("creach-entry-unobserved", "MCPServer", "unobserved-entry", scanID, map[string]any{
			"transport": "http", "status": "reachable",
			"auth_method": "none", "auth_assurance": "unauthenticated",
			"auth_evidence": "unknown",
		}),
		processorFixtureNode("creach-entry-tool-observed", "MCPTool", "observed-reader", scanID, map[string]any{
			"capability_surface": []string{"file_read"},
		}),
		processorFixtureNode("creach-entry-tool-weak", "MCPTool", "weak-reader", scanID, map[string]any{
			"capability_surface": []string{"credential_access"},
		}),
		processorFixtureNode("creach-entry-tool-unobserved", "MCPTool", "unobserved-reader", scanID, map[string]any{
			"capability_surface": []string{"file_read"},
		}),
		processorFixtureNode("creach-target-server", "MCPServer", "target-server", scanID, map[string]any{
			"transport": "http", "status": "reachable",
			"auth_method": "mtls", "auth_assurance": "strong",
			"auth_evidence": "configured_credential",
		}),
		processorFixtureNode("creach-target-identity", "Identity", "target-identity", scanID, nil),
		processorFixtureCredential(
			"creach-target-credential", "target-credential", scanID,
			"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			"value_hash", "value_hash",
		),
		processorFixtureNode("creach-target-tool", "MCPTool", "target-tool", scanID, nil),
		processorFixtureNode("creach-resource", "MCPResource", "target-resource", scanID, nil),
	}
	if _, err := writer.WriteNodes(ctx, managedProcessorNodes(nodes), scanID); err != nil {
		t.Fatalf("write nodes: %v", err)
	}

	rawEdges := []ingest.Edge{
		processorFixtureEdge("creach-agent-observed", "creach-entry-observed", "TRUSTS_SERVER", "AgentInstance", "MCPServer"),
		processorFixtureEdge("creach-agent-weak", "creach-entry-weak", "TRUSTS_SERVER", "AgentInstance", "MCPServer"),
		processorFixtureEdge("creach-agent-unobserved", "creach-entry-unobserved", "TRUSTS_SERVER", "AgentInstance", "MCPServer"),
		processorFixtureEdge("creach-entry-observed", "creach-entry-tool-observed", "PROVIDES_TOOL", "MCPServer", "MCPTool"),
		processorFixtureEdge("creach-entry-weak", "creach-entry-tool-weak", "PROVIDES_TOOL", "MCPServer", "MCPTool"),
		processorFixtureEdge("creach-entry-unobserved", "creach-entry-tool-unobserved", "PROVIDES_TOOL", "MCPServer", "MCPTool"),
		processorFixtureEdge("creach-target-server", "creach-target-identity", "AUTHENTICATES_WITH", "MCPServer", "Identity"),
		processorFixtureEdge("creach-target-identity", "creach-target-credential", "USES_CREDENTIAL", "Identity", "Credential"),
		processorFixtureEdge("creach-target-server", "creach-target-tool", "PROVIDES_TOOL", "MCPServer", "MCPTool"),
	}
	if _, err := writer.WriteEdges(ctx, managedProcessorEdges(rawEdges), scanID); err != nil {
		t.Fatalf("write raw edges: %v", err)
	}
	access := processorFixtureEdge(
		"creach-target-tool", "creach-resource", "HAS_ACCESS_TO", "MCPTool", "MCPResource",
	)
	if _, err := writer.WriteCompositeEdges(
		ctx, compositeProcessorEdges([]ingest.Edge{access}), scanID,
	); err != nil {
		t.Fatalf("write access edge: %v", err)
	}

	if _, err := (&AuthStrength{}).Process(ctx, db, scanID); err != nil {
		t.Fatalf("materialize effective auth: %v", err)
	}
	if _, err := (&CanReach{}).Process(ctx, db, scanID); err != nil {
		t.Fatalf("can_reach process: %v", err)
	}

	assertCompositeEdgeCount(t, ctx, db, "creach-agent-observed", "CAN_REACH", "creach-resource", 1)
	assertCompositeEdgeCount(t, ctx, db, "creach-agent-weak", "CAN_REACH", "creach-resource", 1)
	assertCompositeEdgeCount(t, ctx, db, "creach-agent-unobserved", "CAN_REACH", "creach-resource", 0)
}

// TestIntegrationCrossProtocolEffectiveAuthProvenance proves that shared-host
// correlation accepts only exact observed anonymous A2A access. A configured
// no-auth card without the bounded protocol observation is not enough.
func TestIntegrationCrossProtocolEffectiveAuthProvenance(t *testing.T) {
	ctx, db, writer, cleanup := effectiveAuthIntegrationDB(t, "test-cross-protocol-effective-auth")
	defer cleanup()

	const scanID = "test-cross-protocol-effective-auth"
	nodes := []ingest.Node{
		processorFixtureNode("xproto-ext-observed", "A2AAgent", "observed-external", scanID, map[string]any{
			"auth_method": "apiKey", "auth_assurance": "weak",
			"auth_evidence":        "declared_security_scheme",
			"auth_probe_method":    "get_task_nonexistent",
			"auth_probe_status":    "anonymous_protocol_access",
			"auth_probe_detail":    "task_not_found_v1",
			"observed_auth_method": "none", "observed_auth_assurance": "unauthenticated",
			"observed_auth_evidence": "anonymous_probe_succeeded",
		}),
		processorFixtureNode("xproto-ext-unobserved", "A2AAgent", "unobserved-external", scanID, map[string]any{
			"auth_method": "none", "auth_assurance": "unauthenticated",
			"auth_evidence": "unknown",
		}),
		processorFixtureNode("xproto-internal", "A2AAgent", "internal", scanID, map[string]any{
			"auth_method": "mtls", "auth_assurance": "strong",
			"auth_evidence": "declared_security_scheme",
		}),
		processorFixtureNode("xproto-host", "Host", "shared-host", scanID, map[string]any{
			"hostname": "shared-host.invalid",
		}),
		processorFixtureNode("xproto-server", "MCPServer", "shared-server", scanID, map[string]any{
			"transport": "http", "status": "reachable",
			"auth_method": "mtls", "auth_assurance": "strong",
			"auth_evidence": "configured_credential",
		}),
		processorFixtureNode("xproto-agent-instance", "AgentInstance", "mcp-agent", scanID, nil),
		processorFixtureNode("xproto-tool", "MCPTool", "shared-tool", scanID, nil),
		processorFixtureNode("xproto-resource", "MCPResource", "shared-resource", scanID, nil),
	}
	if _, err := writer.WriteNodes(ctx, managedProcessorNodes(nodes), scanID); err != nil {
		t.Fatalf("write nodes: %v", err)
	}
	rawEdges := []ingest.Edge{
		processorFixtureEdge("xproto-ext-observed", "xproto-internal", "DELEGATES_TO", "A2AAgent", "A2AAgent"),
		processorFixtureEdge("xproto-ext-unobserved", "xproto-internal", "DELEGATES_TO", "A2AAgent", "A2AAgent"),
		processorFixtureEdge("xproto-internal", "xproto-host", "RUNS_ON", "A2AAgent", "Host"),
		processorFixtureEdge("xproto-server", "xproto-host", "RUNS_ON", "MCPServer", "Host"),
		processorFixtureEdge("xproto-agent-instance", "xproto-server", "TRUSTS_SERVER", "AgentInstance", "MCPServer"),
		processorFixtureEdge("xproto-server", "xproto-tool", "PROVIDES_TOOL", "MCPServer", "MCPTool"),
	}
	if _, err := writer.WriteEdges(ctx, managedProcessorEdges(rawEdges), scanID); err != nil {
		t.Fatalf("write raw edges: %v", err)
	}
	access := processorFixtureEdge("xproto-tool", "xproto-resource", "HAS_ACCESS_TO", "MCPTool", "MCPResource")
	if _, err := writer.WriteCompositeEdges(
		ctx, compositeProcessorEdges([]ingest.Edge{access}), scanID,
	); err != nil {
		t.Fatalf("write access edge: %v", err)
	}

	if _, err := (&AuthStrength{}).Process(ctx, db, scanID); err != nil {
		t.Fatalf("materialize effective auth: %v", err)
	}
	if _, err := (&CrossProtocol{}).Process(ctx, db, scanID); err != nil {
		t.Fatalf("cross_protocol process: %v", err)
	}

	assertCompositeEdgeCount(t, ctx, db, "xproto-ext-observed", "CAN_REACH", "xproto-resource", 1)
	assertCompositeEdgeCount(t, ctx, db, "xproto-ext-unobserved", "CAN_REACH", "xproto-resource", 0)
}

func effectiveAuthIntegrationDB(
	t *testing.T,
	scanID string,
) (context.Context, graph.GraphDB, *graph.Writer, func()) {
	t.Helper()
	uri := os.Getenv("AGENTHOUND_NEO4J_URI")
	if uri == "" {
		t.Skip("skipping integration test: AGENTHOUND_NEO4J_URI not set")
	}
	ctx := context.Background()
	driver, err := graph.NewDriver(
		uri,
		os.Getenv("AGENTHOUND_NEO4J_USER"),
		os.Getenv("AGENTHOUND_NEO4J_PASSWORD"),
	)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	db := graph.NewDB(graph.NewReader(driver), graph.NewWriter(driver))
	cleanup := func() {
		_, _ = db.ExecuteWrite(ctx,
			"MATCH (n) WHERE n.scan_id = $sid DETACH DELETE n",
			map[string]any{"sid": scanID})
		driver.Close(ctx)
	}
	_, _ = db.ExecuteWrite(ctx,
		"MATCH (n) WHERE n.scan_id = $sid DETACH DELETE n",
		map[string]any{"sid": scanID})
	return ctx, db, graph.NewWriter(driver), cleanup
}

func assertCompositeEdgeCount(
	t *testing.T,
	ctx context.Context,
	db graph.GraphDB,
	sourceID, kind, targetID string,
	want int,
) {
	t.Helper()
	rows, err := db.Query(ctx, `MATCH (source {objectid:$source})-[edge]->(target {objectid:$target})
WHERE type(edge) = $kind AND edge.is_composite = true
RETURN count(edge) AS n`, map[string]any{
		"source": sourceID,
		"target": targetID,
		"kind":   kind,
	})
	if err != nil {
		t.Fatalf("query %s %s->%s: %v", kind, sourceID, targetID, err)
	}
	if got := toInt(rows[0]["n"]); got != want {
		t.Errorf("%s %s->%s count = %d, want %d", kind, sourceID, targetID, got, want)
	}
}
