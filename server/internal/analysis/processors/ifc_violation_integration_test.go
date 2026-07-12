package processors

import (
	"context"
	"os"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

// TestIntegrationIfcViolationHopAndCapabilityGuards locks the two guards in
// ifc_violation.go: the *1..3 HAS_ACCESS_TO hop cap and the high-impact
// capability filter. The detector matches
//
//	(untrusted)-[:INGESTS_UNTRUSTED]->(:MCPResource)<-[:HAS_ACCESS_TO*1..3]-(sensitive)
//
// where the sensitive tool carries a capability in {credential_access,
// file_write, email_send}. We seed:
//   - POSITIVE: a sensitive sink 1 HAS_ACCESS_TO hop from the shared resource.
//   - FP-GUARD A: a non-sensitive sink 1 hop away (capability filter).
//   - FP-GUARD B: a sensitive sink 4 hops away via a HAS_ACCESS_TO chain
//     (exceeds the *1..3 cap).
func TestIntegrationIfcViolationHopAndCapabilityGuards(t *testing.T) {
	uri := os.Getenv("AGENTHOUND_NEO4J_URI")
	if uri == "" {
		t.Skip("skipping integration test: AGENTHOUND_NEO4J_URI not set")
	}
	user := os.Getenv("AGENTHOUND_NEO4J_USER")
	pass := os.Getenv("AGENTHOUND_NEO4J_PASSWORD")

	ctx := context.Background()
	driver, err := graph.NewDriver(uri, user, pass)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer driver.Close(ctx)

	const scanID = "test-ifc-guards"
	db := graph.NewDB(graph.NewReader(driver), graph.NewWriter(driver))

	cleanup := func() {
		_, _ = db.ExecuteWrite(ctx,
			"MATCH (n) WHERE n.scan_id = $sid DETACH DELETE n",
			map[string]any{"sid": scanID})
	}
	cleanup()
	defer cleanup()

	// The untrusted tool ingests a shared resource. Sensitive sinks reach that
	// same resource via HAS_ACCESS_TO chains of varying length.
	nodes := []ingest.Node{
		{ID: "ifc-untrusted", Kinds: []string{"MCPTool"}, Properties: map[string]any{
			"objectid": "ifc-untrusted", "name": "untrusted_reader", "scan_id": scanID,
		}},
		{ID: "ifc-res", Kinds: []string{"MCPResource"}, Properties: map[string]any{
			"objectid": "ifc-res", "name": "shared-resource", "scan_id": scanID,
		}},
		// POSITIVE: sensitive, 1 hop to the resource.
		{ID: "ifc-sensitive-near", Kinds: []string{"MCPTool"}, Properties: map[string]any{
			"objectid": "ifc-sensitive-near", "name": "cred_tool",
			"capability_surface": []string{"credential_access"}, "scan_id": scanID,
		}},
		// FP-GUARD A: 1 hop but non-sensitive capability.
		{ID: "ifc-benign-near", Kinds: []string{"MCPTool"}, Properties: map[string]any{
			"objectid": "ifc-benign-near", "name": "reader_tool",
			"capability_surface": []string{"database_access"}, "scan_id": scanID,
		}},
		// FP-GUARD B: sensitive but 4 hops away via the chain below.
		{ID: "ifc-sensitive-far", Kinds: []string{"MCPTool"}, Properties: map[string]any{
			"objectid": "ifc-sensitive-far", "name": "far_cred_tool",
			"capability_surface": []string{"credential_access"}, "scan_id": scanID,
		}},
		// Intermediate resources forming the 4-hop chain to ifc-res.
		{ID: "ifc-hop1", Kinds: []string{"MCPResource"}, Properties: map[string]any{
			"objectid": "ifc-hop1", "name": "hop1", "scan_id": scanID,
		}},
		{ID: "ifc-hop2", Kinds: []string{"MCPResource"}, Properties: map[string]any{
			"objectid": "ifc-hop2", "name": "hop2", "scan_id": scanID,
		}},
		{ID: "ifc-hop3", Kinds: []string{"MCPResource"}, Properties: map[string]any{
			"objectid": "ifc-hop3", "name": "hop3", "scan_id": scanID,
		}},
	}
	writer := graph.NewWriter(driver)
	if _, err := writer.WriteNodes(ctx, managedProcessorNodes(nodes), scanID); err != nil {
		t.Fatalf("write nodes: %v", err)
	}

	// The matched pattern is (:MCPResource)<-[:HAS_ACCESS_TO*1..3]-(sensitive),
	// i.e. HAS_ACCESS_TO points sink -> resource. Build the far chain so the
	// only path from ifc-sensitive-far to ifc-res is exactly 4 hops:
	//   far -> hop3 -> hop2 -> hop1 -> res
	edges := []ingest.Edge{
		{Source: "ifc-untrusted", Target: "ifc-res", Kind: "INGESTS_UNTRUSTED", SourceKind: "MCPTool", TargetKind: "MCPResource"},
		{Source: "ifc-sensitive-near", Target: "ifc-res", Kind: "HAS_ACCESS_TO", SourceKind: "MCPTool", TargetKind: "MCPResource"},
		{Source: "ifc-benign-near", Target: "ifc-res", Kind: "HAS_ACCESS_TO", SourceKind: "MCPTool", TargetKind: "MCPResource"},
		{Source: "ifc-sensitive-far", Target: "ifc-hop3", Kind: "HAS_ACCESS_TO", SourceKind: "MCPTool", TargetKind: "MCPResource"},
		{Source: "ifc-hop3", Target: "ifc-hop2", Kind: "HAS_ACCESS_TO", SourceKind: "MCPResource", TargetKind: "MCPResource"},
		{Source: "ifc-hop2", Target: "ifc-hop1", Kind: "HAS_ACCESS_TO", SourceKind: "MCPResource", TargetKind: "MCPResource"},
		{Source: "ifc-hop1", Target: "ifc-res", Kind: "HAS_ACCESS_TO", SourceKind: "MCPResource", TargetKind: "MCPResource"},
	}
	if _, err := writer.WriteEdges(ctx, managedProcessorEdges(edges[:1]), scanID); err != nil {
		t.Fatalf("write raw edge: %v", err)
	}
	if _, err := writer.WriteCompositeEdges(
		ctx,
		compositeProcessorEdges(edges[1:]),
		scanID,
	); err != nil {
		t.Fatalf("write composite edges: %v", err)
	}

	if _, err := (&IfcViolation{}).Process(ctx, db, scanID); err != nil {
		t.Fatalf("ifc_violation process: %v", err)
	}

	// POSITIVE: exactly one IFC_VIOLATION to the near sensitive sink.
	rows, err := db.Query(ctx,
		"MATCH (:MCPTool {objectid:'ifc-untrusted'})-[:IFC_VIOLATION]->(t:MCPTool {objectid:'ifc-sensitive-near'}) RETURN count(t) AS n", nil)
	if err != nil {
		t.Fatalf("query positive ifc: %v", err)
	}
	if got := toInt(rows[0]["n"]); got != 1 {
		t.Errorf("near sensitive sink got %d IFC_VIOLATION edges, want 1", got)
	}

	// FP-GUARD A: the non-sensitive sink must get zero (capability filter).
	rows, err = db.Query(ctx,
		"MATCH (:MCPTool {objectid:'ifc-untrusted'})-[:IFC_VIOLATION]->(t:MCPTool {objectid:'ifc-benign-near'}) RETURN count(t) AS n", nil)
	if err != nil {
		t.Fatalf("query fp-guard A: %v", err)
	}
	if got := toInt(rows[0]["n"]); got != 0 {
		t.Errorf("non-sensitive sink got %d IFC_VIOLATION edges, want 0 (capability filter regression)", got)
	}

	// FP-GUARD B: the 4-hop sensitive sink must get zero (locks the *1..3 cap).
	rows, err = db.Query(ctx,
		"MATCH (:MCPTool {objectid:'ifc-untrusted'})-[:IFC_VIOLATION]->(t:MCPTool {objectid:'ifc-sensitive-far'}) RETURN count(t) AS n", nil)
	if err != nil {
		t.Fatalf("query fp-guard B: %v", err)
	}
	if got := toInt(rows[0]["n"]); got != 0 {
		t.Errorf("4-hop sensitive sink got %d IFC_VIOLATION edges, want 0 (*1..3 hop-cap regression)", got)
	}
}
