package analysis

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/campaign"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

const (
	witnessServerID = "sha256:witness-server"
	witnessAgentID  = "sha256:witness-agent"
	witnessCredID   = "sha256:witness-credential"
	witnessResURI   = "postgres://prod/customers"
)

func witnessExportRow(resourceID string) map[string]any {
	evidenceIDs := []any{
		witnessAgentID, "sha256:tool", witnessServerID,
		witnessCredID, "sha256:identity", resourceID,
	}
	return map[string]any{
		"agent_id":              witnessAgentID,
		"resource_id":           resourceID,
		"resource_uri":          witnessResURI,
		"credential_id":         witnessCredID,
		"credential_value_hash": "0123456789abcdef",
		"credential_merge_key":  "value_hash",
		"server_id":             witnessServerID,
		"server_transport":      "http",
		"evidence_node_ids":     evidenceIDs,
		"evidence_node_labels": []any{
			[]any{"AgentInstance"},
			[]any{"MCPTool"},
			[]any{"MCPServer"},
			[]any{"Credential"},
			[]any{"Identity"},
			[]any{"MCPResource"},
		},
	}
}

func TestBuildWitnessMatchesFingerprint(t *testing.T) {
	resID := ingest.ComputeNodeID("MCPResource", witnessServerID, witnessResURI)
	mock := &graph.MockGraphDB{QueryResult: []map[string]any{witnessExportRow(resID)}}
	findingID := findingFingerprint("CAN_REACH", witnessAgentID, resID)

	w, err := BuildWitness(context.Background(), mock, findingID)
	if err != nil {
		t.Fatalf("BuildWitness: %v", err)
	}
	if w.AgentID != witnessAgentID || w.CredentialID != witnessCredID ||
		w.ServerID != witnessServerID || w.ResourceID != resID {
		t.Fatalf("witness identity mismatch: %+v", w)
	}
	if w.ResourceIdentityInput != witnessResURI ||
		w.PredictedEdgeKind != campaign.PredictedEdgeKindCanReach {
		t.Fatalf("witness fields mismatch: %+v", w)
	}
	if w.SchemaVersion != campaign.WitnessSchemaVersion {
		t.Fatalf("schema version = %d", w.SchemaVersion)
	}
	if len(w.EvidenceNodeIDs) != 6 || len(w.EvidenceNodeKinds) != 6 {
		t.Fatalf("evidence topology = %v / %v", w.EvidenceNodeIDs, w.EvidenceNodeKinds)
	}
	if w.EvidenceNodeIDs[1] != "sha256:tool" || w.EvidenceNodeKinds[1] != "MCPTool" {
		t.Fatalf("actual ordered topology was not exported: %+v", w)
	}
	// The export leaves the revision for the guarded caller to stamp.
	if w.PublicationRevision != 0 {
		t.Fatalf("BuildWitness must not stamp the revision, got %d", w.PublicationRevision)
	}
	// The exported tuple must pass structural validation (binding included).
	if err := w.ValidateStructure(); err != nil {
		t.Fatalf("exported witness failed structural validation: %v", err)
	}
}

func TestBuildWitnessRejectsNonHTTPServer(t *testing.T) {
	resID := ingest.ComputeNodeID("MCPResource", witnessServerID, witnessResURI)
	row := witnessExportRow(resID)
	row["server_transport"] = "stdio"
	mock := &graph.MockGraphDB{QueryResult: []map[string]any{row}}
	findingID := findingFingerprint("CAN_REACH", witnessAgentID, resID)
	if _, err := BuildWitness(context.Background(), mock, findingID); err == nil {
		t.Fatal("stdio-backed resource must not produce a runnable witness")
	}
}

func TestWitnessExportContainsNoEndpoint(t *testing.T) {
	resID := ingest.ComputeNodeID("MCPResource", witnessServerID, witnessResURI)
	mock := &graph.MockGraphDB{QueryResult: []map[string]any{witnessExportRow(resID)}}
	findingID := findingFingerprint("CAN_REACH", witnessAgentID, resID)
	w, err := BuildWitness(context.Background(), mock, findingID)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(w)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(string(payload)), "endpoint") {
		t.Fatalf("witness exposed an endpoint field: %s", payload)
	}
}

func TestBuildWitnessNoMatch(t *testing.T) {
	resID := ingest.ComputeNodeID("MCPResource", witnessServerID, witnessResURI)
	mock := &graph.MockGraphDB{QueryResult: []map[string]any{witnessExportRow(resID)}}
	if _, err := BuildWitness(context.Background(), mock, "0000000000000000"); err == nil {
		t.Fatal("unknown finding must produce an error")
	}
}

// TestBuildWitnessRejectsBrokenBinding guards the sanitizer: if a resource node's
// URI does not hash to its node ID (a forged/mismatched graph), the exported
// witness must fail its binding check rather than emit a bad witness.
func TestBuildWitnessRejectsBrokenBinding(t *testing.T) {
	brokenID := "sha256:not-derived-from-uri"
	mock := &graph.MockGraphDB{QueryResult: []map[string]any{witnessExportRow(brokenID)}}
	findingID := findingFingerprint("CAN_REACH", witnessAgentID, brokenID)
	if _, err := BuildWitness(context.Background(), mock, findingID); err == nil {
		t.Fatal("witness whose resource_id does not bind to (server_id, uri) must be rejected")
	}
}

func TestBuildWitnessEmptyFinding(t *testing.T) {
	mock := &graph.MockGraphDB{QueryResult: []map[string]any{}}
	if _, err := BuildWitness(context.Background(), mock, ""); err == nil {
		t.Fatal("empty finding id must error")
	}
}
