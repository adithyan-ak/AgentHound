package campaign

import (
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

func testEvidence(outcome Outcome) Evidence {
	return Evidence{
		ScenarioID:      "cred-reach",
		ScenarioVersion: 1,
		RunID:           "run-123",
		EngagementID:    "ENG-1",
		OracleType:      OracleTypeDifferentialCredentialReach,
		Outcome:         outcome,
		ControlStatus:   ProbeDenied,
		AuthedStatus:    ProbeAllowed,
		VerifiedAt:      "2026-07-12T00:00:00Z",
		Witness:         validWitness(),
	}
}

func TestEvidenceGraphCredentialReachVerified(t *testing.T) {
	ev := testEvidence(OutcomeCredentialGatedReachVerified)
	nodes, edges := ev.EvidenceGraph("scan-1")
	if len(nodes) != 2 || len(edges) != 1 {
		t.Fatalf("got %d nodes / %d edges, want 2 / 1", len(nodes), len(edges))
	}
	edge := edges[0]
	if edge.Kind != "CREDENTIAL_REACH_VERIFIED" {
		t.Fatalf("edge kind = %q", edge.Kind)
	}
	if edge.Source != ev.Witness.CredentialID || edge.SourceKind != "Credential" {
		t.Fatalf("source = %s/%s, want credential", edge.Source, edge.SourceKind)
	}
	if edge.Target != ev.Witness.ResourceID || edge.TargetKind != "MCPResource" {
		t.Fatalf("target = %s/%s, want resource", edge.Target, edge.TargetKind)
	}

	// Reference-only endpoints assert only ID+kind with empty properties.
	for _, n := range nodes {
		if n.PropertySemantics != ingest.NodePropertySemanticsReferenceOnly {
			t.Errorf("node %s is not reference_only", n.ID)
		}
		if len(n.Properties) != 0 {
			t.Errorf("reference_only node %s must have empty properties, got %v", n.ID, n.Properties)
		}
	}

	// Raw edge must carry a finite non-negative risk_weight (validator + traversal).
	rw, ok := edge.Properties["risk_weight"].(float64)
	if !ok || rw < 0 {
		t.Fatalf("risk_weight = %v, want finite non-negative", edge.Properties["risk_weight"])
	}
	if edge.Properties["is_composite"] != false {
		t.Fatalf("evidence edge must be raw (is_composite=false)")
	}
}

// TestEvidenceGraphNeverCarriesRawCredential is the redaction guard: no emitted
// property may contain the raw credential material, only its hash.
func TestEvidenceGraphNeverCarriesRawCredential(t *testing.T) {
	ev := testEvidence(OutcomeCredentialGatedReachVerified)
	_, edges := ev.EvidenceGraph("scan-1")
	for key, val := range edges[0].Properties {
		if s, ok := val.(string); ok && s == testCredMateri {
			t.Fatalf("property %q leaked raw credential material", key)
		}
	}
	// The hash must be present so the server can re-correlate.
	if edges[0].Properties[PropCredentialValueHash] != ev.Witness.CredentialValueHash {
		t.Fatalf("value_hash echo missing from evidence edge")
	}
	if edges[0].Properties[PropWitnessFingerprint] != ev.Witness.Fingerprint() {
		t.Fatalf("witness fingerprint echo missing from evidence edge")
	}
}

func TestEvidenceGraphPublicAccess(t *testing.T) {
	for _, outcome := range []Outcome{OutcomeAnonymousAccessObserved, OutcomeAnonymousAccessCredentialRejected} {
		ev := testEvidence(outcome)
		nodes, edges := ev.EvidenceGraph("scan-1")
		if len(nodes) != 2 || len(edges) != 1 {
			t.Fatalf("%s: got %d nodes / %d edges, want 2 / 1", outcome, len(nodes), len(edges))
		}
		edge := edges[0]
		if edge.Kind != "PUBLIC_ACCESS_OBSERVED" {
			t.Fatalf("%s: edge kind = %q, want PUBLIC_ACCESS_OBSERVED", outcome, edge.Kind)
		}
		if edge.Source != ev.Witness.ServerID || edge.SourceKind != "MCPServer" {
			t.Fatalf("%s: source = %s/%s, want server", outcome, edge.Source, edge.SourceKind)
		}
	}
}

func TestEvidenceGraphNoEdgeOutcomes(t *testing.T) {
	for _, outcome := range []Outcome{OutcomeNotObserved, OutcomeIndeterminate} {
		ev := testEvidence(outcome)
		nodes, edges := ev.EvidenceGraph("scan-1")
		if len(nodes) != 0 || len(edges) != 0 {
			t.Fatalf("%s must emit no evidence graph, got %d nodes / %d edges", outcome, len(nodes), len(edges))
		}
	}
}
