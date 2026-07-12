package analysis

import "testing"

// TestBuildEvidenceDAG_CredentialChain exercises the three join types on the
// credential-chain path shape: observed edges, a reversed edge (the gateway's
// EXPOSES_CREDENTIAL to the master key is traversed against its direction in
// the attack flow), and the synthetic value_hash join.
func TestBuildEvidenceDAG_CredentialChain(t *testing.T) {
	f := &Finding{
		EdgeKind:   "CAN_REACH_CREDENTIAL_CHAIN",
		SourceID:   "a",
		SourceName: "DevAgent",
		TargetID:   "c2",
		TargetName: "openai-upstream",
		Confidence: 0.95,
	}
	// Narrative order: agent, server, c1, c1master, gateway, c2.
	path := &AttackPath{
		Nodes: []PathNode{
			{ID: "a", Kinds: []string{"AgentInstance"}, Properties: map[string]any{"name": "DevAgent"}},
			{ID: "s", Kinds: []string{"MCPServer"}, Properties: map[string]any{"name": "srv"}},
			{ID: "c1", Kinds: []string{"Credential"}, Properties: map[string]any{"name": "env-key"}},
			{ID: "c1m", Kinds: []string{"Credential"}, Properties: map[string]any{"name": "master"}},
			{ID: "gw", Kinds: []string{"LiteLLMGateway"}, Properties: map[string]any{"name": "gw"}},
			{ID: "c2", Kinds: []string{"Credential"}, Properties: map[string]any{"name": "openai-upstream"}},
		},
		Edges: []PathEdge{
			{Source: "a", Target: "s", Kind: "TRUSTS_SERVER", Properties: map[string]any{"risk_weight": 0.1}},
			{Source: "s", Target: "c1", Kind: "HAS_ENV_VAR", Properties: map[string]any{"risk_weight": 0.1}},
			{Source: "gw", Target: "c1m", Kind: "EXPOSES_CREDENTIAL", Properties: map[string]any{"risk_weight": 0.1}},
			{Source: "gw", Target: "c2", Kind: "EXPOSES_CREDENTIAL", Properties: map[string]any{"risk_weight": 0.1}},
			{Source: "c1", Target: "c1m", Kind: "VALUE_HASH_MATCH", Properties: map[string]any{"is_synthetic": true}},
		},
	}

	dag := BuildEvidenceDAG(f, path, map[string]any{"source_collector": "cross_service_credential_chain"})
	if dag == nil {
		t.Fatal("expected evidence DAG, got nil")
	}

	var synthetic, reversed, observed int
	for _, j := range dag.Joins {
		switch j.Type {
		case JoinSynthetic:
			synthetic++
		case JoinReversed:
			reversed++
		case JoinObserved:
			observed++
		}
	}
	if synthetic != 1 {
		t.Errorf("synthetic joins = %d, want 1 (the value_hash match)", synthetic)
	}
	if reversed != 1 {
		t.Errorf("reversed joins = %d, want 1 (gw->c1master traversed backward)", reversed)
	}
	if observed != 3 {
		t.Errorf("observed joins = %d, want 3", observed)
	}
	if dag.ConnectedComponents != 1 {
		t.Errorf("connected components = %d, want 1", dag.ConnectedComponents)
	}
	if !dag.Complete {
		t.Error("expected Complete=true (single component spanning source and target)")
	}
	if dag.WeightTotal == nil || *dag.WeightTotal < 0.3999 || *dag.WeightTotal > 0.4001 {
		t.Errorf("WeightTotal = %v, want ~0.4 (four weighted edges; synthetic join excluded)", dag.WeightTotal)
	}
	if dag.WeightMissingCount != 0 {
		t.Errorf("WeightMissingCount = %d, want 0 (synthetic join is not a weight-bearing step)", dag.WeightMissingCount)
	}
}

func TestBuildEvidenceDAG_NilPathIsIncomplete(t *testing.T) {
	f := &Finding{
		EdgeKind: "CAN_REACH",
		SourceID: "a",
		TargetID: "b",
	}
	dag := BuildEvidenceDAG(f, nil, nil)
	if dag == nil {
		t.Fatal("expected evidence DAG, got nil")
	}
	if dag.Complete {
		t.Error("expected Complete=false when no path was reconstructed")
	}
	if dag.WeightTotal != nil {
		t.Errorf("WeightTotal = %v, want nil (unknown) for a missing path", *dag.WeightTotal)
	}
	if dag.ConnectedComponents != 2 {
		t.Errorf("connected components = %d, want 2 (disconnected endpoints)", dag.ConnectedComponents)
	}
	if dag.ConfidenceBasis == "" {
		t.Error("expected a confidence basis even without a path")
	}
}
