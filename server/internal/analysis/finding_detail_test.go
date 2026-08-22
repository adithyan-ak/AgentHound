package analysis

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/server/model"
)

func TestInstructionEvidenceFromFinding(t *testing.T) {
	evidenceJSON, err := json.Marshal(map[string]any{
		"version": 1, "verdict": "signal", "total_signals": 1, "truncated": false,
		"signals": []any{map[string]any{
			"rule_id": "injection-ignore-previous", "label": "Ignore Previous Instructions",
			"severity": "critical", "strength": "primary", "raw_offset": 10,
			"line": 2, "column": 3, "match": "ignore previous instructions",
			"context_before": "before\n", "context_after": "\nafter",
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	finding := &model.Finding{
		EdgeKind: "INSTRUCTION_SIGNAL",
		ExactEvidence: &model.ExactFindingEvidence{Nodes: []model.ExactFindingEvidenceNode{{
			ID: "instruction-1", Kinds: []string{"InstructionFile"}, Properties: map[string]any{
				"path": "/work/AGENTS.md", "type": "agents.md", "hash": "sha256:abc",
				"instruction_verdict": "signal", "instruction_scope": "deep",
				"instruction_signal_count": int64(1), "instruction_signal_truncated": false,
				"instruction_evidence_version": int64(1), "instruction_evidence_json": string(evidenceJSON),
				"size_bytes": int64(100), "modified_at": "2026-08-20T12:00:00Z",
			},
		}}, Complete: true},
	}
	got := InstructionEvidenceFromFinding(finding)
	if got == nil || got.Path != "/work/AGENTS.md" || got.TotalSignals != 1 || got.Signals[0].Line != 2 {
		t.Fatalf("instruction evidence = %+v", got)
	}
}

func TestInstructionEvidenceFromFindingRejectsProjectionMismatch(t *testing.T) {
	finding := &model.Finding{
		EdgeKind: "POISONED_INSTRUCTIONS",
		ExactEvidence: &model.ExactFindingEvidence{Nodes: []model.ExactFindingEvidenceNode{{
			Kinds: []string{"InstructionFile"},
			Properties: map[string]any{
				"path": "/work/AGENTS.md", "type": "agents.md", "hash": "sha256:abc",
				"instruction_verdict": "signal", "instruction_scope": "exact_project",
				"instruction_signal_count": int64(1), "instruction_signal_truncated": false,
				"instruction_evidence_version": int64(1), "size_bytes": int64(100),
				"modified_at":               "2026-08-20T12:00:00Z",
				"instruction_evidence_json": `{"version":1,"verdict":"signal","total_signals":1,"truncated":false,"signals":[{"rule_id":"rule","label":"Rule","severity":"medium","strength":"primary","raw_offset":1,"line":1,"column":2,"match":"x","context_before":"","context_after":""}]}`,
			},
		}}},
	}
	if got := InstructionEvidenceFromFinding(finding); got != nil {
		t.Fatalf("projection mismatch produced instruction evidence: %+v", got)
	}
}

func TestAttackPathFromExactEvidenceUsesPersistedWitness(t *testing.T) {
	finding := &model.Finding{
		SourceID: "source",
		TargetID: "target",
		ExactEvidence: &model.ExactFindingEvidence{
			Version:  1,
			Complete: true,
			Reasons:  []string{},
			Nodes: []model.ExactFindingEvidenceNode{
				{ID: "source", Kinds: []string{"AgentInstance"}, Properties: map[string]any{
					"name": "agent", "observation_fact_fingerprints": []any{"internal-node"},
				}},
				{ID: "target", Kinds: []string{"MCPResource"}, Properties: map[string]any{"name": "resource"}},
			},
			Edges: []model.ExactFindingEvidenceEdge{{
				Source: "source",
				Target: "target",
				Kind:   "HAS_ACCESS_TO",
				Properties: map[string]any{
					"risk_weight": 0.2, "observation_fact_fingerprints": []any{"internal-edge"},
				},
			}},
		},
	}

	path := AttackPathFromExactEvidence(finding)
	if path == nil || len(path.Nodes) != 2 || len(path.Edges) != 1 {
		t.Fatalf("path = %+v", path)
	}
	if path.Completeness.State != EvidenceStateComplete ||
		path.Cost.State != EvidenceStateComplete ||
		path.Cost.Value == nil ||
		*path.Cost.Value != 0.2 {
		t.Fatalf("evidence state = %+v cost=%+v", path.Completeness, path.Cost)
	}
	if _, exists := path.Nodes[0].Properties["observation_fact_fingerprints"]; exists {
		t.Fatalf("finding detail node leaked internal fingerprint: %+v", path.Nodes[0])
	}
	if _, exists := path.Edges[0].Properties["observation_fact_fingerprints"]; exists {
		t.Fatalf("finding detail edge leaked internal fingerprint: %+v", path.Edges[0])
	}
	if _, exists := finding.ExactEvidence.Nodes[0].Properties["observation_fact_fingerprints"]; !exists {
		t.Fatal("finding detail sanitization mutated persisted exact evidence")
	}
}

func TestAttackPathFromExactEvidenceMarshalsMissingKindsAsArray(t *testing.T) {
	path := AttackPathFromExactEvidence(&model.Finding{
		ExactEvidence: &model.ExactFindingEvidence{
			Version:  1,
			Complete: true,
			Nodes: []model.ExactFindingEvidenceNode{{
				ID:         "untyped",
				Kinds:      nil,
				Properties: map[string]any{},
			}},
			Edges:   []model.ExactFindingEvidenceEdge{},
			Reasons: []string{},
		},
	})
	if path == nil || len(path.Nodes) != 1 || path.Nodes[0].Kinds == nil {
		t.Fatalf("path node kinds = %#v, want non-nil empty slice", path)
	}

	payload, err := json.Marshal(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(payload), `"kinds":[]`) {
		t.Fatalf("path wire payload = %s, want kinds:[]", payload)
	}
}

func TestBuildImpactUsesCanonicalVariant(t *testing.T) {
	finding := &model.Finding{
		EdgeKind:   "CAN_REACH",
		Variant:    model.FindingVariantCredentialReference,
		SourceName: "agent",
		TargetName: "credential",
	}
	impact := BuildImpact(finding, nil)
	if !strings.Contains(impact.Summary, "usable material is not present") {
		t.Fatalf("summary = %q", impact.Summary)
	}
}

func TestFindingDetailMarshalEmitsRemediationCollectionsAsArrays(t *testing.T) {
	path := &AttackPath{
		Nodes: []PathNode{
			{ID: "server", Properties: map[string]any{"name": "server"}},
			{ID: "tool", Properties: map[string]any{"name": "tool"}},
			{ID: "resource", Properties: map[string]any{"name": "resource"}},
		},
		Edges: []PathEdge{
			{Source: "server", Target: "tool", Kind: "PROVIDES_TOOL"},
			{Source: "tool", Target: "resource", Kind: "HAS_ACCESS_TO"},
		},
	}
	detail := FindingDetail{
		Remediation: BuildRemediation(path, &model.Finding{EdgeKind: "CAN_REACH"}),
	}

	payload, err := json.Marshal(detail)
	if err != nil {
		t.Fatal(err)
	}
	var wire struct {
		Remediation []struct {
			Channels json.RawMessage `json:"channels"`
			Commands json.RawMessage `json:"commands"`
		} `json:"remediation"`
	}
	if err := json.Unmarshal(payload, &wire); err != nil {
		t.Fatal(err)
	}
	if len(wire.Remediation) != 2 {
		t.Fatalf("remediation = %s", payload)
	}
	for i, step := range wire.Remediation {
		if string(step.Channels) != "[]" {
			t.Errorf("remediation[%d].channels = %s, want []", i, step.Channels)
		}
		if string(step.Commands) != "[]" {
			t.Errorf("remediation[%d].commands = %s, want []", i, step.Commands)
		}
	}
}
