package analysis

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestGetFindingByID_Found(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryResult: []map[string]any{
			{
				"source_id": "agent-1", "source_name": "TestAgent", "source_kind": "AgentInstance",
				"target_id": "res-1", "target_name": "ProdDB", "target_kind": "MCPResource",
				"edge_kind": "CAN_REACH", "confidence": 0.9,
				"cross_protocol": false, "target_sensitivity": "critical",
			},
		},
	}

	wantID := findingFingerprint("CAN_REACH", "agent-1", "res-1")

	f, err := GetFindingByID(context.Background(), mock, wantID)
	if err != nil {
		t.Fatalf("GetFindingByID() error = %v", err)
	}
	if f == nil {
		t.Fatal("expected finding, got nil")
	}
	if f.ID != wantID {
		t.Errorf("ID = %q, want %q", f.ID, wantID)
	}
	if f.EdgeKind != "CAN_REACH" {
		t.Errorf("EdgeKind = %q, want CAN_REACH", f.EdgeKind)
	}
}

func TestGetFindingByID_NotFound(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryResult: []map[string]any{
			{
				"source_id": "agent-1", "source_name": "TestAgent", "source_kind": "AgentInstance",
				"target_id": "res-1", "target_name": "ProdDB", "target_kind": "MCPResource",
				"edge_kind": "CAN_REACH", "confidence": 0.9,
				"cross_protocol": false, "target_sensitivity": "critical",
			},
		},
	}

	f, err := GetFindingByID(context.Background(), mock, "nonexistent-id")
	if err != nil {
		t.Fatalf("GetFindingByID() error = %v", err)
	}
	if f != nil {
		t.Errorf("expected nil finding, got %+v", f)
	}
}

func TestGetFindingByID_QueryError(t *testing.T) {
	mock := &graph.MockGraphDB{QueryError: errors.New("db down")}

	_, err := GetFindingByID(context.Background(), mock, "any-id")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestGetCompositeEdgeProps_Found(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryResult: []map[string]any{
			{"props": map[string]any{"cross_protocol": true, "confidence": 0.9}},
		},
	}

	f := &Finding{SourceID: "src-1", TargetID: "tgt-1", EdgeKind: "CAN_REACH"}
	props, err := GetCompositeEdgeProps(context.Background(), mock, f)
	if err != nil {
		t.Fatalf("GetCompositeEdgeProps() error = %v", err)
	}
	if props == nil {
		t.Fatal("expected props, got nil")
	}
	if cp, ok := props["cross_protocol"].(bool); !ok || !cp {
		t.Errorf("cross_protocol = %v, want true", props["cross_protocol"])
	}
}

func TestGetCompositeEdgeProps_NotFound(t *testing.T) {
	mock := &graph.MockGraphDB{QueryResult: []map[string]any{}}

	f := &Finding{SourceID: "src-1", TargetID: "tgt-1", EdgeKind: "CAN_REACH"}
	props, err := GetCompositeEdgeProps(context.Background(), mock, f)
	if err != nil {
		t.Fatalf("GetCompositeEdgeProps() error = %v", err)
	}
	if props != nil {
		t.Errorf("expected nil props, got %v", props)
	}
}

func TestGetCompositeEdgeProps_QueryError(t *testing.T) {
	mock := &graph.MockGraphDB{QueryError: errors.New("timeout")}

	f := &Finding{SourceID: "src-1", TargetID: "tgt-1", EdgeKind: "CAN_REACH"}
	_, err := GetCompositeEdgeProps(context.Background(), mock, f)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestReconstructAttackPath_CAN_REACH(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
			if strings.Contains(cypher, "AgentInstance") && strings.Contains(cypher, "TRUSTS_SERVER") {
				return []map[string]any{
					{
						"nodes": []any{
							map[string]any{"id": "agent-1", "name": "TestAgent", "kinds": []any{"AgentInstance"}, "properties": map[string]any{"name": "TestAgent"}},
							map[string]any{"id": "srv-1", "name": "Server1", "kinds": []any{"MCPServer"}, "properties": map[string]any{"name": "Server1"}},
							map[string]any{"id": "tool-1", "name": "ReadDB", "kinds": []any{"MCPTool"}, "properties": map[string]any{"name": "ReadDB"}},
							map[string]any{"id": "res-1", "name": "ProdDB", "kinds": []any{"MCPResource"}, "properties": map[string]any{"name": "ProdDB"}},
						},
						"edges": []any{
							map[string]any{"source": "agent-1", "target": "srv-1", "kind": "TRUSTS_SERVER", "properties": map[string]any{"risk_weight": 0.1}},
							map[string]any{"source": "srv-1", "target": "tool-1", "kind": "PROVIDES_TOOL", "properties": map[string]any{"risk_weight": 0.1}},
							map[string]any{"source": "tool-1", "target": "res-1", "kind": "HAS_ACCESS_TO", "properties": map[string]any{"risk_weight": 0.2}},
						},
					},
				}, nil
			}
			return nil, nil
		},
	}

	f := &Finding{EdgeKind: "CAN_REACH", SourceID: "agent-1", TargetID: "res-1"}
	path, err := ReconstructAttackPath(context.Background(), mock, f, nil)
	if err != nil {
		t.Fatalf("ReconstructAttackPath() error = %v", err)
	}
	if path == nil {
		t.Fatal("expected path, got nil")
	}
	if len(path.Nodes) != 4 {
		t.Errorf("got %d nodes, want 4", len(path.Nodes))
	}
	if len(path.Edges) != 3 {
		t.Errorf("got %d edges, want 3", len(path.Edges))
	}
}

func TestReconstructAttackPath_CrossProtocol(t *testing.T) {
	triedCrossProtocol := false
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
			if strings.Contains(cypher, "A2AAgent") && strings.Contains(cypher, "DELEGATES_TO") {
				triedCrossProtocol = true
				return []map[string]any{
					{
						"nodes": []any{
							map[string]any{"id": "a2a-1", "name": "ExtAgent", "kinds": []any{"A2AAgent"}, "properties": map[string]any{"name": "ExtAgent"}},
							map[string]any{"id": "res-1", "name": "ProdDB", "kinds": []any{"MCPResource"}, "properties": map[string]any{"name": "ProdDB"}},
						},
						"edges": []any{
							map[string]any{"source": "a2a-1", "target": "res-1", "kind": "DELEGATES_TO", "properties": map[string]any{}},
						},
					},
				}, nil
			}
			return nil, nil
		},
	}

	f := &Finding{EdgeKind: "CAN_REACH", SourceID: "a2a-1", TargetID: "res-1"}
	compositeProps := map[string]any{"cross_protocol": true}
	path, err := ReconstructAttackPath(context.Background(), mock, f, compositeProps)
	if err != nil {
		t.Fatalf("ReconstructAttackPath() error = %v", err)
	}
	if !triedCrossProtocol {
		t.Error("expected cross-protocol query to be tried")
	}
	if path == nil {
		t.Fatal("expected path, got nil")
	}
}

func TestReconstructAttackPath_Fallback(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
			if strings.Contains(cypher, "shortestPath") {
				return []map[string]any{
					{
						"nodes": []any{
							map[string]any{"id": "src-1", "name": "Src", "kinds": []any{"MCPTool"}, "properties": map[string]any{"name": "Src"}},
							map[string]any{"id": "tgt-1", "name": "Tgt", "kinds": []any{"MCPResource"}, "properties": map[string]any{"name": "Tgt"}},
						},
						"edges": []any{
							map[string]any{"source": "src-1", "target": "tgt-1", "kind": "HAS_ACCESS_TO", "properties": map[string]any{}},
						},
					},
				}, nil
			}
			return nil, nil
		},
	}

	f := &Finding{EdgeKind: "CAN_REACH", SourceID: "src-1", TargetID: "tgt-1"}
	path, err := ReconstructAttackPath(context.Background(), mock, f, nil)
	if err != nil {
		t.Fatalf("ReconstructAttackPath() error = %v", err)
	}
	if path == nil {
		t.Fatal("expected fallback path, got nil")
	}
	if len(path.Nodes) != 2 {
		t.Errorf("got %d nodes, want 2", len(path.Nodes))
	}
}

func TestReconstructAttackPath_NoPath(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, _ string, _ map[string]any) ([]map[string]any, error) {
			return nil, nil
		},
	}

	f := &Finding{EdgeKind: "CAN_REACH", SourceID: "src-1", TargetID: "tgt-1"}
	path, err := ReconstructAttackPath(context.Background(), mock, f, nil)
	if err != nil {
		t.Fatalf("ReconstructAttackPath() error = %v", err)
	}
	if path != nil {
		t.Errorf("expected nil path, got %+v", path)
	}
}

func TestParseAttackPath(t *testing.T) {
	row := map[string]any{
		"nodes": []any{
			map[string]any{"id": "n1", "name": "Node1", "kinds": []any{"AgentInstance"}, "properties": map[string]any{"name": "Node1"}},
			map[string]any{"id": "n2", "name": "Node2", "kinds": []any{"MCPServer"}, "properties": map[string]any{"name": "Node2"}},
			map[string]any{"id": "n3", "name": "Node3", "kinds": []any{"MCPTool"}, "properties": map[string]any{"name": "Node3"}},
		},
		"edges": []any{
			map[string]any{"source": "n1", "target": "n2", "kind": "TRUSTS_SERVER", "properties": map[string]any{"risk_weight": 0.1}},
			map[string]any{"source": "n2", "target": "n3", "kind": "PROVIDES_TOOL", "properties": map[string]any{"risk_weight": 0.2}},
		},
	}

	path, err := parseAttackPath(row)
	if err != nil {
		t.Fatalf("parseAttackPath() error = %v", err)
	}
	if path == nil {
		t.Fatal("expected path, got nil")
	}
	if len(path.Nodes) != 3 {
		t.Errorf("got %d nodes, want 3", len(path.Nodes))
	}
	if len(path.Edges) != 2 {
		t.Errorf("got %d edges, want 2", len(path.Edges))
	}
	wantWeight := 0.3
	if path.TotalRiskWeight < wantWeight-0.001 || path.TotalRiskWeight > wantWeight+0.001 {
		t.Errorf("TotalRiskWeight = %f, want ~%f", path.TotalRiskWeight, wantWeight)
	}
}

func TestParseAttackPath_EmptyNodes(t *testing.T) {
	row := map[string]any{
		"nodes": []any{},
		"edges": []any{},
	}
	path, err := parseAttackPath(row)
	if err != nil {
		t.Fatalf("parseAttackPath() error = %v", err)
	}
	if path != nil {
		t.Errorf("expected nil for empty nodes, got %+v", path)
	}
}

func TestParseAttackPath_DuplicateNodes(t *testing.T) {
	row := map[string]any{
		"nodes": []any{
			map[string]any{"id": "n1", "name": "A", "kinds": []any{"MCPServer"}, "properties": map[string]any{}},
			map[string]any{"id": "n1", "name": "A", "kinds": []any{"MCPServer"}, "properties": map[string]any{}},
			map[string]any{"id": "n2", "name": "B", "kinds": []any{"MCPTool"}, "properties": map[string]any{}},
		},
		"edges": []any{
			map[string]any{"source": "n1", "target": "n2", "kind": "PROVIDES_TOOL", "properties": map[string]any{}},
		},
	}

	path, err := parseAttackPath(row)
	if err != nil {
		t.Fatalf("parseAttackPath() error = %v", err)
	}
	if path == nil {
		t.Fatal("expected path, got nil")
	}
	if len(path.Nodes) != 2 {
		t.Errorf("got %d unique nodes, want 2", len(path.Nodes))
	}
}

func TestParsePathNode(t *testing.T) {
	tests := []struct {
		name     string
		input    map[string]any
		wantID   string
		wantKind int
	}{
		{
			name: "complete with kinds as []any",
			input: map[string]any{
				"id":         "node-1",
				"kinds":      []any{"AgentInstance", "Labeled"},
				"properties": map[string]any{"name": "MyAgent"},
			},
			wantID:   "node-1",
			wantKind: 2,
		},
		{
			name: "kinds as []string",
			input: map[string]any{
				"id":         "node-2",
				"kinds":      []string{"MCPServer"},
				"properties": map[string]any{},
			},
			wantID:   "node-2",
			wantKind: 1,
		},
		{
			name:     "missing fields",
			input:    map[string]any{},
			wantID:   "",
			wantKind: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pn := parsePathNode(tt.input)
			if pn.ID != tt.wantID {
				t.Errorf("ID = %q, want %q", pn.ID, tt.wantID)
			}
			if len(pn.Kinds) != tt.wantKind {
				t.Errorf("len(Kinds) = %d, want %d", len(pn.Kinds), tt.wantKind)
			}
		})
	}
}

func TestParsePathEdge(t *testing.T) {
	tests := []struct {
		name       string
		input      map[string]any
		wantSource string
		wantTarget string
		wantKind   string
	}{
		{
			name: "complete",
			input: map[string]any{
				"source":     "src-1",
				"target":     "tgt-1",
				"kind":       "TRUSTS_SERVER",
				"properties": map[string]any{"risk_weight": 0.1},
			},
			wantSource: "src-1",
			wantTarget: "tgt-1",
			wantKind:   "TRUSTS_SERVER",
		},
		{
			name:       "missing fields",
			input:      map[string]any{},
			wantSource: "",
			wantTarget: "",
			wantKind:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pe := parsePathEdge(tt.input)
			if pe.Source != tt.wantSource {
				t.Errorf("Source = %q, want %q", pe.Source, tt.wantSource)
			}
			if pe.Target != tt.wantTarget {
				t.Errorf("Target = %q, want %q", pe.Target, tt.wantTarget)
			}
			if pe.Kind != tt.wantKind {
				t.Errorf("Kind = %q, want %q", pe.Kind, tt.wantKind)
			}
		})
	}
}

func TestFloatFromAny(t *testing.T) {
	tests := []struct {
		name string
		in   any
		want float64
	}{
		{"float64", float64(3.14), 3.14},
		{"int64", int64(42), 42.0},
		{"int", int(7), 7.0},
		{"string defaults to 0", "hello", 0},
		{"nil defaults to 0", nil, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := floatFromAny(tt.in)
			if got != tt.want {
				t.Errorf("floatFromAny(%v) = %f, want %f", tt.in, got, tt.want)
			}
		})
	}
}

func TestBuildImpact_CAN_REACH(t *testing.T) {
	f := &Finding{
		EdgeKind:   "CAN_REACH",
		SourceID:   "agent-1",
		SourceName: "TestAgent",
		TargetID:   "res-1",
		TargetName: "ProdDB",
	}
	path := &AttackPath{
		Nodes: []PathNode{
			{ID: "agent-1", Kinds: []string{"AgentInstance"}, Properties: map[string]any{"name": "TestAgent"}},
			{ID: "res-1", Kinds: []string{"MCPResource"}, Properties: map[string]any{"name": "ProdDB", "sensitivity": "critical"}},
		},
	}

	impact := BuildImpact(f, path, nil)
	if impact == nil {
		t.Fatal("expected impact, got nil")
	}
	if !strings.Contains(impact.Summary, "TestAgent") || !strings.Contains(impact.Summary, "ProdDB") {
		t.Errorf("Summary = %q, expected to contain source and target names", impact.Summary)
	}
	if impact.BlastRadius == "" {
		t.Error("expected non-empty BlastRadius")
	}
	if impact.DataSensitivity != "critical" {
		t.Errorf("DataSensitivity = %q, want critical", impact.DataSensitivity)
	}
}

func TestBuildImpact_CrossProtocol(t *testing.T) {
	f := &Finding{
		EdgeKind:   "CAN_REACH",
		SourceID:   "a2a-1",
		SourceName: "ExtAgent",
		TargetID:   "res-1",
		TargetName: "ProdDB",
	}
	compositeProps := map[string]any{"cross_protocol": true}

	impact := BuildImpact(f, nil, compositeProps)
	if impact == nil {
		t.Fatal("expected impact, got nil")
	}
	if !strings.Contains(impact.Summary, "across protocol boundaries") {
		t.Errorf("Summary = %q, expected cross-protocol template", impact.Summary)
	}
}

func TestBuildImpact_UnknownEdgeKind(t *testing.T) {
	f := &Finding{
		EdgeKind:   "UNKNOWN_EDGE",
		SourceID:   "src-1",
		SourceName: "Src",
		TargetID:   "tgt-1",
		TargetName: "Tgt",
	}

	impact := BuildImpact(f, nil, nil)
	if impact == nil {
		t.Fatal("expected impact, got nil")
	}
	if !strings.Contains(impact.Summary, "UNKNOWN_EDGE") {
		t.Errorf("Summary = %q, expected generic fallback mentioning edge kind", impact.Summary)
	}
	if impact.BlastRadius == "" {
		t.Error("expected non-empty BlastRadius for fallback")
	}
}

func TestBuildImpact_NilPath(t *testing.T) {
	f := &Finding{
		EdgeKind:   "CAN_REACH",
		SourceID:   "agent-1",
		SourceName: "TestAgent",
		TargetID:   "res-1",
		TargetName: "ProdDB",
	}

	impact := BuildImpact(f, nil, nil)
	if impact == nil {
		t.Fatal("expected impact, got nil")
	}
	if impact.DataSensitivity != "" {
		t.Errorf("DataSensitivity = %q, want empty (no path)", impact.DataSensitivity)
	}
	if !strings.Contains(impact.Summary, "TestAgent") {
		t.Errorf("Summary = %q, expected to contain source name", impact.Summary)
	}
}

// TestBuildImpact_BlastRadiusInterpolated guards against the regression
// where BlastRadius leaked literal "%s" placeholders to the UI because
// BuildImpact assigned the template raw instead of running it through
// fmt.Sprintf. Both CAN_REACH templates contain two %s placeholders for
// (srcName, tgtName); a passing test asserts both names interpolate.
func TestBuildImpact_BlastRadiusInterpolated(t *testing.T) {
	cases := []struct {
		name           string
		compositeProps map[string]any
	}{
		{name: "plain CAN_REACH", compositeProps: nil},
		{name: "cross protocol", compositeProps: map[string]any{"cross_protocol": true}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &Finding{
				EdgeKind:   "CAN_REACH",
				SourceID:   "agent-1",
				SourceName: "TestAgent",
				TargetID:   "res-1",
				TargetName: "ProdDB",
			}
			impact := BuildImpact(f, nil, tc.compositeProps)
			if impact == nil {
				t.Fatal("expected impact, got nil")
			}
			if strings.Contains(impact.BlastRadius, "%s") {
				t.Errorf("BlastRadius leaked %%s placeholder: %q", impact.BlastRadius)
			}
			if !strings.Contains(impact.BlastRadius, "TestAgent") {
				t.Errorf("BlastRadius = %q, expected source name to be interpolated", impact.BlastRadius)
			}
			if !strings.Contains(impact.BlastRadius, "ProdDB") {
				t.Errorf("BlastRadius = %q, expected target name to be interpolated", impact.BlastRadius)
			}
		})
	}
}

// TestBuildImpact_PreservesStaticBlastRadius confirms that templates
// without %s placeholders pass through formatBlastRadius unchanged, so
// the helper does not produce Go's "%!(EXTRA ...)" warts on edge kinds
// like CAN_EXECUTE whose BlastRadius is static prose.
func TestBuildImpact_PreservesStaticBlastRadius(t *testing.T) {
	f := &Finding{
		EdgeKind:   "CAN_EXECUTE",
		SourceID:   "tool-1",
		SourceName: "ShellExec",
		TargetID:   "host-1",
		TargetName: "prod-host",
	}
	impact := BuildImpact(f, nil, nil)
	if impact == nil {
		t.Fatal("expected impact, got nil")
	}
	if strings.Contains(impact.BlastRadius, "%") {
		t.Errorf("BlastRadius contains stray %% (Sprintf wart?): %q", impact.BlastRadius)
	}
	if impact.BlastRadius != "Full host compromise is possible through any agent with access to this tool." {
		t.Errorf("BlastRadius template was mutated: %q", impact.BlastRadius)
	}
}

// TestReconstructAttackPath_CredentialChain guards the cross-service
// credential-chain reconstruction added so finding-detail responses no
// longer return null AttackPath for the v0.2 demo's flagship finding.
// The mock returns a credential-chain shaped row only when the cypher
// query is the credential-chain variant; the test asserts that variant
// fires when compositeProps carry source_collector or via_gateway tags.
func TestReconstructAttackPath_CredentialChain(t *testing.T) {
	triedCredentialChain := false
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, _ map[string]any) ([]map[string]any, error) {
			if strings.Contains(cypher, "LiteLLMGateway") && strings.Contains(cypher, "value_hash") {
				triedCredentialChain = true
				return []map[string]any{
					{
						"nodes": []any{
							map[string]any{"id": "agent-1", "name": "DevAgent", "kinds": []any{"AgentInstance"}, "properties": map[string]any{}},
							map[string]any{"id": "srv-1", "name": "Server1", "kinds": []any{"MCPServer"}, "properties": map[string]any{}},
							map[string]any{"id": "c1-1", "name": "OPENAI_API_KEY", "kinds": []any{"Credential"}, "properties": map[string]any{}},
							map[string]any{"id": "c1m-1", "name": "master-key", "kinds": []any{"Credential"}, "properties": map[string]any{}},
							map[string]any{"id": "gw-1", "name": "litellm-gw", "kinds": []any{"LiteLLMGateway"}, "properties": map[string]any{}},
							map[string]any{"id": "c2-1", "name": "openai-upstream", "kinds": []any{"Credential"}, "properties": map[string]any{}},
						},
						"edges": []any{
							map[string]any{"source": "agent-1", "target": "srv-1", "kind": "TRUSTS_SERVER", "properties": map[string]any{}},
							map[string]any{"source": "srv-1", "target": "c1-1", "kind": "HAS_ENV_VAR", "properties": map[string]any{}},
							map[string]any{"source": "gw-1", "target": "c1m-1", "kind": "EXPOSES_CREDENTIAL", "properties": map[string]any{}},
							map[string]any{"source": "gw-1", "target": "c2-1", "kind": "EXPOSES_CREDENTIAL", "properties": map[string]any{}},
							map[string]any{"source": "c1-1", "target": "c1m-1", "kind": "VALUE_HASH_MATCH", "properties": map[string]any{"is_synthetic": true}},
						},
					},
				}, nil
			}
			return nil, nil
		},
	}

	f := &Finding{EdgeKind: "CAN_REACH", SourceID: "agent-1", TargetID: "c2-1"}
	compositeProps := map[string]any{
		"source_collector":  "cross_service_credential_chain",
		"via_gateway":       "litellm-gw",
		"merge_value_hash":  "abcd1234",
		"upstream_provider": "openai",
	}
	path, err := ReconstructAttackPath(context.Background(), mock, f, compositeProps)
	if err != nil {
		t.Fatalf("ReconstructAttackPath() error = %v", err)
	}
	if !triedCredentialChain {
		t.Error("expected credential-chain query to be tried")
	}
	if path == nil {
		t.Fatal("expected reconstructed path, got nil")
	}
	if len(path.Nodes) != 6 {
		t.Errorf("got %d nodes, want 6 (agent, server, c1, c1master, gateway, c2)", len(path.Nodes))
	}
}

// TestBuildImpact_SummaryNoExtraWart guards against the regression
// where Impact.Summary leaked Go's literal "%!(EXTRA string=...)" to
// the UI for edge kinds whose summary template contains fewer than
// two %s placeholders. Before the fix, BuildImpact called
// fmt.Sprintf(tmpl.summary, srcName, tgtName) unconditionally;
// POISONED_DESCRIPTION and POISONED_INSTRUCTIONS only have one %s, so
// the second arg landed in the formatted output as the wart.
func TestBuildImpact_SummaryNoExtraWart(t *testing.T) {
	cases := []struct {
		name     string
		edgeKind string
		srcName  string
		tgtName  string
		wantSrc  bool // template should interpolate srcName
	}{
		{
			name:     "POISONED_DESCRIPTION (1 placeholder)",
			edgeKind: "POISONED_DESCRIPTION",
			srcName:  "MyTool",
			tgtName:  "MyTarget",
			wantSrc:  true,
		},
		{
			name:     "POISONED_INSTRUCTIONS (1 placeholder)",
			edgeKind: "POISONED_INSTRUCTIONS",
			srcName:  "/path/to/CLAUDE.md",
			tgtName:  "agent-1",
			wantSrc:  true,
		},
		{
			name:     "CAN_REACH (2 placeholders)",
			edgeKind: "CAN_REACH",
			srcName:  "TestAgent",
			tgtName:  "ProdDB",
			wantSrc:  true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := &Finding{
				EdgeKind:   tc.edgeKind,
				SourceID:   "src",
				SourceName: tc.srcName,
				TargetID:   "tgt",
				TargetName: tc.tgtName,
			}
			impact := BuildImpact(f, nil, nil)
			if impact == nil {
				t.Fatal("expected impact, got nil")
			}
			if strings.Contains(impact.Summary, "%!(EXTRA") {
				t.Errorf("Summary leaked Sprintf wart: %q", impact.Summary)
			}
			if strings.Contains(impact.Summary, "%s") {
				t.Errorf("Summary leaked %%s placeholder: %q", impact.Summary)
			}
			if tc.wantSrc && !strings.Contains(impact.Summary, tc.srcName) {
				t.Errorf("Summary = %q, expected source name %q to be interpolated", impact.Summary, tc.srcName)
			}
		})
	}
}

// TestBuildImpact_CredentialChain confirms the dedicated impact
// template fires for credential-chain findings instead of the generic
// CAN_REACH template that gives the operator no information about the
// upstream provider exposure.
func TestBuildImpact_CredentialChain(t *testing.T) {
	f := &Finding{
		EdgeKind:   "CAN_REACH",
		SourceID:   "agent-1",
		SourceName: "DevAgent",
		TargetID:   "c2-1",
		TargetName: "openai-upstream",
	}
	compositeProps := map[string]any{
		"source_collector": "cross_service_credential_chain",
	}
	impact := BuildImpact(f, nil, compositeProps)
	if impact == nil {
		t.Fatal("expected impact, got nil")
	}
	if !strings.Contains(impact.Summary, "value_hash") {
		t.Errorf("Summary = %q, expected credential-chain template mentioning value_hash", impact.Summary)
	}
	if !strings.Contains(impact.BlastRadius, "openai-upstream") {
		t.Errorf("BlastRadius = %q, expected upstream credential name to be interpolated", impact.BlastRadius)
	}
	if strings.Contains(impact.BlastRadius, "%s") {
		t.Errorf("BlastRadius leaked placeholder: %q", impact.BlastRadius)
	}
}
