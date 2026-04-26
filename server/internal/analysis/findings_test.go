package analysis

import (
	"context"
	"errors"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestQueryFindings_AllEdgeKinds(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryResult: []map[string]any{
			{
				"source_id": "agent-1", "source_name": "TestAgent", "source_kind": "AgentInstance",
				"target_id": "tool-1", "target_name": "ExfilTool", "target_kind": "MCPTool",
				"edge_kind": "CAN_EXFILTRATE_VIA", "confidence": 0.8,
				"cross_protocol": false, "target_sensitivity": "",
			},
			{
				"source_id": "agent-1", "source_name": "TestAgent", "source_kind": "AgentInstance",
				"target_id": "res-1", "target_name": "ProdDB", "target_kind": "MCPResource",
				"edge_kind": "CAN_REACH", "confidence": 0.9,
				"cross_protocol": false, "target_sensitivity": "critical",
			},
			{
				"source_id": "tool-1", "source_name": "MalTool", "source_kind": "MCPTool",
				"target_id": "tool-1", "target_name": "MalTool", "target_kind": "MCPTool",
				"edge_kind": "POISONED_DESCRIPTION", "confidence": 1.0,
				"cross_protocol": false, "target_sensitivity": "",
			},
			{
				"source_id": "tool-1", "source_name": "ReadDB", "source_kind": "MCPTool",
				"target_id": "tool-2", "target_name": "OrigDB", "target_kind": "MCPTool",
				"edge_kind": "SHADOWS", "confidence": 0.6,
				"cross_protocol": false, "target_sensitivity": "",
			},
			{
				"source_id": "tool-1", "source_name": "RunCode", "source_kind": "MCPTool",
				"target_id": "host-1", "target_name": "prod-server", "target_kind": "Host",
				"edge_kind": "CAN_EXECUTE", "confidence": 1.0,
				"cross_protocol": false, "target_sensitivity": "",
			},
		},
	}

	findings, err := QueryFindings(context.Background(), mock, "")
	if err != nil {
		t.Fatalf("QueryFindings() error = %v", err)
	}
	if len(findings) != 5 {
		t.Fatalf("got %d findings, want 5", len(findings))
	}

	expected := []struct {
		edgeKind string
		severity string
		category string
	}{
		{"CAN_EXFILTRATE_VIA", "critical", "Data Exfiltration"},
		{"CAN_REACH", "critical", "Transitive Access"},
		{"POISONED_DESCRIPTION", "high", "Prompt Injection"},
		{"SHADOWS", "high", "Tool Shadowing"},
		{"CAN_EXECUTE", "medium", "Remote Execution"},
	}

	for i, exp := range expected {
		f := findings[i]
		if f.EdgeKind != exp.edgeKind {
			t.Errorf("findings[%d].EdgeKind = %q, want %q", i, f.EdgeKind, exp.edgeKind)
		}
		if f.Severity != exp.severity {
			t.Errorf("findings[%d].Severity = %q, want %q", i, f.Severity, exp.severity)
		}
		if f.Category != exp.category {
			t.Errorf("findings[%d].Category = %q, want %q", i, f.Category, exp.category)
		}
		if f.ID == "" {
			t.Errorf("findings[%d].ID is empty", i)
		}
	}
}

func TestQueryFindings_SeverityFilter(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryResult: []map[string]any{
			{
				"source_id": "a1", "source_name": "A", "source_kind": "AgentInstance",
				"target_id": "t1", "target_name": "T", "target_kind": "MCPTool",
				"edge_kind": "CAN_EXFILTRATE_VIA", "confidence": 0.8,
				"cross_protocol": false, "target_sensitivity": "",
			},
			{
				"source_id": "t1", "source_name": "T", "source_kind": "MCPTool",
				"target_id": "h1", "target_name": "H", "target_kind": "Host",
				"edge_kind": "CAN_EXECUTE", "confidence": 1.0,
				"cross_protocol": false, "target_sensitivity": "",
			},
		},
	}

	findings, err := QueryFindings(context.Background(), mock, "critical")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1 (only critical)", len(findings))
	}
	if findings[0].EdgeKind != "CAN_EXFILTRATE_VIA" {
		t.Errorf("EdgeKind = %q", findings[0].EdgeKind)
	}
}

func TestQueryFindings_CrossProtocolCritical(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryResult: []map[string]any{
			{
				"source_id": "ext-1", "source_name": "ExtAgent", "source_kind": "A2AAgent",
				"target_id": "res-1", "target_name": "Secrets", "target_kind": "MCPResource",
				"edge_kind": "CAN_REACH", "confidence": 0.5,
				"cross_protocol": true, "target_sensitivity": "low",
			},
		},
	}

	findings, err := QueryFindings(context.Background(), mock, "")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Severity != "critical" {
		t.Errorf("cross-protocol CAN_REACH severity = %q, want critical", findings[0].Severity)
	}
}

func TestQueryFindings_CanReachHighSensitivity(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryResult: []map[string]any{
			{
				"source_id": "a1", "source_name": "A", "source_kind": "AgentInstance",
				"target_id": "r1", "target_name": "R", "target_kind": "MCPResource",
				"edge_kind": "CAN_REACH", "confidence": 0.5,
				"cross_protocol": false, "target_sensitivity": "high",
			},
		},
	}

	findings, err := QueryFindings(context.Background(), mock, "")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if findings[0].Severity != "high" {
		t.Errorf("severity = %q, want high", findings[0].Severity)
	}
}

func TestQueryFindings_CanReachMediumDefault(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryResult: []map[string]any{
			{
				"source_id": "a1", "source_name": "A", "source_kind": "AgentInstance",
				"target_id": "r1", "target_name": "R", "target_kind": "MCPResource",
				"edge_kind": "CAN_REACH", "confidence": 0.5,
				"cross_protocol": false, "target_sensitivity": "low",
			},
		},
	}

	findings, err := QueryFindings(context.Background(), mock, "")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if findings[0].Severity != "medium" {
		t.Errorf("severity = %q, want medium", findings[0].Severity)
	}
}

func TestQueryFindings_UnknownEdgeKind(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryResult: []map[string]any{
			{
				"source_id": "a1", "source_name": "A", "source_kind": "Node",
				"target_id": "b1", "target_name": "B", "target_kind": "Node",
				"edge_kind": "CUSTOM_EDGE", "confidence": 0.5,
				"cross_protocol": false, "target_sensitivity": "",
			},
		},
	}

	findings, err := QueryFindings(context.Background(), mock, "")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(findings))
	}
	if findings[0].Severity != "low" {
		t.Errorf("severity = %q, want low", findings[0].Severity)
	}
	if findings[0].Category != "Other" {
		t.Errorf("category = %q, want Other", findings[0].Category)
	}
}

func TestQueryFindings_EmptyResult(t *testing.T) {
	mock := &graph.MockGraphDB{QueryResult: nil}

	findings, err := QueryFindings(context.Background(), mock, "")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("got %d findings, want 0", len(findings))
	}
}

func TestQueryFindings_QueryError(t *testing.T) {
	mock := &graph.MockGraphDB{QueryError: errors.New("db error")}

	_, err := QueryFindings(context.Background(), mock, "")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestQueryFindings_MissingTargetNameUsesID(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryResult: []map[string]any{
			{
				"source_id": "a1", "source_name": "A", "source_kind": "AgentInstance",
				"target_id": "res-123", "target_name": nil, "target_kind": "MCPResource",
				"edge_kind": "CAN_REACH", "confidence": 0.5,
				"cross_protocol": false, "target_sensitivity": "",
			},
		},
	}

	findings, err := QueryFindings(context.Background(), mock, "")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(findings) != 1 {
		t.Fatal("expected 1 finding")
	}
	if findings[0].TargetName != "" {
		t.Errorf("TargetName = %q, want empty", findings[0].TargetName)
	}
}

func TestQueryFindings_OWASPMap(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryResult: []map[string]any{
			{
				"source_id": "a1", "source_name": "A", "source_kind": "AgentInstance",
				"target_id": "t1", "target_name": "T", "target_kind": "MCPTool",
				"edge_kind": "CAN_EXFILTRATE_VIA", "confidence": 0.8,
				"cross_protocol": false, "target_sensitivity": "",
			},
		},
	}

	findings, err := QueryFindings(context.Background(), mock, "")
	if err != nil {
		t.Fatalf("error = %v", err)
	}
	if len(findings[0].OWASPMap) != 3 {
		t.Errorf("OWASPMap len = %d, want 3", len(findings[0].OWASPMap))
	}
}

func TestClassifySeverity(t *testing.T) {
	tests := []struct {
		name              string
		edgeKind          string
		crossProtocol     bool
		confidence        float64
		targetSensitivity string
		want              string
	}{
		{"exfiltrate always critical", "CAN_EXFILTRATE_VIA", false, 0.5, "", "critical"},
		{"reach cross-protocol", "CAN_REACH", true, 0.5, "low", "critical"},
		{"reach high-confidence critical resource", "CAN_REACH", false, 0.9, "critical", "critical"},
		{"reach high resource", "CAN_REACH", false, 0.5, "high", "high"},
		{"reach default medium", "CAN_REACH", false, 0.5, "low", "medium"},
		{"poisoned desc high", "POISONED_DESCRIPTION", false, 1.0, "", "high"},
		{"shadows high", "SHADOWS", false, 0.6, "", "high"},
		{"poisoned instr high", "POISONED_INSTRUCTIONS", false, 1.0, "", "high"},
		{"impersonate medium", "CAN_IMPERSONATE", false, 0.8, "", "medium"},
		{"execute medium", "CAN_EXECUTE", false, 1.0, "", "medium"},
		{"has_access_to medium", "HAS_ACCESS_TO", false, 0.7, "", "medium"},
		{"unknown low", "CUSTOM", false, 0.5, "", "low"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifySeverity(tt.edgeKind, tt.crossProtocol, tt.confidence, tt.targetSensitivity)
			if got != tt.want {
				t.Errorf("classifySeverity() = %q, want %q", got, tt.want)
			}
		})
	}
}
