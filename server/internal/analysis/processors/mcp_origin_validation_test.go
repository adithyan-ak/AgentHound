package processors

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

func TestMCPOriginValidationBuildsFindingEdgeOnlyFromAcceptedProof(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteResult: 1}
	processor := &MCPOriginValidation{}
	stats, err := processor.Process(context.Background(), mock, "scan-1")
	if err != nil {
		t.Fatalf("Process: %v", err)
	}
	if processor.Name() != "mcp_origin_validation" || processor.Dependencies() != nil {
		t.Fatalf("processor contract = %q, %v", processor.Name(), processor.Dependencies())
	}
	if stats.ProcessorName != processor.Name() || stats.EdgesCreated != 1 {
		t.Fatalf("stats = %+v", stats)
	}
	calls := mock.CallsTo("ExecuteWrite")
	if len(calls) != 1 {
		t.Fatalf("ExecuteWrite calls = %d", len(calls))
	}
	query, _ := calls[0].Args[0].(string)
	for _, required := range []string{
		"origin_validation_status = 'accepted'",
		"matching_jsonrpc_response",
		"session_allocated",
		"MCP_ORIGIN_VALIDATION_FAILED",
		"evidence_node_ids = [s.objectid]",
	} {
		if !strings.Contains(query, required) {
			t.Errorf("processor query missing %q: %s", required, query)
		}
	}
}

func TestMCPOriginValidationPropagatesWriteError(t *testing.T) {
	mock := &graph.MockGraphDB{ExecuteWriteError: errors.New("write failed")}
	stats, err := (&MCPOriginValidation{}).Process(context.Background(), mock, "scan-1")
	if err == nil || stats.ProcessorName != "mcp_origin_validation" {
		t.Fatalf("stats=%+v error=%v", stats, err)
	}
}
