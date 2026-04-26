package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

// TestCypherInjectionViaNodeKind is a regression: source_kind is interpolated
// into the Cypher string, so any value not in the AllowedNodeKinds whitelist
// must be rejected before reaching the database.
func TestCypherInjectionViaNodeKind(t *testing.T) {
	injections := []string{
		"MCPServer' OR 1=1--",
		"MCPServer}) RETURN n;//",
		"MCPServer UNION ALL MATCH (n) RETURN n",
		"MCPServer`+String.fromCharCode(96)+`",
		"MCPServer DETACH DELETE n",
	}

	mock := &graph.MockGraphDB{}
	h := NewAnalysisHandler(mock)

	for _, kind := range injections {
		t.Run(kind, func(t *testing.T) {
			body := `{"source":"test","source_kind":"` + kind + `","target":"x","target_kind":"MCPTool"}`
			req := httptest.NewRequest(http.MethodPost, "/api/v1/analysis/shortest-path", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()

			h.HandleShortestPath(rec, req)

			if rec.Code != http.StatusBadRequest {
				t.Errorf("injection %q: status = %d, want %d", kind, rec.Code, http.StatusBadRequest)
			}
			if !strings.Contains(rec.Body.String(), "invalid source_kind") {
				t.Errorf("injection %q: body should contain 'invalid source_kind', got %s", kind, rec.Body.String())
			}
		})
	}

	calls := mock.CallsTo("Query")
	if len(calls) > 0 {
		t.Errorf("GraphDB.Query called %d times — injection attempts should be blocked before reaching the database", len(calls))
	}
}

func TestValidNodeKindRejectsArbitraryStrings(t *testing.T) {
	invalid := []string{
		"",
		"NotANode",
		"mcpserver",
		"DROP TABLE",
		"MCPServer; MATCH",
	}
	for _, kind := range invalid {
		if validNodeKind(kind) {
			t.Errorf("validNodeKind(%q) = true, want false", kind)
		}
	}
}

func TestValidNodeKindAcceptsAllLabels(t *testing.T) {
	for _, label := range []string{
		"MCPServer", "MCPTool", "MCPResource", "MCPPrompt",
		"A2AAgent", "A2ASkill", "AgentInstance",
		"Identity", "Credential", "Host",
		"ConfigFile", "InstructionFile",
		"ResourceGroup", "TrustZone",
	} {
		if !validNodeKind(label) {
			t.Errorf("validNodeKind(%q) = false, want true", label)
		}
	}
}

func TestCypherInjectionViaTargetKind(t *testing.T) {
	mock := &graph.MockGraphDB{}
	h := NewAnalysisHandler(mock)

	body := `{"source":"test","source_kind":"MCPServer","target":"x","target_kind":"MCPTool' OR 1=1--"}`
	req := httptest.NewRequest(http.MethodPost, "/api/v1/analysis/shortest-path", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.HandleShortestPath(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if !strings.Contains(rec.Body.String(), "invalid target_kind") {
		t.Errorf("body should contain 'invalid target_kind', got %s", rec.Body.String())
	}

	if len(mock.CallsTo("Query")) > 0 {
		t.Error("GraphDB.Query should not be called when target_kind is invalid")
	}
}
