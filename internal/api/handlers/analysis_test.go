package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"

	"github.com/adithyan-ak/agenthound/internal/analysis"
	"github.com/adithyan-ak/agenthound/internal/graph"
	"github.com/go-chi/chi/v5"
)

func TestHandleShortestPath_MissingSource(t *testing.T) {
	h := NewAnalysisHandler(&mockGraphDB{}, nil)
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodPost, "/api/v1/analysis/shortest-path", []byte(`{}`))
	h.HandleShortestPath(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	var resp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error.Code != "VALIDATION_ERROR" {
		t.Fatalf("expected VALIDATION_ERROR, got %s", resp.Error.Code)
	}
}

func TestHandleShortestPath_InvalidKind(t *testing.T) {
	h := NewAnalysisHandler(&mockGraphDB{}, nil)
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodPost, "/api/v1/analysis/shortest-path",
		[]byte(`{"source":"x","source_kind":"INVALID"}`))
	h.HandleShortestPath(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestHandleFindings_Empty(t *testing.T) {
	h := NewAnalysisHandler(&mockGraphDB{queryResult: nil}, nil)
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodGet, "/api/v1/analysis/findings", nil)
	h.HandleFindings(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var findings []any
	if err := json.NewDecoder(w.Body).Decode(&findings); err != nil {
		t.Fatal(err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(findings))
	}
}

func TestHandleListPreBuilt(t *testing.T) {
	h := NewAnalysisHandler(&mockGraphDB{}, nil)
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodGet, "/api/v1/analysis/prebuilt", nil)
	h.HandleListPreBuilt(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var queries []any
	if err := json.NewDecoder(w.Body).Decode(&queries); err != nil {
		t.Fatal(err)
	}
	if len(queries) != 17 {
		t.Fatalf("expected 17 pre-built queries, got %d", len(queries))
	}
}

func TestHandlePreBuilt_NotFound(t *testing.T) {
	h := NewAnalysisHandler(&mockGraphDB{}, nil)
	router := chi.NewRouter()
	router.Get("/api/v1/analysis/prebuilt/{id}", h.HandlePreBuilt)

	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodGet, "/api/v1/analysis/prebuilt/nonexistent-query", nil)
	router.ServeHTTP(w, r)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d", w.Code)
	}
	var resp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error.Code != "NOT_FOUND" {
		t.Fatalf("expected NOT_FOUND, got %s", resp.Error.Code)
	}
}

func TestParseTarget(t *testing.T) {
	tests := []struct {
		name       string
		target     string
		targetKind string
		wantKind   string
		wantName   string
	}{
		{name: "both empty", target: "", targetKind: "", wantKind: "", wantName: ""},
		{name: "colon-separated target", target: "MCPServer:myserver", targetKind: "", wantKind: "MCPServer", wantName: "myserver"},
		{name: "plain target with kind", target: "myserver", targetKind: "MCPServer", wantKind: "MCPServer", wantName: "myserver"},
		{name: "empty target with kind", target: "", targetKind: "MCPServer", wantKind: "MCPServer", wantName: ""},
		{name: "colon target ignored when kind set", target: "MCPServer:myserver", targetKind: "A2AAgent", wantKind: "A2AAgent", wantName: "MCPServer:myserver"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotKind, gotName := parseTarget(tt.target, tt.targetKind)
			if gotKind != tt.wantKind || gotName != tt.wantName {
				t.Errorf("parseTarget(%q, %q) = (%q, %q), want (%q, %q)",
					tt.target, tt.targetKind, gotKind, gotName, tt.wantKind, tt.wantName)
			}
		})
	}
}

func TestIsObjectID(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  bool
	}{
		{name: "valid sha256 hex", value: "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", want: true},
		{name: "with sha256 prefix", value: "sha256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", want: true},
		{name: "human name", value: "claude-desktop", want: false},
		{name: "empty", value: "", want: false},
		{name: "too short hex", value: "a1b2c3", want: false},
		{name: "uppercase hex", value: "A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2C3D4E5F6A1B2", want: false},
		{name: "non-hex chars", value: "g1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2", want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isObjectID(tt.value)
			if got != tt.want {
				t.Errorf("isObjectID(%q) = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}

func TestNodeMatchProp(t *testing.T) {
	if got := nodeMatchProp("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"); got != "objectid" {
		t.Errorf("expected objectid for hex hash, got %s", got)
	}
	if got := nodeMatchProp("claude-desktop"); got != "name" {
		t.Errorf("expected name for human string, got %s", got)
	}
}

func TestClamp(t *testing.T) {
	tests := []struct {
		name       string
		val        int
		min        int
		max        int
		defaultVal int
		want       int
	}{
		{name: "zero returns default", val: 0, min: 1, max: 20, defaultVal: 10, want: 10},
		{name: "in range returns val", val: 5, min: 1, max: 20, defaultVal: 10, want: 5},
		{name: "negative returns default", val: -3, min: 1, max: 20, defaultVal: 10, want: 10},
		{name: "exceeds max clamped", val: 50, min: 1, max: 20, defaultVal: 10, want: 20},
		{name: "below min clamped", val: 1, min: 5, max: 20, defaultVal: 10, want: 5},
		{name: "exactly min", val: 1, min: 1, max: 20, defaultVal: 10, want: 1},
		{name: "exactly max", val: 20, min: 1, max: 20, defaultVal: 10, want: 20},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := clamp(tt.val, tt.min, tt.max, tt.defaultVal)
			if got != tt.want {
				t.Errorf("clamp(%d, %d, %d, %d) = %d, want %d",
					tt.val, tt.min, tt.max, tt.defaultVal, got, tt.want)
			}
		})
	}
}

func TestHandleAllPaths_MissingSource(t *testing.T) {
	h := NewAnalysisHandler(&mockGraphDB{}, nil)
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodPost, "/api/v1/analysis/all-paths", []byte(`{}`))
	h.HandleAllPaths(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	var resp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error.Code != "VALIDATION_ERROR" {
		t.Fatalf("expected VALIDATION_ERROR, got %s", resp.Error.Code)
	}
}

func TestHandleWeightedPath_MissingFields(t *testing.T) {
	h := NewAnalysisHandler(&mockGraphDB{}, nil)
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodPost, "/api/v1/analysis/weighted-path", []byte(`{}`))
	h.HandleWeightedPath(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	var resp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error.Code != "VALIDATION_ERROR" {
		t.Fatalf("expected VALIDATION_ERROR, got %s", resp.Error.Code)
	}
}

// --- HandleFindingDetail tests using graph.MockGraphDB with QueryFunc ---

// findingID for CAN_REACH|src001|tgt001 = SHA256("CAN_REACH|src001|tgt001")[:16] = "9fd26fdabddf168f"
const testFindingID = "9fd26fdabddf168f"

func findingsRow() map[string]any {
	return map[string]any{
		"source_id":          "src001",
		"source_name":        "test-agent",
		"source_kind":        "AgentInstance",
		"target_id":          "tgt001",
		"target_name":        "prod-db",
		"target_kind":        "MCPResource",
		"edge_kind":          "CAN_REACH",
		"confidence":         0.9,
		"cross_protocol":     false,
		"target_sensitivity": "critical",
	}
}

func pathRow() map[string]any {
	return map[string]any{
		"nodes": []any{
			map[string]any{"id": "src001", "name": "test-agent", "kinds": []any{"AgentInstance"}, "properties": map[string]any{}},
			map[string]any{"id": "srv001", "name": "test-server", "kinds": []any{"MCPServer"}, "properties": map[string]any{}},
			map[string]any{"id": "tool001", "name": "test-tool", "kinds": []any{"MCPTool"}, "properties": map[string]any{}},
			map[string]any{"id": "tgt001", "name": "prod-db", "kinds": []any{"MCPResource"}, "properties": map[string]any{}},
		},
		"edges": []any{
			map[string]any{"kind": "TRUSTS_SERVER", "source": "src001", "target": "srv001", "properties": map[string]any{"risk_weight": 0.1}},
			map[string]any{"kind": "PROVIDES_TOOL", "source": "srv001", "target": "tool001", "properties": map[string]any{"risk_weight": 0.1}},
			map[string]any{"kind": "HAS_ACCESS_TO", "source": "tool001", "target": "tgt001", "properties": map[string]any{"risk_weight": 0.2}},
		},
	}
}

func TestHandleFindingDetail_Success(t *testing.T) {
	var callCount atomic.Int32
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, _ string, _ map[string]any) ([]map[string]any, error) {
			n := callCount.Add(1)
			if n == 1 {
				return []map[string]any{findingsRow()}, nil
			}
			if n == 2 {
				return []map[string]any{{"props": map[string]any{"evidence": "test"}}}, nil
			}
			return []map[string]any{pathRow()}, nil
		},
	}
	h := NewAnalysisHandler(mock, nil)
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodGet, "/api/v1/analysis/findings/"+testFindingID, nil)
	r = withChiURLParam(r, "id", testFindingID)
	h.HandleFindingDetail(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp analysis.FindingDetail
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Finding.ID != testFindingID {
		t.Errorf("finding ID: got %q, want %q", resp.Finding.ID, testFindingID)
	}
	if resp.Finding.EdgeKind != "CAN_REACH" {
		t.Errorf("edge kind: got %q, want CAN_REACH", resp.Finding.EdgeKind)
	}
	if resp.AttackPath == nil {
		t.Error("expected non-nil attack_path")
	}
	if resp.Remediation == nil {
		t.Error("expected non-nil remediation")
	}
	if resp.Impact == nil {
		t.Error("expected non-nil impact")
	}
}

func TestHandleFindingDetail_InvalidID_TooShort(t *testing.T) {
	h := NewAnalysisHandler(&mockGraphDB{}, nil)
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodGet, "/api/v1/analysis/findings/abc123", nil)
	r = withChiURLParam(r, "id", "abc123")
	h.HandleFindingDetail(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	var resp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error.Code != "VALIDATION_ERROR" {
		t.Errorf("expected VALIDATION_ERROR, got %s", resp.Error.Code)
	}
}

func TestHandleFindingDetail_InvalidID_NonHex(t *testing.T) {
	h := NewAnalysisHandler(&mockGraphDB{}, nil)
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodGet, "/api/v1/analysis/findings/zzzzzzzzzzzzzzzz", nil)
	r = withChiURLParam(r, "id", "zzzzzzzzzzzzzzzz")
	h.HandleFindingDetail(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	var resp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error.Code != "VALIDATION_ERROR" {
		t.Errorf("expected VALIDATION_ERROR, got %s", resp.Error.Code)
	}
}

func TestHandleFindingDetail_NotFound(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, _ string, _ map[string]any) ([]map[string]any, error) {
			return nil, nil
		},
	}
	h := NewAnalysisHandler(mock, nil)
	w := httptest.NewRecorder()
	validHexID := "aabbccdd11223344"
	r := newTestRequest(http.MethodGet, "/api/v1/analysis/findings/"+validHexID, nil)
	r = withChiURLParam(r, "id", validHexID)
	h.HandleFindingDetail(w, r)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected 404, got %d: %s", w.Code, w.Body.String())
	}
	var resp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error.Code != "NOT_FOUND" {
		t.Errorf("expected NOT_FOUND, got %s", resp.Error.Code)
	}
}

func TestHandleFindingDetail_QueryError(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, _ string, _ map[string]any) ([]map[string]any, error) {
			return nil, errors.New("neo4j connection refused")
		},
	}
	h := NewAnalysisHandler(mock, nil)
	w := httptest.NewRecorder()
	validHexID := "aabbccdd11223344"
	r := newTestRequest(http.MethodGet, "/api/v1/analysis/findings/"+validHexID, nil)
	r = withChiURLParam(r, "id", validHexID)
	h.HandleFindingDetail(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
}
