package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/analysis"
	"github.com/adithyan-ak/agenthound/server/internal/appdb"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/adithyan-ak/agenthound/server/model"
	"github.com/go-chi/chi/v5"
)

// recordingFindingLister captures the args HandleFindings forwards to the
// snapshot store so the ?include_suppressed / ?severity plumbing can be
// asserted at the handler layer without a database.
type recordingFindingLister struct {
	gotSeverity   string
	gotSuppressed bool
	findings      []model.Finding
}

func (m *recordingFindingLister) ListLatestPerFingerprint(_ context.Context, severity string, includeSuppressed bool) ([]model.Finding, error) {
	m.gotSeverity = severity
	m.gotSuppressed = includeSuppressed
	return m.findings, nil
}

type publishedFindingStore struct {
	recordingFindingLister
	scope   appdb.FindingScope
	finding *model.Finding
}

func (m *publishedFindingStore) ListPublished(
	_ context.Context,
	severity string,
	includeSuppressed bool,
) ([]model.Finding, appdb.FindingScope, error) {
	m.gotSeverity = severity
	m.gotSuppressed = includeSuppressed
	return m.findings, m.scope, nil
}

func (m *publishedFindingStore) GetPublished(
	_ context.Context,
	_ string,
) (*model.Finding, appdb.FindingScope, error) {
	return m.finding, m.scope, nil
}

func TestHandleFindings_SuppressedHiddenByDefault(t *testing.T) {
	mock := &recordingFindingLister{findings: []model.Finding{{ID: "aaaaaaaaaaaaaaaa", Severity: "high"}}}
	h := &AnalysisHandler{findingStore: mock}
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodGet, "/api/v1/analysis/findings", nil)
	h.HandleFindings(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if mock.gotSuppressed {
		t.Error("default findings request must pass includeSuppressed=false")
	}
}

func TestHandleFindings_IncludeSuppressedTrue(t *testing.T) {
	mock := &recordingFindingLister{}
	h := &AnalysisHandler{findingStore: mock}
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodGet, "/api/v1/analysis/findings?include_suppressed=true", nil)
	h.HandleFindings(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if !mock.gotSuppressed {
		t.Error("?include_suppressed=true must pass includeSuppressed=true to the store")
	}
}

func TestHandleFindings_SeverityForwarded(t *testing.T) {
	mock := &recordingFindingLister{}
	h := &AnalysisHandler{findingStore: mock}
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodGet, "/api/v1/analysis/findings?severity=critical", nil)
	h.HandleFindings(w, r)

	if mock.gotSeverity != "critical" {
		t.Errorf("severity filter not forwarded: got %q", mock.gotSeverity)
	}
}

func TestHandleFindings_PublishedScopeIsExactAndAttributed(t *testing.T) {
	revision := int64(9)
	store := &publishedFindingStore{
		recordingFindingLister: recordingFindingLister{
			findings: []model.Finding{{ID: "aaaaaaaaaaaaaaaa", ScanID: "scan-published"}},
		},
		scope: appdb.FindingScope{
			Mode:             "published",
			ScanID:           "scan-published",
			Revision:         &revision,
			ProjectionStatus: model.ProjectionIncomplete,
			SnapshotStatus:   model.LifecycleComplete,
			Available:        true,
			Stale:            true,
		},
	}
	h := &AnalysisHandler{findingStore: store}
	w := httptest.NewRecorder()
	r := newTestRequest(
		http.MethodGet,
		"/api/v1/analysis/findings?scope=published&severity=high",
		nil,
	)

	h.HandleFindings(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	if store.gotSeverity != "high" {
		t.Fatalf("severity = %q, want high", store.gotSeverity)
	}
	if got := w.Header().Get("X-Snapshot-Scan-ID"); got != "scan-published" {
		t.Fatalf("X-Snapshot-Scan-ID = %q", got)
	}
	if got := w.Header().Get("X-Snapshot-Stale"); got != "true" {
		t.Fatalf("X-Snapshot-Stale = %q", got)
	}
}

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
	if len(queries) != 19 {
		t.Fatalf("expected 19 pre-built queries, got %d", len(queries))
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

func TestHandleWeightedPath_UsesBoundedDirectedMinimumWeight(t *testing.T) {
	mock := &graph.MockGraphDB{
		HasAPOCResult: true,
		QueryFunc: func(_ context.Context, cypher string, params map[string]any) ([]map[string]any, error) {
			if strings.Contains(cypher, "traversal:resolve") {
				value, _ := params["value"].(string)
				return []map[string]any{{
					"id": value, "name": value,
					"kinds":      []any{"AgentInstance"},
					"properties": map[string]any{"objectid": value, "name": value},
				}}, nil
			}
			if !strings.Contains(cypher, "traversal:adjacency") {
				t.Fatalf("unexpected query: %s", cypher)
			}
			if params["relationship_kinds"] == nil {
				t.Fatal("security traversal must send an explicit relationship scope")
			}
			ids, _ := params["ids"].([]string)
			rows := make([]map[string]any, 0)
			for _, id := range ids {
				switch id {
				case "A":
					rows = append(rows,
						traversalAdjacencyRow("A", "T", "HAS_ACCESS_TO", 0.9),
						traversalAdjacencyRow("A", "B", "PROVIDES_TOOL", 0.1),
					)
				case "B":
					rows = append(rows, traversalAdjacencyRow("B", "T", "HAS_ACCESS_TO", 0.1))
				}
			}
			return rows, nil
		},
	}
	h := NewAnalysisHandler(mock, nil)
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodPost, "/api/v1/analysis/weighted-path", []byte(
		`{"source":"A","source_kind":"AgentInstance","target":"T","target_kind":"MCPResource","scope":"security","max_hops":2}`,
	))

	h.HandleWeightedPath(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	var response struct {
		Paths     []analysis.TraversalPath   `json:"paths"`
		Algorithm string                     `json:"algorithm"`
		Metadata  analysis.TraversalMetadata `json:"metadata"`
	}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if len(response.Paths) != 1 || response.Paths[0].Weight != 0.2 {
		t.Fatalf("paths = %+v, want minimum weight 0.2", response.Paths)
	}
	if response.Algorithm != "bounded-min-weight" ||
		response.Metadata.Scope != analysis.TraversalScopeSecurity ||
		response.Metadata.Direction != "out" {
		t.Fatalf("metadata = %+v, algorithm = %q", response.Metadata, response.Algorithm)
	}
	if len(mock.CallsTo("HasAPOC")) != 0 {
		t.Fatal("weighted traversal must be independent of APOC availability")
	}
}

func traversalAdjacencyRow(source, target, kind string, weight float64) map[string]any {
	return map[string]any{
		"traversal_source": source,
		"traversal_target": target,
		"next_id":          target,
		"next_name":        target,
		"next_kinds":       []any{"MCPResource"},
		"next_properties":  map[string]any{"objectid": target, "name": target},
		"source":           source,
		"target":           target,
		"kind":             kind,
		"risk_weight":      weight,
	}
}

// --- HandleFindingDetail tests using graph.MockGraphDB with QueryFunc ---

// findingID for CAN_REACH|src001|tgt001 = SHA256("CAN_REACH|src001|tgt001")[:16] = "9fd26fdabddf168f"
const testFindingID = "9fd26fdabddf168f"

func findingsRow() map[string]any {
	evidence := pathRow()
	return map[string]any{
		"source_id":            "src001",
		"source_name":          "test-agent",
		"source_kind":          "AgentInstance",
		"target_id":            "tgt001",
		"target_name":          "prod-db",
		"target_kind":          "MCPResource",
		"edge_kind":            "CAN_REACH",
		"confidence":           0.9,
		"cross_protocol":       false,
		"target_sensitivity":   "critical",
		"evidence_version":     int64(1),
		"exact_evidence_nodes": evidence["nodes"],
		"exact_evidence_edges": evidence["edges"],
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
	if callCount.Load() != 1 {
		t.Fatalf("detail queried mutable graph %d times, want one detector finding query", callCount.Load())
	}
}

func TestHandleFindingDetail_PublishedRowSurvivesMissingLiveEdge(t *testing.T) {
	revision := int64(12)
	persisted := &model.Finding{
		ID:         testFindingID,
		ScanID:     "scan-published",
		Severity:   "high",
		Category:   "Transitive Access",
		Title:      "persisted finding",
		EdgeKind:   "CAN_REACH",
		SourceID:   "src001",
		TargetID:   "tgt001",
		Confidence: 0.9,
		ExactEvidence: &model.ExactFindingEvidence{
			Version:  1,
			Complete: true,
			Reasons:  []string{},
			Nodes: []model.ExactFindingEvidenceNode{
				{ID: "src001", Kinds: []string{"AgentInstance"}, Properties: map[string]any{"name": "source"}},
				{ID: "tgt001", Kinds: []string{"MCPResource"}, Properties: map[string]any{"name": "target"}},
			},
			Edges: []model.ExactFindingEvidenceEdge{{
				Source: "src001", Target: "tgt001", Kind: "CAN_REACH",
				Properties: map[string]any{"risk_weight": 0.1},
			}},
		},
	}
	store := &publishedFindingStore{
		scope: appdb.FindingScope{
			Mode:             "published",
			ScanID:           "scan-published",
			Revision:         &revision,
			ProjectionStatus: model.ProjectionIncomplete,
			SnapshotStatus:   model.LifecycleComplete,
			Available:        true,
			Stale:            true,
		},
		finding: persisted,
	}
	liveGraph := &graph.MockGraphDB{QueryError: errors.New("stale graph must not be read")}
	h := &AnalysisHandler{
		graphDB:      liveGraph,
		findingStore: store,
	}
	w := httptest.NewRecorder()
	r := newTestRequest(
		http.MethodGet,
		"/api/v1/analysis/findings/"+testFindingID+"?scope=published",
		nil,
	)
	r = withChiURLParam(r, "id", testFindingID)

	h.HandleFindingDetail(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var response analysis.FindingDetail
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Finding.Title != "persisted finding" {
		t.Fatalf("detail did not start from persisted row: %+v", response.Finding)
	}
	if response.AttackPath == nil || len(response.AttackPath.Edges) != 1 {
		t.Fatalf("persisted exact evidence was not served: %+v", response.AttackPath)
	}
	if response.Snapshot == nil ||
		response.Snapshot.LiveEvidenceState != "persisted_exact_evidence" ||
		!response.Snapshot.Stale {
		t.Fatalf("snapshot metadata = %+v", response.Snapshot)
	}
	if len(liveGraph.CallsTo("Query")) != 0 {
		t.Fatal("stale published detail must not attach mutable live evidence")
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
