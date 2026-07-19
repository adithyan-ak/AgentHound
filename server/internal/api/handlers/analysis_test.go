package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
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

type fakePublishedFindingStore struct {
	recordingFindingLister
	scope   appdb.FindingScope
	finding *model.Finding
	listErr error
	getErr  error
}

func (m *fakePublishedFindingStore) ListPublished(
	_ context.Context,
	severity string,
	includeSuppressed bool,
) ([]model.Finding, appdb.FindingScope, error) {
	m.gotSeverity = severity
	m.gotSuppressed = includeSuppressed
	return m.findings, m.scope, m.listErr
}

func (m *fakePublishedFindingStore) GetPublished(
	_ context.Context,
	_ string,
) (*model.Finding, appdb.FindingScope, error) {
	return m.finding, m.scope, m.getErr
}

func TestHandleFindings_SuppressedHiddenByDefault(t *testing.T) {
	mock := &fakePublishedFindingStore{
		recordingFindingLister: recordingFindingLister{
			findings: []model.Finding{{ID: "aaaaaaaaaaaaaaaa", Severity: "high"}},
		},
	}
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
	mock := &fakePublishedFindingStore{}
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
	mock := &fakePublishedFindingStore{}
	h := &AnalysisHandler{findingStore: mock}
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodGet, "/api/v1/analysis/findings?severity=critical", nil)
	h.HandleFindings(w, r)

	if mock.gotSeverity != "critical" {
		t.Errorf("severity filter not forwarded: got %q", mock.gotSeverity)
	}
}

func TestHandleFindingsRejectsScopeParameter(t *testing.T) {
	h := &AnalysisHandler{findingStore: &fakePublishedFindingStore{}}
	w := httptest.NewRecorder()
	r := newTestRequest(
		http.MethodGet,
		"/api/v1/analysis/findings?scope=history",
		nil,
	)

	h.HandleFindings(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", w.Code, w.Body.String())
	}
}

func TestHandleFindings_PublishedScopeIsExactAndAttributed(t *testing.T) {
	revision := int64(9)
	store := &fakePublishedFindingStore{
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
		"/api/v1/analysis/findings?severity=high",
		nil,
	)

	h.HandleFindings(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	if store.gotSeverity != "high" {
		t.Fatalf("severity = %q, want high", store.gotSeverity)
	}
	var response struct {
		Scope appdb.FindingScope `json:"scope"`
	}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Scope.ScanID != "scan-published" || !response.Scope.Stale {
		t.Fatalf("scope = %+v", response.Scope)
	}
}

func TestHandleFindingsSerializesVerificationMetadata(t *testing.T) {
	store := &fakePublishedFindingStore{
		recordingFindingLister: recordingFindingLister{findings: []model.Finding{{
			ID: "aaaaaaaaaaaaaaaa",
			Evidence: model.FindingEvidence{
				State: model.FindingEvidenceVerified,
				Verification: &model.FindingVerification{
					ScenarioID: "cred-reach", ScenarioVersion: 1,
					CampaignRunID: "run-api", VerifiedAt: "2026-07-13T12:00:00Z",
					OracleType:   "differential_credential_reach",
					Outcome:      "credential_gated_reach_verified",
					ControlStage: "initialize", ControlStatus: "denied",
					AuthedStage: "resource_read", AuthedStatus: "allowed",
					AuthedResourceAddressed: true, CleanupStatus: "not_applicable",
				},
			},
		}}},
	}
	h := &AnalysisHandler{findingStore: store}
	w := httptest.NewRecorder()
	h.HandleFindings(w, newTestRequest(http.MethodGet, "/api/v1/analysis/findings", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var response struct {
		Findings []model.Finding `json:"findings"`
	}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if len(response.Findings) != 1 ||
		response.Findings[0].Evidence.Verification == nil ||
		response.Findings[0].Evidence.Verification.CampaignRunID != "run-api" ||
		response.Findings[0].Evidence.Verification.CleanupStatus != "not_applicable" {
		t.Fatalf("verification API round-trip = %+v", response.Findings)
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

func TestHandleShortestPathRejectsScopeCompatibilityField(t *testing.T) {
	h := NewAnalysisHandler(&mockGraphDB{}, nil)
	w := httptest.NewRecorder()
	r := newTestRequest(
		http.MethodPost,
		"/api/v1/analysis/shortest-path",
		[]byte(`{"source":"x","source_kind":"MCPServer","scope":"topology"}`),
	)
	h.HandleShortestPath(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400: %s", w.Code, w.Body.String())
	}
}

func TestHandleShortestPathRejectsUpdatingProjectionBeforeEndpointResolution(t *testing.T) {
	mock := &graph.MockGraphDB{}
	h := &AnalysisHandler{
		graphDB: mock,
		projectionReader: &fakeProjectionStateReader{
			states: []*model.ProjectionState{{Status: model.ProjectionUpdating}},
		},
	}
	w := httptest.NewRecorder()
	r := newTestRequest(
		http.MethodPost,
		"/api/v1/analysis/shortest-path",
		[]byte(`{"source":"A","source_kind":"AgentInstance","target":"T","target_kind":"MCPResource"}`),
	)

	h.HandleShortestPath(w, r)

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", w.Code, w.Body.String())
	}
	if len(mock.CallsTo("Query")) != 0 {
		t.Fatal("endpoint resolution queried the graph while projection was updating")
	}
}

func TestHandleFindings_Empty(t *testing.T) {
	h := &AnalysisHandler{findingStore: &fakePublishedFindingStore{}}
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodGet, "/api/v1/analysis/findings", nil)
	h.HandleFindings(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var response struct {
		Findings []any `json:"findings"`
	}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if len(response.Findings) != 0 {
		t.Fatalf("expected 0 findings, got %d", len(response.Findings))
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

func TestHandlePreBuiltRejectsUnreadableProjectionBeforeGraphQuery(t *testing.T) {
	mismatched := completeProjectionState("published-scan", 7)
	mismatched.ScanID = "updating-scan"
	dirty := completeProjectionState("published-scan", 7)
	dirty.DirtyCoverage = []string{"mcp:root:sha256:dirty"}
	for _, test := range []struct {
		name  string
		state *model.ProjectionState
	}{
		{name: "absent", state: nil},
		{name: "updating", state: &model.ProjectionState{Status: model.ProjectionUpdating}},
		{name: "incomplete", state: &model.ProjectionState{Status: model.ProjectionIncomplete}},
		{name: "complete but not current publication", state: mismatched},
		{name: "complete but dirty", state: dirty},
	} {
		t.Run(test.name, func(t *testing.T) {
			mock := &graph.MockGraphDB{QueryResult: []map[string]any{{"server_name": "server"}}}
			h := &AnalysisHandler{
				graphDB: mock,
				projectionReader: &fakeProjectionStateReader{
					states: []*model.ProjectionState{test.state},
				},
			}
			w := httptest.NewRecorder()
			r := withChiURLParam(
				newTestRequest(http.MethodGet, "/api/v1/analysis/prebuilt/no-auth-servers", nil),
				"id",
				"no-auth-servers",
			)

			h.HandlePreBuilt(w, r)

			if w.Code != http.StatusConflict {
				t.Fatalf("status = %d, want 409: %s", w.Code, w.Body.String())
			}
			if len(mock.CallsTo("Query")) != 0 {
				t.Fatal("graph query ran for an unreadable projection")
			}
		})
	}
}

func TestHandlePreBuiltRejectsProjectionChangeDuringRead(t *testing.T) {
	mock := &graph.MockGraphDB{QueryResult: []map[string]any{{"server_name": "server"}}}
	h := &AnalysisHandler{
		graphDB: mock,
		projectionReader: &fakeProjectionStateReader{
			states: []*model.ProjectionState{
				completeProjectionState("scan-1", 7),
				completeProjectionState("scan-2", 8),
			},
		},
	}
	w := httptest.NewRecorder()
	r := withChiURLParam(
		newTestRequest(http.MethodGet, "/api/v1/analysis/prebuilt/no-auth-servers", nil),
		"id",
		"no-auth-servers",
	)

	h.HandlePreBuilt(w, r)

	if w.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", w.Code, w.Body.String())
	}
	var response ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Error.Code != "PROJECTION_CONFLICT" {
		t.Fatalf("error code = %q", response.Error.Code)
	}
}

func TestHandlePreBuiltReturnsStableProjectionIdentity(t *testing.T) {
	mock := &graph.MockGraphDB{QueryResult: []map[string]any{{"server_name": "server"}}}
	h := newStableAnalysisHandler(mock)
	w := httptest.NewRecorder()
	r := withChiURLParam(
		newTestRequest(http.MethodGet, "/api/v1/analysis/prebuilt/no-auth-servers", nil),
		"id",
		"no-auth-servers",
	)

	h.HandlePreBuilt(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	var response struct {
		Projection projectionIdentity `json:"projection"`
	}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Projection != (projectionIdentity{ScanID: "scan-1", Revision: 1}) {
		t.Fatalf("projection = %+v", response.Projection)
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
	h := newStableAnalysisHandler(mock)
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodPost, "/api/v1/analysis/weighted-path", []byte(
		`{"source":"A","source_kind":"AgentInstance","target":"T","target_kind":"MCPResource","max_hops":2}`,
	))

	h.HandleWeightedPath(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", w.Code, w.Body.String())
	}
	var response struct {
		Paths    []analysis.TraversalPath   `json:"paths"`
		Metadata analysis.TraversalMetadata `json:"metadata"`
	}
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if len(response.Paths) != 1 || response.Paths[0].Weight != 0.2 {
		t.Fatalf("paths = %+v, want minimum weight 0.2", response.Paths)
	}
	if response.Metadata.Algorithm != "bounded-min-weight" ||
		response.Metadata.Scope != analysis.TraversalScopeSecurity ||
		response.Metadata.Direction != "out" {
		t.Fatalf("metadata = %+v", response.Metadata)
	}
	if len(mock.CallsTo("HasAPOC")) != 0 {
		t.Fatal("weighted traversal must be independent of APOC availability")
	}
}

func TestHandleTopologyShortestPathUsesExplicitUndirectedOperation(t *testing.T) {
	mock := &graph.MockGraphDB{
		QueryFunc: func(_ context.Context, cypher string, params map[string]any) ([]map[string]any, error) {
			if strings.Contains(cypher, "traversal:resolve") {
				value, _ := params["value"].(string)
				return []map[string]any{{
					"id": value, "name": value,
					"kinds":      []any{"AgentInstance"},
					"properties": map[string]any{"objectid": value, "name": value},
				}}, nil
			}
			if params["relationship_kinds"] != nil {
				t.Fatal("topology operation must not apply the security relationship policy")
			}
			return []map[string]any{
				traversalAdjacencyRow("A", "T", "RUNS_ON", 0.4),
			}, nil
		},
	}
	h := newStableAnalysisHandler(mock)
	w := httptest.NewRecorder()
	r := newTestRequest(
		http.MethodPost,
		"/api/v1/analysis/topology/shortest-path",
		[]byte(`{"source":"A","source_kind":"AgentInstance","target":"T","target_kind":"Host","max_hops":1}`),
	)

	h.HandleTopologyShortestPath(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var response analysis.TraversalResult
	if err := json.NewDecoder(w.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Metadata.Scope != analysis.TraversalScopeTopology ||
		response.Metadata.Direction != "both" {
		t.Fatalf("metadata = %+v", response.Metadata)
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

// findingID for CAN_REACH|src001|tgt001 = SHA256("CAN_REACH|src001|tgt001")[:16] = "9fd26fdabddf168f"
const testFindingID = "9fd26fdabddf168f"

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
	store := &fakePublishedFindingStore{
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
		"/api/v1/analysis/findings/"+testFindingID,
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
		response.Snapshot.EvidenceState != "persisted_exact_evidence" ||
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
	h := &AnalysisHandler{findingStore: &fakePublishedFindingStore{}}
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
	h := &AnalysisHandler{findingStore: &fakePublishedFindingStore{
		getErr: errors.New("postgres connection refused"),
	}}
	w := httptest.NewRecorder()
	validHexID := "aabbccdd11223344"
	r := newTestRequest(http.MethodGet, "/api/v1/analysis/findings/"+validHexID, nil)
	r = withChiURLParam(r, "id", validHexID)
	h.HandleFindingDetail(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d: %s", w.Code, w.Body.String())
	}
}
