package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/adithyan-ak/agenthound/server/model"
	"github.com/go-chi/chi/v5"
)

type mockGraphDB struct {
	queryResult []map[string]any
	queryErr    error
	writeCount  int
	writeErr    error
	hasAPOCVal  bool
}

func (m *mockGraphDB) Query(_ context.Context, _ string, _ map[string]any) ([]map[string]any, error) {
	return m.queryResult, m.queryErr
}

func (m *mockGraphDB) WriteCompositeEdges(_ context.Context, _ []ingest.Edge, _ string) (int, error) {
	return m.writeCount, m.writeErr
}

func (m *mockGraphDB) UpdateNodeProperties(_ context.Context, _ string, _ map[string]any) error {
	return nil
}

func (m *mockGraphDB) ExecuteWrite(_ context.Context, _ string, _ map[string]any) (int, error) {
	return m.writeCount, m.writeErr
}

func (m *mockGraphDB) GetNode(_ context.Context, _ string) (*ingest.Node, []ingest.Edge, error) {
	return nil, nil, nil
}

func (m *mockGraphDB) ListNodes(_ context.Context, _ string, _ int) ([]ingest.Node, error) {
	return nil, nil
}

func (m *mockGraphDB) ListNodesPage(_ context.Context, _ string, _, _ int, _ string) ([]ingest.Node, graph.PageInfo, error) {
	return nil, graph.PageInfo{Complete: true}, nil
}

func (m *mockGraphDB) GetStats(_ context.Context) (*graph.GraphStats, error) {
	return &graph.GraphStats{
		NodeCounts: map[string]int64{},
		EdgeCounts: map[string]int64{},
	}, nil
}

func (m *mockGraphDB) HasAPOC(_ context.Context) bool {
	return m.hasAPOCVal
}

type fakeProjectionStateReader struct {
	states []*model.ProjectionState
	err    error
	calls  int
}

func (f *fakeProjectionStateReader) GetProjectionState(
	_ context.Context,
) (*model.ProjectionState, error) {
	if f.err != nil {
		return nil, f.err
	}
	if len(f.states) == 0 {
		return nil, nil
	}
	index := f.calls
	if index >= len(f.states) {
		index = len(f.states) - 1
	}
	f.calls++
	return f.states[index], nil
}

func completeProjectionState(scanID string, revision int64) *model.ProjectionState {
	return &model.ProjectionState{
		Status:            model.ProjectionComplete,
		ScanID:            scanID,
		PublishedScanID:   scanID,
		PublishedRevision: &revision,
		DirtyCoverage:     []string{},
	}
}

func newStableAnalysisHandler(db graph.GraphDB) *AnalysisHandler {
	return &AnalysisHandler{
		graphDB: db,
		projectionReader: &fakeProjectionStateReader{
			states: []*model.ProjectionState{completeProjectionState("scan-1", 1)},
		},
	}
}

func newTestRequest(method, path string, body []byte) *http.Request {
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func withChiURLParam(r *http.Request, key, val string) *http.Request {
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add(key, val)
	return r.WithContext(context.WithValue(r.Context(), chi.RouteCtxKey, rctx))
}
