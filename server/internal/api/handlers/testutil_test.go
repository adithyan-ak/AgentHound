package handlers

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
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

func (m *mockGraphDB) WriteEdges(_ context.Context, _ []ingest.Edge, _ string) (int, error) {
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

func (m *mockGraphDB) HasAPOC(_ context.Context) bool {
	return m.hasAPOCVal
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
