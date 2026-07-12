package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/adithyan-ak/agenthound/server/model"
)

type fakeGraphReader struct {
	stats      *graph.GraphStats
	nodes      []ingest.Node
	nodePage   graph.PageInfo
	statsCalls int
	nodeCalls  int
}

func (f *fakeGraphReader) GetStats(context.Context) (*graph.GraphStats, error) {
	f.statsCalls++
	return f.stats, nil
}

func (f *fakeGraphReader) ListNodesPage(
	context.Context,
	string,
	int,
	int,
	string,
) ([]ingest.Node, graph.PageInfo, error) {
	f.nodeCalls++
	return f.nodes, f.nodePage, nil
}

func (f *fakeGraphReader) GetNode(context.Context, string) (*ingest.Node, []ingest.Edge, error) {
	return nil, nil, nil
}

func (f *fakeGraphReader) ListEdgesPage(
	context.Context,
	string,
	string,
	string,
	int,
	int,
	string,
) ([]ingest.Edge, graph.PageInfo, error) {
	return nil, graph.PageInfo{}, nil
}

func (f *fakeGraphReader) SearchNodes(context.Context, string, int) ([]graph.SearchResult, error) {
	return nil, nil
}

func (f *fakeGraphReader) GetNeighborhood(
	context.Context,
	string,
	int,
) ([]ingest.Node, []ingest.Edge, error) {
	return nil, nil, nil
}

func (f *fakeGraphReader) GetBlastRadius(
	context.Context,
	string,
	string,
	int,
) (*graph.BlastRadiusResult, error) {
	return nil, nil
}

func TestParseIntParam(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		key        string
		defaultVal int
		want       int
	}{
		{name: "empty string returns default", query: "", key: "limit", defaultVal: 100, want: 100},
		{name: "valid 50", query: "limit=50", key: "limit", defaultVal: 100, want: 50},
		{name: "invalid abc returns default", query: "limit=abc", key: "limit", defaultVal: 100, want: 100},
		{name: "negative returns default", query: "limit=-1", key: "limit", defaultVal: 100, want: 100},
		{name: "zero returns default", query: "limit=0", key: "limit", defaultVal: 100, want: 100},
		{name: "exceeds max clamped", query: "limit=99999", key: "limit", defaultVal: 100, want: maxQueryLimit},
		{name: "exactly max", query: "limit=10000", key: "limit", defaultVal: 100, want: maxQueryLimit},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			url := "/test"
			if tt.query != "" {
				url += "?" + tt.query
			}
			r := httptest.NewRequest(http.MethodGet, url, nil)
			got := parseIntParam(r, tt.key, tt.defaultVal)
			if got != tt.want {
				t.Errorf("parseIntParam() = %d, want %d", got, tt.want)
			}
		})
	}
}

func TestParseOffsetParamIsUncappedAndNonNegative(t *testing.T) {
	for _, tc := range []struct {
		query string
		want  int
	}{
		{query: "offset=0", want: 0},
		{query: "offset=250000", want: 250000},
		{query: "offset=-1", want: 0},
		{query: "offset=invalid", want: 0},
	} {
		r := httptest.NewRequest(http.MethodGet, "/?"+tc.query, nil)
		if got := parseOffsetParam(r, "offset"); got != tc.want {
			t.Errorf("%s: offset = %d, want %d", tc.query, got, tc.want)
		}
	}
}

func TestGraphPageMetadata(t *testing.T) {
	got := graphPageMetadata(graph.PageInfo{
		Offset: 100, Limit: 100, Total: 201,
		HasMore: true, Complete: false, Revision: "rev-1",
	}, projectionIdentity{ScanID: "scan-1", Revision: 7})
	if got.Offset != 100 || got.Limit != 100 || got.Total != 201 ||
		!got.HasMore || got.Complete || got.Revision != "rev-1" ||
		got.Projection == nil ||
		*got.Projection != (projectionIdentity{ScanID: "scan-1", Revision: 7}) {
		t.Fatalf("page metadata = %+v", got)
	}
}

func TestGraphStatsReturnsStableProjectionIdentity(t *testing.T) {
	reader := &fakeGraphReader{stats: &graph.GraphStats{
		NodeCounts: map[string]int64{"MCPServer": 1},
		EdgeCounts: map[string]int64{},
		TotalNodes: 1,
	}}
	h := &GraphHandler{
		reader: reader,
		projectionReader: &fakeProjectionStateReader{
			states: []*model.ProjectionState{completeProjectionState("scan-7", 7)},
		},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/graph/stats", nil)

	h.HandleStats(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var response struct {
		Projection projectionIdentity `json:"projection"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Projection != (projectionIdentity{ScanID: "scan-7", Revision: 7}) {
		t.Fatalf("projection = %+v", response.Projection)
	}
}

func TestGraphNodePageRejectsProjectionChange(t *testing.T) {
	reader := &fakeGraphReader{
		nodes: []ingest.Node{{ID: "node-1", Kinds: []string{"MCPServer"}, Properties: map[string]any{}}},
		nodePage: graph.PageInfo{
			Offset: 0, Limit: 100, Total: 1, Complete: true, Revision: "graph-rev",
		},
	}
	h := &GraphHandler{
		reader: reader,
		projectionReader: &fakeProjectionStateReader{
			states: []*model.ProjectionState{
				completeProjectionState("scan-7", 7),
				completeProjectionState("scan-8", 8),
			},
		},
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/api/v1/graph/nodes", nil)

	h.HandleListNodes(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409: %s", rec.Code, rec.Body.String())
	}
	if reader.nodeCalls != 1 {
		t.Fatalf("node calls = %d, want 1", reader.nodeCalls)
	}
}

func TestWriteRevisionConflict(t *testing.T) {
	rec := httptest.NewRecorder()
	err := fmt.Errorf("list nodes: %w", &graph.RevisionMismatchError{
		Expected: "rev-1",
		Actual:   "rev-2",
	})
	if !writeRevisionConflict(rec, err) {
		t.Fatal("expected revision mismatch to be handled")
	}
	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409", rec.Code)
	}
	var response ErrorResponse
	if err := json.NewDecoder(rec.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	details, ok := response.Error.Details.(map[string]any)
	if !ok || details["actual_revision"] != "rev-2" {
		t.Fatalf("conflict details = %#v, want actual_revision rev-2", response.Error.Details)
	}
	if writeRevisionConflict(httptest.NewRecorder(), errors.New("other")) {
		t.Fatal("non-revision error must not be handled as a conflict")
	}
}
