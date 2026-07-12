package graph

import (
	"context"
	"strings"
	"sync"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

// MockGraphDB implements GraphDB for testing. Not in _test.go so other
// packages (analysis, processors, riskscore) can import it.
type MockGraphDB struct {
	mu sync.Mutex

	// Configurable return values per method.
	QueryResult []map[string]any
	QueryError  error
	QueryFunc   func(ctx context.Context, cypher string, params map[string]any) ([]map[string]any, error)

	WriteCompositeEdgesResult int
	WriteCompositeEdgesError  error

	UpdateNodeError error

	ExecuteWriteResult int
	ExecuteWriteError  error
	ExecuteWriteFunc   func(ctx context.Context, cypher string, params map[string]any) (int, error)

	GetNodeResult *ingest.Node
	GetNodeEdges  []ingest.Edge
	GetNodeError  error

	ListNodesResult   []ingest.Node
	ListNodesError    error
	ListNodesPageInfo PageInfo
	ListNodesPageFunc func(ctx context.Context, kind string, limit, offset int, revision string) ([]ingest.Node, PageInfo, error)

	StatsResult *GraphStats
	StatsError  error

	HasAPOCResult bool

	// Recorded calls for assertions.
	Calls []MockCall
}

// MockCall records a single method invocation.
type MockCall struct {
	Method string
	Args   []any
}

func (m *MockGraphDB) record(method string, args ...any) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.Calls = append(m.Calls, MockCall{Method: method, Args: args})
}

// CallsTo returns all recorded calls matching the given method name.
func (m *MockGraphDB) CallsTo(method string) []MockCall {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []MockCall
	for _, c := range m.Calls {
		if c.Method == method {
			out = append(out, c)
		}
	}
	return out
}

func (m *MockGraphDB) Query(ctx context.Context, cypher string, params map[string]any) ([]map[string]any, error) {
	m.record("Query", cypher, params)
	if m.QueryFunc != nil {
		return m.QueryFunc(ctx, cypher, params)
	}
	if m.QueryResult == nil && strings.Contains(cypher, "incomplete_property_nodes") {
		return []map[string]any{{
			"incomplete_property_nodes":         int64(0),
			"incomplete_property_relationships": int64(0),
			"tokenless_nodes":                   int64(0),
			"tokenless_incident_relationships":  int64(0),
		}}, m.QueryError
	}
	return m.QueryResult, m.QueryError
}

func (m *MockGraphDB) WriteCompositeEdges(
	ctx context.Context,
	edges []ingest.Edge,
	scanID string,
) (int, error) {
	m.record("WriteCompositeEdges", edges, scanID)
	if m.WriteCompositeEdgesError != nil {
		return 0, m.WriteCompositeEdgesError
	}
	if m.WriteCompositeEdgesResult > 0 {
		return m.WriteCompositeEdgesResult, nil
	}
	return len(edges), nil
}

func (m *MockGraphDB) UpdateNodeProperties(ctx context.Context, objectID string, props map[string]any) error {
	m.record("UpdateNodeProperties", objectID, props)
	return m.UpdateNodeError
}

func (m *MockGraphDB) ExecuteWrite(ctx context.Context, cypher string, params map[string]any) (int, error) {
	m.record("ExecuteWrite", cypher, params)
	if m.ExecuteWriteFunc != nil {
		return m.ExecuteWriteFunc(ctx, cypher, params)
	}
	return m.ExecuteWriteResult, m.ExecuteWriteError
}

func (m *MockGraphDB) GetNode(ctx context.Context, objectID string) (*ingest.Node, []ingest.Edge, error) {
	m.record("GetNode", objectID)
	return m.GetNodeResult, m.GetNodeEdges, m.GetNodeError
}

func (m *MockGraphDB) ListNodes(ctx context.Context, kind string, limit int) ([]ingest.Node, error) {
	m.record("ListNodes", kind, limit)
	return m.ListNodesResult, m.ListNodesError
}

func (m *MockGraphDB) ListNodesPage(
	ctx context.Context,
	kind string,
	limit, offset int,
	revision string,
) ([]ingest.Node, PageInfo, error) {
	m.record("ListNodesPage", kind, limit, offset, revision)
	if m.ListNodesPageFunc != nil {
		return m.ListNodesPageFunc(ctx, kind, limit, offset, revision)
	}
	page := m.ListNodesPageInfo
	if page == (PageInfo{}) {
		page = PageInfo{
			Offset:   offset,
			Limit:    limit,
			Total:    int64(len(m.ListNodesResult)),
			Complete: true,
			Revision: "mock-revision",
		}
	}
	return m.ListNodesResult, page, m.ListNodesError
}

func (m *MockGraphDB) GetStats(ctx context.Context) (*GraphStats, error) {
	m.record("GetStats")
	if m.StatsResult != nil || m.StatsError != nil {
		return m.StatsResult, m.StatsError
	}
	return &GraphStats{
		NodeCounts: map[string]int64{},
		EdgeCounts: map[string]int64{},
	}, nil
}

func (m *MockGraphDB) HasAPOC(ctx context.Context) bool {
	m.record("HasAPOC")
	return m.HasAPOCResult
}
