package graph

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

// recordedExec captures every execFn call for assertion.
type recordedExec struct {
	mu    sync.Mutex
	calls []recordedCall
	// fn is called per-batch; defaults to "return len(rows), nil".
	fn func(cypher string, params map[string]any) (int, error)
}

type recordedCall struct {
	Cypher string
	Params map[string]any
}

func (r *recordedExec) exec(_ context.Context, cypher string, params map[string]any) (int, error) {
	r.mu.Lock()
	r.calls = append(r.calls, recordedCall{Cypher: cypher, Params: params})
	fn := r.fn
	r.mu.Unlock()
	if fn != nil {
		return fn(cypher, params)
	}
	// Default: return the row count from $nodes/$edges so writers see
	// realistic written-counts for batch-boundary assertions.
	if rows, ok := params["nodes"].([]map[string]any); ok {
		return len(rows), nil
	}
	if rows, ok := params["edges"].([]map[string]any); ok {
		return len(rows), nil
	}
	return 0, nil
}

func (r *recordedExec) snapshot() []recordedCall {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]recordedCall, len(r.calls))
	copy(out, r.calls)
	return out
}

// newTestWriter builds a Writer with the given execFn and APOC mode without
// touching a real Neo4j driver. Pre-firing apocOnce locks hasAPOC to the
// desired value so detectAPOC becomes a no-op.
func newTestWriter(execFn execFunc, hasAPOC bool) *Writer {
	w := &Writer{
		batchSize: defaultBatchSize,
		execFn:    execFn,
		hasAPOC:   hasAPOC,
	}
	w.apocOnce.Do(func() {})
	return w
}

// rowsAt asserts that params[key] is a []map[string]any and returns it,
// failing the test (with a useful message) if the type doesn't match. This
// keeps every recorded-call assertion in one place; errcheck is satisfied
// because the comma-ok form is used.
func rowsAt(t *testing.T, params map[string]any, key string) []map[string]any {
	t.Helper()
	v, ok := params[key].([]map[string]any)
	if !ok {
		t.Fatalf("params[%q]: expected []map[string]any, got %T", key, params[key])
	}
	return v
}

// propsAt asserts that row[key] is a map[string]any and returns it.
func propsAt(t *testing.T, row map[string]any, key string) map[string]any {
	t.Helper()
	v, ok := row[key].(map[string]any)
	if !ok {
		t.Fatalf("row[%q]: expected map[string]any, got %T", key, row[key])
	}
	return v
}

func TestEdgeKindEndpointsCoversAllEdgeKinds(t *testing.T) {
	for kind := range ingest.AllowedEdgeKinds {
		if _, ok := ingest.EdgeKindEndpoints[kind]; !ok {
			t.Errorf("EdgeKindEndpoints missing entry for edge kind %q", kind)
		}
	}
	for kind := range ingest.EdgeKindEndpoints {
		if !ingest.AllowedEdgeKinds[kind] {
			t.Errorf("EdgeKindEndpoints has extra entry for unknown edge kind %q", kind)
		}
	}
}

// --- WriteNodes -------------------------------------------------------------

func TestWriteNodes_EmptyInputSkipsExec(t *testing.T) {
	rec := &recordedExec{}
	w := newTestWriter(rec.exec, false)

	n, err := w.WriteNodes(context.Background(), nil, "scan-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 nodes written, got %d", n)
	}
	if got := len(rec.snapshot()); got != 0 {
		t.Errorf("expected no exec calls for empty input, got %d", got)
	}
}

func TestWriteNodes_SingleNodeOneMerge(t *testing.T) {
	rec := &recordedExec{}
	w := newTestWriter(rec.exec, false)

	nodes := []ingest.Node{
		{ID: "abc", Kinds: []string{"MCPServer"}, Properties: map[string]any{"name": "s1"}},
	}
	n, err := w.WriteNodes(context.Background(), managedTestNodes(nodes), "scan-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 node written, got %d", n)
	}

	calls := rec.snapshot()
	if len(calls) != 1 {
		t.Fatalf("expected 1 exec call, got %d", len(calls))
	}
	if !strings.Contains(calls[0].Cypher, "MERGE (n:MCPServer {objectid: node.id})") {
		t.Errorf("missing MERGE for MCPServer; got cypher: %s", calls[0].Cypher)
	}
	if calls[0].Params["scan_id"] != "scan-1" {
		t.Errorf("expected scan_id=scan-1, got %v", calls[0].Params["scan_id"])
	}
}

func TestWriteNodes_BatchBoundary1500(t *testing.T) {
	rec := &recordedExec{}
	w := newTestWriter(rec.exec, false)

	nodes := make([]ingest.Node, 1500)
	for i := range nodes {
		nodes[i] = ingest.Node{
			ID:    "id-" + intToStr(i),
			Kinds: []string{"MCPServer"},
		}
	}

	n, err := w.WriteNodes(context.Background(), managedTestNodes(nodes), "scan-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1500 {
		t.Errorf("expected 1500 nodes written, got %d", n)
	}

	calls := rec.snapshot()
	if len(calls) != 2 {
		t.Fatalf("expected 2 batches (1000+500), got %d", len(calls))
	}
	first := rowsAt(t, calls[0].Params, "nodes")
	second := rowsAt(t, calls[1].Params, "nodes")
	if len(first) != 1000 {
		t.Errorf("first batch: expected 1000 rows, got %d", len(first))
	}
	if len(second) != 500 {
		t.Errorf("second batch: expected 500 rows, got %d", len(second))
	}
}

func TestWriteNodes_MixedKindsGroupedSeparately(t *testing.T) {
	rec := &recordedExec{}
	w := newTestWriter(rec.exec, false)

	nodes := []ingest.Node{
		{ID: "s1", Kinds: []string{"MCPServer"}},
		{ID: "t1", Kinds: []string{"MCPTool"}},
		{ID: "s2", Kinds: []string{"MCPServer"}},
		{ID: "t2", Kinds: []string{"MCPTool"}},
		{ID: "a1", Kinds: []string{"A2AAgent"}},
	}

	if _, err := w.WriteNodes(context.Background(), managedTestNodes(nodes), "scan-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	calls := rec.snapshot()
	if len(calls) != 3 {
		t.Fatalf("expected 3 exec calls (one per kind), got %d", len(calls))
	}

	kindsSeen := make(map[string]int)
	for _, c := range calls {
		for _, kind := range []string{"MCPServer", "MCPTool", "A2AAgent"} {
			if strings.Contains(c.Cypher, "MERGE (n:"+kind+" {") {
				rows := rowsAt(t, c.Params, "nodes")
				kindsSeen[kind] = len(rows)
			}
		}
	}
	if kindsSeen["MCPServer"] != 2 {
		t.Errorf("MCPServer batch: expected 2 rows, got %d", kindsSeen["MCPServer"])
	}
	if kindsSeen["MCPTool"] != 2 {
		t.Errorf("MCPTool batch: expected 2 rows, got %d", kindsSeen["MCPTool"])
	}
	if kindsSeen["A2AAgent"] != 1 {
		t.Errorf("A2AAgent batch: expected 1 row, got %d", kindsSeen["A2AAgent"])
	}
}

func TestWriteNodes_PropertiesPropagated(t *testing.T) {
	rec := &recordedExec{}
	w := newTestWriter(rec.exec, false)

	nodes := []ingest.Node{
		{
			ID:    "x",
			Kinds: []string{"MCPServer"},
			Properties: map[string]any{
				"name":     "my-server",
				"endpoint": "http://localhost:1234",
				"scan_id":  "scan-1",
			},
		},
	}

	if _, err := w.WriteNodes(context.Background(), managedTestNodes(nodes), "scan-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	calls := rec.snapshot()
	if len(calls) != 1 {
		t.Fatalf("expected 1 call, got %d", len(calls))
	}

	rows := rowsAt(t, calls[0].Params, "nodes")
	props := propsAt(t, rows[0], "properties")
	if props["name"] != "my-server" {
		t.Errorf("expected name=my-server, got %v", props["name"])
	}
	if props["endpoint"] != "http://localhost:1234" {
		t.Errorf("expected endpoint propagated, got %v", props["endpoint"])
	}
}

func TestWriteNodes_ErrorPropagatesNoPartialRecovery(t *testing.T) {
	wantErr := errors.New("neo4j down")
	rec := &recordedExec{
		fn: func(_ string, _ map[string]any) (int, error) {
			return 0, wantErr
		},
	}
	w := newTestWriter(rec.exec, false)

	nodes := []ingest.Node{{ID: "x", Kinds: []string{"MCPServer"}}}
	n, err := w.WriteNodes(context.Background(), managedTestNodes(nodes), "scan-1")

	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("expected wrapped wantErr, got %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 written when first batch errors, got %d", n)
	}
	if !strings.Contains(err.Error(), "fallback node batch") {
		t.Errorf("expected error to mention 'fallback node batch', got %q", err.Error())
	}
}

func TestWriteNodes_PartialBatchErrorReturnsCountSoFar(t *testing.T) {
	// Fail on the second batch. Writer returns the count from the first.
	var callCount int
	rec := &recordedExec{
		fn: func(_ string, params map[string]any) (int, error) {
			callCount++
			if callCount == 2 {
				return 0, errors.New("second-batch fail")
			}
			rows, ok := params["nodes"].([]map[string]any)
			if !ok {
				return 0, errors.New("nodes param wrong type")
			}
			return len(rows), nil
		},
	}
	w := newTestWriter(rec.exec, false)

	nodes := make([]ingest.Node, 1500)
	for i := range nodes {
		nodes[i] = ingest.Node{
			ID:    "id-" + intToStr(i),
			Kinds: []string{"MCPServer"},
		}
	}

	n, err := w.WriteNodes(context.Background(), managedTestNodes(nodes), "scan-1")
	if err == nil {
		t.Fatal("expected error from second batch")
	}
	if n != 1000 {
		t.Errorf("expected 1000 (first batch), got %d", n)
	}
}

func TestWriteNodes_RejectsMissingKinds(t *testing.T) {
	rec := &recordedExec{}
	w := newTestWriter(rec.exec, false)

	nodes := []ingest.Node{
		{ID: "x", Kinds: nil, ObservationDomains: []string{"test-domain"}},
	}
	if _, err := w.WriteNodes(context.Background(), nodes, "scan-1"); err == nil {
		t.Fatal("expected missing kind to be rejected")
	}
	if calls := rec.snapshot(); len(calls) != 0 {
		t.Fatalf("invalid node reached graph execution: %+v", calls)
	}
}

func TestWriteNodes_RejectsMissingObservationDomain(t *testing.T) {
	rec := &recordedExec{}
	w := newTestWriter(rec.exec, false)

	nodes := []ingest.Node{{ID: "x", Kinds: []string{"MCPServer"}}}
	if _, err := w.WriteNodes(context.Background(), nodes, "scan-1"); err == nil {
		t.Fatal("expected missing observation domain to be rejected")
	}
	if calls := rec.snapshot(); len(calls) != 0 {
		t.Fatalf("unowned node reached graph execution: %+v", calls)
	}
}

// --- WriteEdges -------------------------------------------------------------

func TestWriteEdges_EmptyInputSkipsExec(t *testing.T) {
	rec := &recordedExec{}
	w := newTestWriter(rec.exec, false)

	n, err := w.WriteEdges(context.Background(), nil, "scan-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 0 {
		t.Errorf("expected 0 edges written, got %d", n)
	}
	if got := len(rec.snapshot()); got != 0 {
		t.Errorf("expected no exec calls for empty input, got %d", got)
	}
}

func TestWriteEdges_SingleEdgeOneMerge_Fallback(t *testing.T) {
	rec := &recordedExec{}
	w := newTestWriter(rec.exec, false)

	edges := []ingest.Edge{
		{
			Source: "s1", Target: "t1", Kind: "PROVIDES_TOOL",
			SourceKind: "MCPServer", TargetKind: "MCPTool",
		},
	}
	n, err := w.WriteEdges(context.Background(), managedTestEdges(edges), "scan-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 1 {
		t.Errorf("expected 1 edge, got %d", n)
	}

	calls := rec.snapshot()
	if len(calls) != 1 {
		t.Fatalf("expected 1 exec, got %d", len(calls))
	}
	if !strings.Contains(calls[0].Cypher, "MERGE (a)-[r:PROVIDES_TOOL]->(b)") {
		t.Errorf("expected fallback MERGE for PROVIDES_TOOL; got: %s", calls[0].Cypher)
	}
	if !strings.Contains(calls[0].Cypher, "MATCH (a:MCPServer {objectid: edge.source})") {
		t.Errorf("expected explicit MCPServer source label; got: %s", calls[0].Cypher)
	}
}

func TestWriteEdges_SingleEdge_APOC(t *testing.T) {
	rec := &recordedExec{}
	w := newTestWriter(rec.exec, true)

	edges := []ingest.Edge{
		{
			Source: "s1", Target: "t1", Kind: "PROVIDES_TOOL",
			SourceKind: "MCPServer", TargetKind: "MCPTool",
		},
	}
	if _, err := w.WriteEdges(context.Background(), managedTestEdges(edges), "scan-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	calls := rec.snapshot()
	if len(calls) != 1 {
		t.Fatalf("expected 1 exec, got %d", len(calls))
	}
	if !strings.Contains(calls[0].Cypher, "apoc.merge.relationship(a, $kind") {
		t.Errorf("APOC mode should call apoc.merge.relationship; got: %s", calls[0].Cypher)
	}
	if strings.Contains(calls[0].Cypher, "b, edge.properties)") {
		t.Fatal("APOC merge bypasses managed property-completeness checks")
	}
	if !strings.Contains(calls[0].Cypher, "rel.observation_properties_complete") {
		t.Fatal("APOC merge does not track managed property completeness")
	}
	if calls[0].Params["kind"] != "PROVIDES_TOOL" {
		t.Errorf("expected kind=PROVIDES_TOOL param, got %v", calls[0].Params["kind"])
	}
}

func TestWriteEdges_BatchBoundary2500(t *testing.T) {
	rec := &recordedExec{}
	w := newTestWriter(rec.exec, false)

	edges := make([]ingest.Edge, 2500)
	for i := range edges {
		edges[i] = ingest.Edge{
			Source:     "s-" + intToStr(i),
			Target:     "t-" + intToStr(i),
			Kind:       "PROVIDES_TOOL",
			SourceKind: "MCPServer",
			TargetKind: "MCPTool",
		}
	}

	n, err := w.WriteEdges(context.Background(), managedTestEdges(edges), "scan-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != 2500 {
		t.Errorf("expected 2500 edges, got %d", n)
	}

	calls := rec.snapshot()
	if len(calls) != 3 {
		t.Fatalf("expected 3 batches (1000+1000+500), got %d", len(calls))
	}
	if got := len(rowsAt(t, calls[0].Params, "edges")); got != 1000 {
		t.Errorf("batch 0: expected 1000 rows, got %d", got)
	}
	if got := len(rowsAt(t, calls[1].Params, "edges")); got != 1000 {
		t.Errorf("batch 1: expected 1000 rows, got %d", got)
	}
	if got := len(rowsAt(t, calls[2].Params, "edges")); got != 500 {
		t.Errorf("batch 2: expected 500 rows, got %d", got)
	}
}

func TestWriteEdges_APOCAndFallbackProduceSameWrites(t *testing.T) {
	// Both paths group edges identically. The shape of the recorded
	// calls (param keys, edges payload, scan_id) should match.
	edges := []ingest.Edge{
		{
			Source: "s1", Target: "t1", Kind: "PROVIDES_TOOL",
			SourceKind: "MCPServer", TargetKind: "MCPTool",
			Properties: map[string]any{"k": "v"},
		},
		{
			Source: "s2", Target: "t2", Kind: "PROVIDES_TOOL",
			SourceKind: "MCPServer", TargetKind: "MCPTool",
		},
	}

	apocRec := &recordedExec{}
	apocW := newTestWriter(apocRec.exec, true)
	if _, err := apocW.WriteEdges(context.Background(), managedTestEdges(edges), "scan-1"); err != nil {
		t.Fatalf("apoc: %v", err)
	}

	fbRec := &recordedExec{}
	fbW := newTestWriter(fbRec.exec, false)
	if _, err := fbW.WriteEdges(context.Background(), managedTestEdges(edges), "scan-1"); err != nil {
		t.Fatalf("fallback: %v", err)
	}

	apocCalls := apocRec.snapshot()
	fbCalls := fbRec.snapshot()
	if len(apocCalls) != len(fbCalls) {
		t.Fatalf("call count differs: apoc=%d, fallback=%d", len(apocCalls), len(fbCalls))
	}

	// Same number of edge rows, same scan_id, same source/target IDs.
	apocEdges := rowsAt(t, apocCalls[0].Params, "edges")
	fbEdges := rowsAt(t, fbCalls[0].Params, "edges")
	if len(apocEdges) != len(fbEdges) {
		t.Fatalf("edge row count differs: apoc=%d, fallback=%d", len(apocEdges), len(fbEdges))
	}
	for i := range apocEdges {
		if apocEdges[i]["source"] != fbEdges[i]["source"] {
			t.Errorf("row %d: source differs: apoc=%v, fb=%v", i, apocEdges[i]["source"], fbEdges[i]["source"])
		}
		if apocEdges[i]["target"] != fbEdges[i]["target"] {
			t.Errorf("row %d: target differs: apoc=%v, fb=%v", i, apocEdges[i]["target"], fbEdges[i]["target"])
		}
	}
	if apocCalls[0].Params["scan_id"] != fbCalls[0].Params["scan_id"] {
		t.Error("scan_id differs between apoc and fallback")
	}
}

func TestWriteEdges_RejectsUnknownRawKind(t *testing.T) {
	rec := &recordedExec{}
	w := newTestWriter(rec.exec, false)

	edges := []ingest.Edge{
		{Source: "s1", Target: "t1", Kind: "PROVIDES_TOOL", SourceKind: "CustomSource", TargetKind: "CustomTarget"},
	}

	if _, err := w.WriteEdges(context.Background(), managedTestEdges(edges), "scan-1"); err == nil {
		t.Fatal("expected unknown raw kind to be rejected")
	}
	if calls := rec.snapshot(); len(calls) != 0 {
		t.Fatalf("invalid edge reached graph execution: %+v", calls)
	}
}

func TestWriterRejectsMissingExplicitEndpointKinds(t *testing.T) {
	rec := &recordedExec{}
	w := newTestWriter(rec.exec, false)

	edges := []ingest.Edge{
		{Source: "s1", Target: "t1", Kind: "PROVIDES_TOOL"},
	}
	if _, err := w.WriteEdges(context.Background(), edges, "scan-1"); err == nil {
		t.Fatal("expected missing endpoint kinds to be rejected")
	}
	if calls := rec.snapshot(); len(calls) != 0 {
		t.Fatalf("invalid edge reached graph execution: %+v", calls)
	}
}

func TestWriteEdges_RejectsUnownedRawEdge(t *testing.T) {
	rec := &recordedExec{}
	w := newTestWriter(rec.exec, false)

	edges := []ingest.Edge{{
		Source: "s1", Target: "t1", Kind: "PROVIDES_TOOL",
		SourceKind: "MCPServer", TargetKind: "MCPTool",
	}}
	if _, err := w.WriteEdges(context.Background(), edges, "scan-1"); err == nil {
		t.Fatal("expected unowned raw edge to be rejected")
	}
	if calls := rec.snapshot(); len(calls) != 0 {
		t.Fatalf("unowned edge reached graph execution: %+v", calls)
	}
}

func TestWriteEdges_RejectsCompositeCompatibilityBypass(t *testing.T) {
	rec := &recordedExec{}
	w := newTestWriter(rec.exec, false)
	edge := ingest.Edge{
		Source: "agent", Target: "resource", Kind: "CAN_REACH",
		SourceKind: "AgentInstance", TargetKind: "MCPResource",
		Properties: map[string]any{"is_composite": true},
	}

	if _, err := w.WriteEdges(
		context.Background(),
		managedTestEdges([]ingest.Edge{edge}),
		"scan-1",
	); err == nil {
		t.Fatal("generic WriteEdges accepted a composite edge")
	}
	if calls := rec.snapshot(); len(calls) != 0 {
		t.Fatalf("composite bypass reached graph execution: %+v", calls)
	}
}

func TestWriteEdges_RejectsRawKindMarkedComposite(t *testing.T) {
	rec := &recordedExec{}
	w := newTestWriter(rec.exec, false)
	edge := ingest.Edge{
		Source: "server", Target: "tool", Kind: "PROVIDES_TOOL",
		SourceKind: "MCPServer", TargetKind: "MCPTool",
		Properties: map[string]any{"is_composite": true},
	}

	if _, err := w.WriteEdges(
		context.Background(),
		managedTestEdges([]ingest.Edge{edge}),
		"scan-1",
	); err == nil {
		t.Fatal("generic WriteEdges accepted a raw edge marked composite")
	}
	if calls := rec.snapshot(); len(calls) != 0 {
		t.Fatalf("raw/composite bypass reached graph execution: %+v", calls)
	}
}

func TestWriteCompositeEdges_UsesExplicitPostprocessorPath(t *testing.T) {
	rec := &recordedExec{}
	w := newTestWriter(rec.exec, false)
	edge := ingest.Edge{
		Source: "agent", Target: "resource", Kind: "CAN_REACH",
		SourceKind: "AgentInstance", TargetKind: "MCPResource",
		Properties: map[string]any{"is_composite": true},
	}

	written, err := w.WriteCompositeEdges(
		context.Background(),
		[]ingest.Edge{edge},
		"scan-1",
	)
	if err != nil {
		t.Fatalf("WriteCompositeEdges: %v", err)
	}
	if written != 1 {
		t.Fatalf("written = %d, want 1", written)
	}
}

func TestWriteEdges_UnknownKindCannotBypassManagedRawValidation(t *testing.T) {
	rec := &recordedExec{}
	w := newTestWriter(rec.exec, false)

	edges := []ingest.Edge{
		{
			Source: "s1", Target: "t1", Kind: "UNKNOWN_KIND",
			SourceKind: "MCPServer", TargetKind: "MCPTool",
		},
	}
	if _, err := w.WriteEdges(context.Background(), managedTestEdges(edges), "scan-1"); err == nil {
		t.Fatal("expected unknown edge kind to be rejected")
	}
	if calls := rec.snapshot(); len(calls) != 0 {
		t.Fatalf("invalid edge reached graph execution: %+v", calls)
	}
}

func TestWriteEdges_PropertiesPropagated(t *testing.T) {
	rec := &recordedExec{}
	w := newTestWriter(rec.exec, false)

	edges := []ingest.Edge{
		{
			Source: "s1", Target: "t1", Kind: "PROVIDES_TOOL",
			SourceKind: "MCPServer", TargetKind: "MCPTool",
			Properties: map[string]any{
				"scan_id":     "scan-1",
				"last_seen":   "2026-01-01T00:00:00Z",
				"confidence":  0.9,
				"risk_weight": 0.1,
			},
		},
	}
	if _, err := w.WriteEdges(context.Background(), managedTestEdges(edges), "scan-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	calls := rec.snapshot()
	rows := rowsAt(t, calls[0].Params, "edges")
	props := propsAt(t, rows[0], "properties")
	if props["confidence"] != 0.9 {
		t.Errorf("expected confidence=0.9 propagated, got %v", props["confidence"])
	}
	if props["risk_weight"] != 0.1 {
		t.Errorf("expected risk_weight=0.1 propagated, got %v", props["risk_weight"])
	}
	if props["scan_id"] != "scan-1" {
		t.Errorf("expected scan_id propagated, got %v", props["scan_id"])
	}
}

func TestWriteEdges_NilPropertiesBecomeEmptyMap(t *testing.T) {
	rec := &recordedExec{}
	w := newTestWriter(rec.exec, false)

	edges := []ingest.Edge{
		{
			Source: "s1", Target: "t1", Kind: "PROVIDES_TOOL",
			SourceKind: "MCPServer", TargetKind: "MCPTool", Properties: nil,
		},
	}
	if _, err := w.WriteEdges(context.Background(), managedTestEdges(edges), "scan-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	rows := rowsAt(t, rec.snapshot()[0].Params, "edges")
	props := propsAt(t, rows[0], "properties")
	if len(props) != 0 {
		t.Errorf("nil props should normalize to empty map; got %d entries", len(props))
	}
}

func TestWriteEdges_ErrorPropagation_Fallback(t *testing.T) {
	wantErr := errors.New("write fail")
	rec := &recordedExec{
		fn: func(_ string, _ map[string]any) (int, error) { return 0, wantErr },
	}
	w := newTestWriter(rec.exec, false)

	edges := []ingest.Edge{
		{
			Source: "s1", Target: "t1", Kind: "PROVIDES_TOOL",
			SourceKind: "MCPServer", TargetKind: "MCPTool",
		},
	}
	_, err := w.WriteEdges(context.Background(), managedTestEdges(edges), "scan-1")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("expected wrapped wantErr, got: %v", err)
	}
	if !strings.Contains(err.Error(), "edge batch") {
		t.Errorf("expected error to mention 'edge batch'; got %q", err.Error())
	}
}

func TestWriteEdges_ErrorPropagation_APOC(t *testing.T) {
	wantErr := errors.New("apoc fail")
	rec := &recordedExec{
		fn: func(_ string, _ map[string]any) (int, error) { return 0, wantErr },
	}
	w := newTestWriter(rec.exec, true)

	edges := []ingest.Edge{
		{
			Source: "s1", Target: "t1", Kind: "PROVIDES_TOOL",
			SourceKind: "MCPServer", TargetKind: "MCPTool",
		},
	}
	_, err := w.WriteEdges(context.Background(), managedTestEdges(edges), "scan-1")
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("expected wrapped wantErr, got: %v", err)
	}
	if !strings.Contains(err.Error(), "apoc edge batch") {
		t.Errorf("expected error to mention 'apoc edge batch'; got %q", err.Error())
	}
}

func TestWriteEdges_DifferentKindsDifferentBatches(t *testing.T) {
	// Each (kind, sourceKind, targetKind) tuple is its own group, so
	// each gets its own MERGE Cypher and its own batch.
	rec := &recordedExec{}
	w := newTestWriter(rec.exec, false)

	edges := []ingest.Edge{
		{
			Source: "s1", Target: "t1", Kind: "PROVIDES_TOOL",
			SourceKind: "MCPServer", TargetKind: "MCPTool",
		},
		{Source: "s2", Target: "h1", Kind: "RUNS_ON", SourceKind: "MCPServer", TargetKind: "Host"},
		{Source: "a1", Target: "h1", Kind: "RUNS_ON", SourceKind: "A2AAgent", TargetKind: "Host"},
	}
	if _, err := w.WriteEdges(context.Background(), managedTestEdges(edges), "scan-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	calls := rec.snapshot()
	if len(calls) != 3 {
		t.Fatalf("expected 3 calls (3 distinct groups), got %d", len(calls))
	}
}

func TestWriterCarriesObservationOwnershipWithoutTrustingReservedProperties(t *testing.T) {
	nodeRecorder := &recordedExec{}
	writer := newTestWriter(nodeRecorder.exec, false)
	node := ingest.Node{
		ID:                 "shared",
		Kinds:              []string{"MCPServer"},
		ObservationDomains: []string{"mcp", "config"},
		Properties: map[string]any{
			"name":               "shared",
			"observation_tokens": []string{"attacker-controlled"},
		},
	}
	if _, err := writer.WriteNodes(context.Background(), []ingest.Node{node}, "scan-1"); err != nil {
		t.Fatalf("WriteNodes: %v", err)
	}
	nodeRow := rowsAt(t, nodeRecorder.snapshot()[0].Params, "nodes")[0]
	tokens, _ := nodeRow["observation_tokens"].([]string)
	wantTokens := []string{"config\x1fscan-1", "mcp\x1fscan-1"}
	if len(tokens) != len(wantTokens) || tokens[0] != wantTokens[0] || tokens[1] != wantTokens[1] {
		t.Fatalf("node tokens = %q, want %q", tokens, wantTokens)
	}
	props := propsAt(t, nodeRow, "properties")
	for _, reserved := range []string{
		"observation_tokens",
		"observation_properties_complete",
		"observation_reference_tokens",
	} {
		if _, exists := props[reserved]; exists {
			t.Fatalf("reserved property %q was accepted from artifact", reserved)
		}
	}
	if strings.Contains(nodeRecorder.snapshot()[0].Cypher, "legacy_observation") ||
		strings.Contains(nodeRecorder.snapshot()[0].Cypher, "observation_managed") {
		t.Fatal("node merge retained removed unmanaged-observation state")
	}

	edgeRecorder := &recordedExec{}
	writer = newTestWriter(edgeRecorder.exec, false)
	edge := ingest.Edge{
		Source:             "s",
		Target:             "t",
		Kind:               "PROVIDES_TOOL",
		SourceKind:         "MCPServer",
		TargetKind:         "MCPTool",
		ObservationDomains: []string{"mcp"},
	}
	if _, err := writer.WriteEdges(context.Background(), []ingest.Edge{edge}, "scan-1"); err != nil {
		t.Fatalf("WriteEdges: %v", err)
	}
	edgeRow := rowsAt(t, edgeRecorder.snapshot()[0].Params, "edges")[0]
	edgeTokens, _ := edgeRow["observation_tokens"].([]string)
	if len(edgeTokens) != 1 || edgeTokens[0] != "mcp\x1fscan-1" {
		t.Fatalf("edge tokens = %q, want mcp ownership", edgeTokens)
	}
}

func TestWriterStoresAllDependencyTokensSeparately(t *testing.T) {
	recorder := &recordedExec{}
	writer := newTestWriter(recorder.exec, false)
	edge := ingest.Edge{
		Source:               "a",
		Target:               "b",
		Kind:                 "DELEGATES_TO",
		SourceKind:           "A2AAgent",
		TargetKind:           "A2AAgent",
		ObservationDomains:   []string{"a2a:target:a", "a2a:target:b"},
		ObservationSemantics: ingest.ObservationSemanticsAllDependencies,
	}
	if _, err := writer.WriteEdges(
		context.Background(),
		[]ingest.Edge{edge},
		"scan-1",
	); err != nil {
		t.Fatalf("WriteEdges: %v", err)
	}

	call := recorder.snapshot()[0]
	row := rowsAt(t, call.Params, "edges")[0]
	tokens, _ := row["observation_tokens"].([]string)
	if len(tokens) != 0 {
		t.Fatalf("ordinary owner tokens = %q, want none", tokens)
	}
	dependencies, _ := row["observation_dependency_tokens"].([]string)
	want := []string{"a2a:target:a\x1fscan-1", "a2a:target:b\x1fscan-1"}
	if len(dependencies) != len(want) ||
		dependencies[0] != want[0] ||
		dependencies[1] != want[1] {
		t.Fatalf("dependency tokens = %q, want %q", dependencies, want)
	}
	if row["observation_semantics"] != string(ingest.ObservationSemanticsAllDependencies) {
		t.Fatalf("observation semantics = %v", row["observation_semantics"])
	}
	for _, fragment := range []string{
		"old_dependency_tokens",
		"r.observation_dependency_tokens",
	} {
		if !strings.Contains(call.Cypher, fragment) {
			t.Fatalf("dependency merge query missing %q:\n%s", fragment, call.Cypher)
		}
	}
}

func TestWriterReplacesCompleteAllDependencyOwnerSetAtomically(t *testing.T) {
	edge := ingest.Edge{
		Source:               "a",
		Target:               "b",
		Kind:                 "DELEGATES_TO",
		SourceKind:           "A2AAgent",
		TargetKind:           "A2AAgent",
		ObservationDomains:   []string{"a2a:target:a", "a2a:target:c"},
		ObservationSemantics: ingest.ObservationSemanticsAllDependencies,
	}
	for _, hasAPOC := range []bool{false, true} {
		name := "fallback"
		if hasAPOC {
			name = "apoc"
		}
		t.Run(name, func(t *testing.T) {
			recorder := &recordedExec{}
			writer := newTestWriter(recorder.exec, hasAPOC)
			if _, err := writer.WriteObservationEdges(
				context.Background(),
				[]ingest.Edge{edge},
				"scan-current",
				[]string{"a2a:target:a", "a2a:target:c"},
			); err != nil {
				t.Fatalf("WriteObservationEdges: %v", err)
			}
			calls := recorder.snapshot()
			if len(calls) != 1 {
				t.Fatalf("writer calls = %d, want 1", len(calls))
			}
			for _, fragment := range []string{
				"AS replace_dependency_set",
				"AND incoming_complete",
				"AND (replace_dependency_set",
				"WHEN replace_dependency_set THEN edge.observation_dependency_tokens",
				"WHEN replace_dependency_set THEN edge.observation_fact_fingerprints",
				"ELSE old_fact_fingerprints",
			} {
				if !strings.Contains(calls[0].Cypher, fragment) {
					t.Fatalf("dependency-set replacement query missing %q:\n%s", fragment, calls[0].Cypher)
				}
			}
		})
	}
}

func TestCompleteObservationReplacesManagedProperties(t *testing.T) {
	scope := "mcp:target:sha256:server-a"
	recorder := &recordedExec{}
	writer := newTestWriter(recorder.exec, false)
	node := ingest.Node{
		ID:                 "server-a",
		Kinds:              []string{"MCPServer"},
		ObservationDomains: []string{scope},
		Properties:         map[string]any{"name": "fresh"},
	}

	if _, err := writer.WriteObservationNodes(
		context.Background(),
		[]ingest.Node{node},
		"scan-current",
		[]string{scope},
	); err != nil {
		t.Fatalf("WriteObservationNodes: %v", err)
	}
	call := recorder.snapshot()[0]
	row := rowsAt(t, call.Params, "nodes")[0]
	prefixes, _ := row["complete_domain_prefixes"].([]string)
	if want := scope + "\x1f"; len(prefixes) != 1 || prefixes[0] != want {
		t.Fatalf("complete prefixes = %q, want [%q]", prefixes, want)
	}
	for _, fragment := range []string{
		"SET n = node.properties",
		"NOT observation_created AND NOT replace_properties",
		"n.observation_properties_complete",
		"CASE WHEN replace_properties THEN [1] ELSE [] END | REMOVE n:AIService",
	} {
		if !strings.Contains(call.Cypher, fragment) {
			t.Fatalf("managed replacement query missing %q:\n%s", fragment, call.Cypher)
		}
	}
	if strings.Contains(call.Cypher, "REMOVE n:SchemaVersion") {
		t.Fatal("managed replacement removes internal labels")
	}
}

func TestReferenceOnlyObservationPreservesAuthoritativeProperties(t *testing.T) {
	scope := "scan:loot:sha256:reference"
	recorder := &recordedExec{}
	writer := newTestWriter(recorder.exec, false)
	node := ingest.Node{
		ID:                 "litellm",
		Kinds:              []string{"LiteLLMGateway", "AIService"},
		ObservationDomains: []string{scope},
		Properties:         map[string]any{"objectid": "litellm"},
		PropertySemantics:  ingest.NodePropertySemanticsReferenceOnly,
	}

	if _, err := writer.WriteObservationNodes(
		context.Background(),
		[]ingest.Node{node},
		"loot-scan",
		[]string{scope},
	); err != nil {
		t.Fatalf("WriteObservationNodes: %v", err)
	}
	call := recorder.snapshot()[0]
	row := rowsAt(t, call.Params, "nodes")[0]
	if referenceOnly, _ := row["reference_only"].(bool); !referenceOnly {
		t.Fatalf("writer row did not preserve reference-only semantics: %+v", row)
	}
	properties := propsAt(t, row, "properties")
	if len(properties) != 1 || properties["objectid"] != "litellm" {
		t.Fatalf("reference properties = %+v, want objectid only", properties)
	}
	for _, fragment := range []string{
		"old_authoritative_tokens",
		"AND NOT node.reference_only",
		"old_properties_complete OR",
		"n.observation_reference_tokens",
		"NOT replace_properties AND NOT node.reference_only",
	} {
		if !strings.Contains(call.Cypher, fragment) {
			t.Fatalf("reference-only merge query missing %q:\n%s", fragment, call.Cypher)
		}
	}
}

func TestWriterSeparatesAuthoritativeAndReferenceRows(t *testing.T) {
	recorder := &recordedExec{}
	writer := newTestWriter(recorder.exec, false)
	nodes := []ingest.Node{
		{
			ID:                 "shared",
			Kinds:              []string{"LiteLLMGateway", "AIService"},
			ObservationDomains: []string{"scan:network:sha256:authoritative"},
			Properties:         map[string]any{"endpoint": "http://127.0.0.1:4000"},
		},
		{
			ID:                 "shared",
			Kinds:              []string{"LiteLLMGateway", "AIService"},
			ObservationDomains: []string{"scan:loot:sha256:reference"},
			Properties:         map[string]any{"objectid": "shared"},
			PropertySemantics:  ingest.NodePropertySemanticsReferenceOnly,
		},
	}

	if _, err := writer.WriteObservationNodes(
		context.Background(),
		nodes,
		"shared-owner",
		[]string{
			"scan:network:sha256:authoritative",
			"scan:loot:sha256:reference",
		},
	); err != nil {
		t.Fatalf("WriteObservationNodes: %v", err)
	}
	calls := recorder.snapshot()
	if len(calls) != 2 {
		t.Fatalf("mixed property semantics produced %d batches, want 2", len(calls))
	}
	var referenceRows, authoritativeRows int
	for _, call := range calls {
		for _, row := range rowsAt(t, call.Params, "nodes") {
			if referenceOnly, _ := row["reference_only"].(bool); referenceOnly {
				referenceRows++
			} else {
				authoritativeRows++
			}
		}
	}
	if referenceRows != 1 || authoritativeRows != 1 {
		t.Fatalf(
			"writer rows: reference=%d authoritative=%d",
			referenceRows,
			authoritativeRows,
		)
	}
}

func TestWriterRejectsPropertiesOnReferenceOnlyNode(t *testing.T) {
	recorder := &recordedExec{}
	writer := newTestWriter(recorder.exec, false)
	node := ingest.Node{
		ID:                 "litellm",
		Kinds:              []string{"LiteLLMGateway", "AIService"},
		ObservationDomains: []string{"scan:loot:sha256:reference"},
		Properties:         map[string]any{"endpoint": "fabricated"},
		PropertySemantics:  ingest.NodePropertySemanticsReferenceOnly,
	}

	if _, err := writer.WriteObservationNodes(
		context.Background(),
		[]ingest.Node{node},
		"loot-scan",
		[]string{"scan:loot:sha256:reference"},
	); err == nil {
		t.Fatal("writer accepted properties on a reference-only observation")
	}
	if calls := recorder.snapshot(); len(calls) != 0 {
		t.Fatalf("invalid reference reached graph execution: %+v", calls)
	}
}

// --- Helpers ----------------------------------------------------------------

func intToStr(i int) string {
	if i == 0 {
		return "0"
	}
	neg := i < 0
	if neg {
		i = -i
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}

func managedTestNodes(nodes []ingest.Node) []ingest.Node {
	result := append([]ingest.Node(nil), nodes...)
	for i := range result {
		if len(result[i].ObservationDomains) == 0 {
			result[i].ObservationDomains = []string{"test-domain"}
		}
	}
	return result
}

func managedTestEdges(edges []ingest.Edge) []ingest.Edge {
	result := append([]ingest.Edge(nil), edges...)
	for i := range result {
		if len(result[i].ObservationDomains) == 0 {
			result[i].ObservationDomains = []string{"test-domain"}
		}
	}
	return result
}
