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
	n, err := w.WriteNodes(context.Background(), nodes, "scan-1")
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

	n, err := w.WriteNodes(context.Background(), nodes, "scan-1")
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

	if _, err := w.WriteNodes(context.Background(), nodes, "scan-1"); err != nil {
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

	if _, err := w.WriteNodes(context.Background(), nodes, "scan-1"); err != nil {
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
	n, err := w.WriteNodes(context.Background(), nodes, "scan-1")

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

	n, err := w.WriteNodes(context.Background(), nodes, "scan-1")
	if err == nil {
		t.Fatal("expected error from second batch")
	}
	if n != 1000 {
		t.Errorf("expected 1000 (first batch), got %d", n)
	}
}

func TestWriteNodes_NoKindsDefaultsToNodeLabel(t *testing.T) {
	rec := &recordedExec{}
	w := newTestWriter(rec.exec, false)

	nodes := []ingest.Node{
		{ID: "x", Kinds: nil},
	}
	if _, err := w.WriteNodes(context.Background(), nodes, "scan-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	calls := rec.snapshot()
	if len(calls) != 1 || !strings.Contains(calls[0].Cypher, "MERGE (n:Node {") {
		t.Fatalf("expected default Node label MERGE; got %s", calls[0].Cypher)
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
		{Source: "s1", Target: "t1", Kind: "PROVIDES_TOOL"},
	}
	n, err := w.WriteEdges(context.Background(), edges, "scan-1")
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
	// Endpoint resolution from registry: PROVIDES_TOOL is MCPServer -> MCPTool
	if !strings.Contains(calls[0].Cypher, "MATCH (a:MCPServer {objectid: edge.source})") {
		t.Errorf("expected MCPServer source label from registry; got: %s", calls[0].Cypher)
	}
}

func TestWriteEdges_SingleEdge_APOC(t *testing.T) {
	rec := &recordedExec{}
	w := newTestWriter(rec.exec, true)

	edges := []ingest.Edge{
		{Source: "s1", Target: "t1", Kind: "PROVIDES_TOOL"},
	}
	if _, err := w.WriteEdges(context.Background(), edges, "scan-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	calls := rec.snapshot()
	if len(calls) != 1 {
		t.Fatalf("expected 1 exec, got %d", len(calls))
	}
	if !strings.Contains(calls[0].Cypher, "apoc.merge.relationship(a, $kind") {
		t.Errorf("APOC mode should call apoc.merge.relationship; got: %s", calls[0].Cypher)
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
			Source: "s-" + intToStr(i),
			Target: "t-" + intToStr(i),
			Kind:   "PROVIDES_TOOL",
		}
	}

	n, err := w.WriteEdges(context.Background(), edges, "scan-1")
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
		{Source: "s1", Target: "t1", Kind: "PROVIDES_TOOL", Properties: map[string]any{"k": "v"}},
		{Source: "s2", Target: "t2", Kind: "PROVIDES_TOOL"},
	}

	apocRec := &recordedExec{}
	apocW := newTestWriter(apocRec.exec, true)
	if _, err := apocW.WriteEdges(context.Background(), edges, "scan-1"); err != nil {
		t.Fatalf("apoc: %v", err)
	}

	fbRec := &recordedExec{}
	fbW := newTestWriter(fbRec.exec, false)
	if _, err := fbW.WriteEdges(context.Background(), edges, "scan-1"); err != nil {
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

func TestWriteEdges_ExplicitKindsOverrideRegistry(t *testing.T) {
	rec := &recordedExec{}
	w := newTestWriter(rec.exec, false)

	edges := []ingest.Edge{
		{Source: "s1", Target: "t1", Kind: "PROVIDES_TOOL", SourceKind: "CustomSource", TargetKind: "CustomTarget"},
	}

	if _, err := w.WriteEdges(context.Background(), edges, "scan-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	calls := rec.snapshot()
	if !strings.Contains(calls[0].Cypher, "MATCH (a:CustomSource") {
		t.Errorf("explicit SourceKind should override registry; got: %s", calls[0].Cypher)
	}
	if !strings.Contains(calls[0].Cypher, "MATCH (b:CustomTarget") {
		t.Errorf("explicit TargetKind should override registry; got: %s", calls[0].Cypher)
	}
}

func TestWriteEdges_RegistryFallbackForMissingKinds(t *testing.T) {
	// Edge with no explicit kinds; registry must supply PROVIDES_TOOL =
	// MCPServer -> MCPTool.
	rec := &recordedExec{}
	w := newTestWriter(rec.exec, false)

	edges := []ingest.Edge{
		{Source: "s1", Target: "t1", Kind: "PROVIDES_TOOL"},
	}
	if _, err := w.WriteEdges(context.Background(), edges, "scan-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	calls := rec.snapshot()
	if !strings.Contains(calls[0].Cypher, "MATCH (a:MCPServer") {
		t.Errorf("registry should resolve source to MCPServer; got: %s", calls[0].Cypher)
	}
	if !strings.Contains(calls[0].Cypher, "MATCH (b:MCPTool") {
		t.Errorf("registry should resolve target to MCPTool; got: %s", calls[0].Cypher)
	}
}

func TestWriteEdges_UnknownKindNoLabels(t *testing.T) {
	// Unknown edge kind without explicit kinds: no labels in MATCH, just
	// objectid lookup. The Writer still emits the cypher — driver-side
	// the MATCH may find nothing, but that is not the Writer's concern.
	rec := &recordedExec{}
	w := newTestWriter(rec.exec, false)

	edges := []ingest.Edge{
		{Source: "s1", Target: "t1", Kind: "UNKNOWN_KIND"},
	}
	if _, err := w.WriteEdges(context.Background(), edges, "scan-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	calls := rec.snapshot()
	if !strings.Contains(calls[0].Cypher, "MATCH (a {objectid: edge.source})") {
		t.Errorf("unknown kind: expected unlabeled source MATCH; got: %s", calls[0].Cypher)
	}
	if !strings.Contains(calls[0].Cypher, "MERGE (a)-[r:UNKNOWN_KIND]->(b)") {
		t.Errorf("expected MERGE with UNKNOWN_KIND; got: %s", calls[0].Cypher)
	}
}

func TestWriteEdges_PropertiesPropagated(t *testing.T) {
	rec := &recordedExec{}
	w := newTestWriter(rec.exec, false)

	edges := []ingest.Edge{
		{
			Source: "s1", Target: "t1", Kind: "PROVIDES_TOOL",
			Properties: map[string]any{
				"scan_id":     "scan-1",
				"last_seen":   "2026-01-01T00:00:00Z",
				"confidence":  0.9,
				"risk_weight": 0.1,
			},
		},
	}
	if _, err := w.WriteEdges(context.Background(), edges, "scan-1"); err != nil {
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
		{Source: "s1", Target: "t1", Kind: "PROVIDES_TOOL", Properties: nil},
	}
	if _, err := w.WriteEdges(context.Background(), edges, "scan-1"); err != nil {
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
		{Source: "s1", Target: "t1", Kind: "PROVIDES_TOOL"},
	}
	_, err := w.WriteEdges(context.Background(), edges, "scan-1")
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
		{Source: "s1", Target: "t1", Kind: "PROVIDES_TOOL"},
	}
	_, err := w.WriteEdges(context.Background(), edges, "scan-1")
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
		{Source: "s1", Target: "t1", Kind: "PROVIDES_TOOL"},
		{Source: "s2", Target: "h1", Kind: "RUNS_ON", SourceKind: "MCPServer", TargetKind: "Host"},
		{Source: "a1", Target: "h1", Kind: "RUNS_ON", SourceKind: "A2AAgent", TargetKind: "Host"},
	}
	if _, err := w.WriteEdges(context.Background(), edges, "scan-1"); err != nil {
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
			"name":                "shared",
			"observation_tokens":  []string{"attacker-controlled"},
			"legacy_observation":  false,
			"observation_managed": false,
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
		"legacy_observation",
		"observation_managed",
		"observation_properties_complete",
	} {
		if _, exists := props[reserved]; exists {
			t.Fatalf("reserved property %q was accepted from artifact", reserved)
		}
	}
	if !strings.Contains(nodeRecorder.snapshot()[0].Cypher, "legacy_observation") {
		t.Fatal("node merge must preserve pre-lifecycle legacy ownership")
	}

	edgeRecorder := &recordedExec{}
	writer = newTestWriter(edgeRecorder.exec, false)
	edge := ingest.Edge{
		Source:             "s",
		Target:             "t",
		Kind:               "PROVIDES_TOOL",
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

func TestCompleteObservationReplacesManagedPropertiesAndMigratesLegacy(t *testing.T) {
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
		"WHEN replace_properties THEN false",
		"n.observation_properties_complete",
	} {
		if !strings.Contains(call.Cypher, fragment) {
			t.Fatalf("managed replacement query missing %q:\n%s", fragment, call.Cypher)
		}
	}
}

func TestUnknownObservationCannotBlindlyReplaceProperties(t *testing.T) {
	recorder := &recordedExec{}
	writer := newTestWriter(recorder.exec, false)
	node := ingest.Node{
		ID:         "legacy",
		Kinds:      []string{"MCPServer"},
		Properties: map[string]any{"name": "legacy-update"},
	}

	if _, err := writer.WriteObservationNodes(
		context.Background(),
		[]ingest.Node{node},
		"scan-legacy",
		nil,
	); err != nil {
		t.Fatalf("WriteObservationNodes: %v", err)
	}
	call := recorder.snapshot()[0]
	row := rowsAt(t, call.Params, "nodes")[0]
	if prefixes, _ := row["complete_domain_prefixes"].([]string); len(prefixes) != 0 {
		t.Fatalf("unknown observation received replacement prefixes: %q", prefixes)
	}
	if !strings.Contains(call.Cypher, "size(node.observation_tokens) > 0") {
		t.Fatal("property replacement is not gated on managed ownership")
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
