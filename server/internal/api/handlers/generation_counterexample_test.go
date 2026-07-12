package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/analysis"
	"github.com/adithyan-ak/agenthound/server/internal/appdb"
	srvingest "github.com/adithyan-ak/agenthound/server/internal/ingest"
	"github.com/adithyan-ak/agenthound/server/model"
)

// genFact models a node or edge with its generation-membership set, enough to
// interpret the decremental generation delete the ScanHandler issues.
type genFact struct {
	src, tgt string // populated for edges; empty for nodes
	gens     map[string]bool
}

func newGenFact(src, tgt string, gens ...string) *genFact {
	f := &genFact{src: src, tgt: tgt, gens: map[string]bool{}}
	for _, g := range gens {
		f.gens[g] = true
	}
	return f
}

// genGraphDB is an in-memory GraphDB that understands the exact decremental
// delete + membership-count cypher the ScanHandler emits, so the
// complete-A -> complete-B -> delete-B restore can be exercised end to end
// without a live Neo4j.
type genGraphDB struct {
	edges map[string]*genFact
	nodes map[string]*genFact
}

func (g *genGraphDB) edgeless(nodeID string) bool {
	for _, e := range g.edges {
		if e.src == nodeID || e.tgt == nodeID {
			return false
		}
	}
	return true
}

func (g *genGraphDB) countEdges(gen string) int {
	n := 0
	for _, e := range g.edges {
		if e.gens[gen] {
			n++
		}
	}
	return n
}

func (g *genGraphDB) countNodes(gen string) int {
	n := 0
	for _, nd := range g.nodes {
		if nd.gens[gen] {
			n++
		}
	}
	return n
}

func (g *genGraphDB) ExecuteWrite(_ context.Context, cypher string, params map[string]any) (int, error) {
	gen, _ := params["gen"].(string)
	switch {
	case strings.Contains(cypher, "$gen IN coalesce(r.generations") && strings.Contains(cypher, "DELETE r"):
		// Owned-only atomic decrement + GC for edges: ONLY edges that actually
		// carried $gen are touched; removing $gen deletes the edge just when
		// that emptied its set. An untagged/foreign edge (no $gen) is skipped
		// entirely, so an in-flight ingest's untagged edges are never GC'd.
		for id, e := range g.edges {
			if !e.gens[gen] {
				continue
			}
			delete(e.gens, gen)
			if len(e.gens) == 0 {
				delete(g.edges, id)
			}
		}
	case strings.Contains(cypher, "$gen IN coalesce(n.generations") && strings.Contains(cypher, "DELETE n"):
		for id, nd := range g.nodes {
			if !nd.gens[gen] {
				continue
			}
			delete(nd.gens, gen)
			if len(nd.gens) == 0 && g.edgeless(id) {
				delete(g.nodes, id)
			}
		}
	}
	return 0, nil
}

func (g *genGraphDB) Query(_ context.Context, cypher string, params map[string]any) ([]map[string]any, error) {
	gen, _ := params["gen"].(string)
	switch {
	case strings.Contains(cypher, "$gen IN coalesce(r.generations"):
		return []map[string]any{{"c": int64(g.countEdges(gen))}}, nil
	case strings.Contains(cypher, "$gen IN coalesce(n.generations"):
		return []map[string]any{{"c": int64(g.countNodes(gen))}}, nil
	}
	return nil, nil
}

func (g *genGraphDB) WriteEdges(context.Context, []ingest.Edge, string) (int, error) { return 0, nil }
func (g *genGraphDB) UpdateNodeProperties(context.Context, string, map[string]any) error {
	return nil
}
func (g *genGraphDB) GetNode(context.Context, string) (*ingest.Node, []ingest.Edge, error) {
	return nil, nil, nil
}
func (g *genGraphDB) ListNodes(context.Context, string, int) ([]ingest.Node, error) { return nil, nil }
func (g *genGraphDB) ListNodesPage(context.Context, string, int, int) ([]ingest.Node, error) {
	return nil, nil
}
func (g *genGraphDB) HasAPOC(context.Context) bool { return false }

// DeleteGenerationTx performs the same owned-only decrement + GC the concrete
// DB runs in one transaction: edges first (so the node edgeless guard sees the
// removed edges), then nodes.
func (g *genGraphDB) DeleteGenerationTx(_ context.Context, gen string) error {
	for id, e := range g.edges {
		if !e.gens[gen] {
			continue
		}
		delete(e.gens, gen)
		if len(e.gens) == 0 {
			delete(g.edges, id)
		}
	}
	for id, nd := range g.nodes {
		if !nd.gens[gen] {
			continue
		}
		delete(nd.gens, gen)
		if len(nd.gens) == 0 && g.edgeless(id) {
			delete(g.nodes, id)
		}
	}
	return nil
}

func (g *genGraphDB) DeleteByScanIDTx(context.Context, string) error { return nil }

// TestHandleDeleteScan_CompleteAThenBThenDeleteB_RestoresA is the deletion
// counterexample: after a complete generation A is superseded by a complete
// generation B (same scope), deleting the current generation B must
// rematerialize A with its facts INTACT — not leave an empty graph behind a
// flipped pointer.
//
// The graph is seeded to the post-(A->B) state: facts A and B both observed
// carry both generations; A-only and B-only facts carry one each. Deleting B
// must (1) drop B-only facts, (2) keep A-only facts, and (3) keep shared facts
// attributed to A — exactly A's original posture.
func TestHandleDeleteScan_CompleteAThenBThenDeleteB_RestoresA(t *testing.T) {
	const genA, genB = "gen-a", "gen-b"

	gg := &genGraphDB{
		nodes: map[string]*genFact{
			"n_src":    newGenFact("", "", genA, genB), // shared source
			"n_shared": newGenFact("", "", genA, genB), // shared target
			"n_aonly":  newGenFact("", "", genA),       // only A saw this
			"n_bonly":  newGenFact("", "", genB),       // only B saw this
		},
		edges: map[string]*genFact{
			"e_shared": newGenFact("n_src", "n_shared", genA, genB),
			"e_aonly":  newGenFact("n_src", "n_aonly", genA),
			"e_bonly":  newGenFact("n_src", "n_bonly", genB),
		},
	}

	store := &fakeScanStoreForHandler{
		scan:  &model.Scan{ID: "scan-b", Collector: "mcp", Scope: "mcp", Status: model.ScanStatusCompleted, IsCurrent: true, GenerationID: genB},
		prior: &model.Scan{ID: "scan-a", Collector: "mcp", Scope: "mcp", GenerationID: genA},
	}
	fd := &fakeFindingDeleter{}
	h := &ScanHandler{scanStore: store, findingStore: fd, graphDB: gg}

	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodDelete, "/api/v1/scans/scan-b", nil)
	r = withChiURLParam(r, "id", "scan-b")
	h.HandleDelete(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}

	// Prior generation A rematerialized as current.
	if len(store.promoted) != 1 || store.promoted[0] != "scan-a" {
		t.Fatalf("expected prior generation scan-a rematerialized, got %v", store.promoted)
	}

	// A's posture is fully intact: both A edges survive, both attributed to A.
	if got := gg.countEdges(genA); got != 2 {
		t.Errorf("generation A must retain its 2 edges after deleting B, got %d", got)
	}
	if got := gg.countNodes(genA); got != 3 {
		t.Errorf("generation A must retain its 3 nodes after deleting B, got %d", got)
	}
	// B is completely gone from the graph.
	if got := gg.countEdges(genB); got != 0 {
		t.Errorf("generation B edges must be gone, got %d", got)
	}
	if got := gg.countNodes(genB); got != 0 {
		t.Errorf("generation B nodes must be gone, got %d", got)
	}
	// Shared facts specifically survived (the data-loss regression): the edge
	// A and B both observed must still exist, attributed to A.
	if _, ok := gg.edges["e_shared"]; !ok {
		t.Error("shared edge must survive B deletion (attributed to A)")
	}
	if _, ok := gg.edges["e_bonly"]; ok {
		t.Error("B-only edge must be deleted")
	}
	if _, ok := gg.edges["e_aonly"]; !ok {
		t.Error("A-only edge must survive B deletion")
	}
	if !fd.deleted || !store.deleted {
		t.Error("expected finding snapshot + scan row deletion")
	}
}

// TestHandleDeleteScan_InFlightUntaggedFactSurvivesGC is the F3 counterexample:
// the generation GC must be owned-only. An in-flight ingest writes facts that
// carry an EMPTY generations set until the tagging stage; a concurrent scan
// delete's GC must never treat those untagged facts as orphans and delete them.
// Here an untagged edge+node (simulating that in-flight write) coexists with
// generation B's facts; deleting B must leave the untagged facts intact.
func TestHandleDeleteScan_InFlightUntaggedFactSurvivesGC(t *testing.T) {
	const genB = "gen-b"

	gg := &genGraphDB{
		nodes: map[string]*genFact{
			"n_bonly":    newGenFact("", "", genB), // B's own node
			"n_inflight": newGenFact("", ""),       // untagged: empty generations set
		},
		edges: map[string]*genFact{
			"e_bonly":    newGenFact("n_bonly", "n_bonly", genB),
			"e_inflight": newGenFact("n_inflight", "n_inflight"), // untagged in-flight edge
		},
	}

	store := &fakeScanStoreForHandler{
		scan: &model.Scan{ID: "scan-b", Collector: "mcp", Scope: "mcp", Status: model.ScanStatusCompleted, IsCurrent: true, GenerationID: genB},
		// No prior generation to rematerialize.
	}
	h := &ScanHandler{scanStore: store, findingStore: &fakeFindingDeleter{}, graphDB: gg}

	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodDelete, "/api/v1/scans/scan-b", nil)
	r = withChiURLParam(r, "id", "scan-b")
	h.HandleDelete(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", w.Code, w.Body.String())
	}
	// B's own facts are gone.
	if _, ok := gg.edges["e_bonly"]; ok {
		t.Error("B-only edge must be deleted")
	}
	if _, ok := gg.nodes["n_bonly"]; ok {
		t.Error("B-only node must be deleted")
	}
	// The untagged in-flight facts MUST survive — the GC is owned-only and must
	// never delete a fact that did not carry the deleted generation.
	if _, ok := gg.edges["e_inflight"]; !ok {
		t.Error("in-flight untagged edge must survive the generation GC")
	}
	if _, ok := gg.nodes["n_inflight"]; !ok {
		t.Error("in-flight untagged node must survive the generation GC")
	}
}

// TestScanHandler_CoordinatorSerializesWithIngest is the F3 concurrency test:
// the scan-delete handler and ingest share one coordinator, so their
// graph-mutating sections are mutually exclusive. We drive many concurrent
// delete + "ingest" critical sections through the shared coordinator and assert
// (under -race) that no two are ever active simultaneously.
func TestScanHandler_CoordinatorSerializesWithIngest(t *testing.T) {
	coord := srvingest.NewCoordinator()

	var active int32
	var maxConcurrent int32
	enter := func() {
		coord.Lock()
		n := atomic.AddInt32(&active, 1)
		for {
			m := atomic.LoadInt32(&maxConcurrent)
			if n <= m || atomic.CompareAndSwapInt32(&maxConcurrent, m, n) {
				break
			}
		}
		// Hold the section briefly to widen the race window.
		time.Sleep(time.Millisecond)
		atomic.AddInt32(&active, -1)
		coord.Unlock()
	}

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); enter() }()
	}
	wg.Wait()

	if got := atomic.LoadInt32(&maxConcurrent); got != 1 {
		t.Fatalf("coordinator must serialize graph mutations; observed %d concurrent", got)
	}
}

// persistedFindingSource returns a fixed persisted occurrence (with its
// snapshotted evidence DAG) so the detail handler can be checked for
// list/detail evidence parity.
type persistedFindingSource struct{ finding *model.Finding }

func (p *persistedFindingSource) ListCurrentFindings(context.Context, appdb.FindingQuery) ([]model.Finding, int, error) {
	return nil, 0, nil
}

func (p *persistedFindingSource) GetCurrentFinding(context.Context, []string, string) (*model.Finding, error) {
	return p.finding, nil
}

// TestHandleFindingDetail_PrefersPersistedEvidenceAfterMutation is the
// detail-parity counterexample: when the finding comes from the persisted
// store with a snapshotted evidence DAG, the detail endpoint must report THAT
// evidence, not a recomputation against a since-mutated (here: empty) live
// graph. Recomputation would yield an incomplete DAG; the persisted one is
// complete.
func TestHandleFindingDetail_PrefersPersistedEvidenceAfterMutation(t *testing.T) {
	const findingID = "aabbccdd11223344"
	weight := 0.3
	finding := &model.Finding{
		ID: findingID, EdgeKind: "CAN_REACH", Severity: "high",
		SourceID: "srcA", SourceName: "agent-a", SourceKind: "AgentInstance",
		TargetID: "tgtA", TargetName: "res-a", TargetKind: "MCPResource",
		GenerationID:       "gen-1",
		WeightTotal:        &weight,
		WeightMissingCount: 0,
		// Snapshotted at ingest: a COMPLETE evidence DAG spanning source->target.
		EvidenceDAG: map[string]any{
			"nodes": []any{
				map[string]any{"id": "srcA", "kinds": []any{"AgentInstance"}, "name": "agent-a", "role": "source"},
				map[string]any{"id": "tgtA", "kinds": []any{"MCPResource"}, "name": "res-a", "role": "target"},
			},
			"joins": []any{
				map[string]any{"source": "srcA", "target": "tgtA", "kind": "CAN_REACH", "type": "observed", "weight": weight},
			},
			"connected_components": float64(1),
			"confidence_basis":     "persisted-basis",
			"complete":             true,
			"weight_total":         weight,
			"weight_missing_count": float64(0),
		},
	}

	h := &AnalysisHandler{
		graphDB:  &graphDBReturningNothing{},
		findings: &persistedFindingSource{finding: finding},
		gens:     completeGenScope(),
	}

	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodGet, "/api/v1/analysis/findings/"+findingID, nil)
	r = withChiURLParam(r, "id", findingID)
	h.HandleFindingDetail(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", w.Code, w.Body.String())
	}
	var resp analysis.FindingDetail
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.EvidenceDAG == nil {
		t.Fatal("expected an evidence DAG in the detail response")
	}
	// The persisted, complete DAG must be reported — not a fresh (empty-graph)
	// recomputation, which would be Complete=false with a different basis.
	if !resp.EvidenceDAG.Complete {
		t.Error("detail must report the persisted (complete) evidence DAG, not a live recompute")
	}
	if resp.EvidenceDAG.ConfidenceBasis != "persisted-basis" {
		t.Errorf("expected persisted confidence basis, got %q", resp.EvidenceDAG.ConfidenceBasis)
	}
	if resp.EvidenceDAG.WeightTotal == nil || *resp.EvidenceDAG.WeightTotal != weight {
		t.Errorf("expected persisted weight total %v, got %v", weight, resp.EvidenceDAG.WeightTotal)
	}
	// The attack path shown is rebuilt from the persisted DAG, so it spans the
	// same evidence rather than being empty.
	if resp.AttackPath == nil || len(resp.AttackPath.Nodes) != 2 {
		t.Errorf("expected attack path rebuilt from persisted DAG (2 nodes), got %+v", resp.AttackPath)
	}
}

// graphDBReturningNothing is a live graph whose reads all come back empty,
// standing in for a graph that was mutated/re-ingested since the snapshot.
type graphDBReturningNothing struct{}

func (graphDBReturningNothing) Query(context.Context, string, map[string]any) ([]map[string]any, error) {
	return nil, nil
}
func (graphDBReturningNothing) WriteEdges(context.Context, []ingest.Edge, string) (int, error) {
	return 0, nil
}
func (graphDBReturningNothing) UpdateNodeProperties(context.Context, string, map[string]any) error {
	return nil
}
func (graphDBReturningNothing) ExecuteWrite(context.Context, string, map[string]any) (int, error) {
	return 0, nil
}
func (graphDBReturningNothing) GetNode(context.Context, string) (*ingest.Node, []ingest.Edge, error) {
	return nil, nil, nil
}
func (graphDBReturningNothing) ListNodes(context.Context, string, int) ([]ingest.Node, error) {
	return nil, nil
}
func (graphDBReturningNothing) ListNodesPage(context.Context, string, int, int) ([]ingest.Node, error) {
	return nil, nil
}
func (graphDBReturningNothing) HasAPOC(context.Context) bool { return false }
func (graphDBReturningNothing) DeleteGenerationTx(context.Context, string) error {
	return nil
}
func (graphDBReturningNothing) DeleteByScanIDTx(context.Context, string) error {
	return nil
}
