package ingest

import (
	"context"
	"errors"
	"strings"
	"testing"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/adithyan-ak/agenthound/server/model"
)

// countingGraphDB routes the pipeline's generation queries/writes to canned
// answers and records the retention/tagging operations so tests can assert
// coverage-aware behavior without a live Neo4j.
type countingGraphDB struct {
	*graph.MockGraphDB

	nodesTotal    int64
	edgesTotal    int64
	genNodesTotal int64 // count of nodes in a specific generation ($gen membership)
	genEdgesTotal int64 // count of edges in a specific generation ($gen membership)
	retiredNodes  int64 // non-destructive retired-node count
	retiredEdges  int64 // non-destructive retired-edge count
	existingNodes int64
	existingEdges int64

	retiredPrior []string // prior gen ids passed to the (non-destructive) retirement count
	destructive  []string // gen ids passed to any DESTRUCTIVE retirement delete (must stay empty)
	taggedGen    []string // gen ids passed to generation tagging
}

func newCountingGraphDB() *countingGraphDB {
	return &countingGraphDB{MockGraphDB: &graph.MockGraphDB{}}
}

func (c *countingGraphDB) Query(ctx context.Context, cypher string, params map[string]any) ([]map[string]any, error) {
	switch {
	case strings.Contains(cypher, "$prior IN coalesce(n.generations"):
		c.retiredPrior = append(c.retiredPrior, stringParam(params, "prior"))
		return []map[string]any{{"c": c.retiredNodes}}, nil
	case strings.Contains(cypher, "$prior IN coalesce(r.generations"):
		c.retiredPrior = append(c.retiredPrior, stringParam(params, "prior"))
		return []map[string]any{{"c": c.retiredEdges}}, nil
	case strings.Contains(cypher, "$gen IN coalesce(n.generations"):
		return []map[string]any{{"c": c.genNodesTotal}}, nil
	case strings.Contains(cypher, "$gen IN coalesce(r.generations"):
		return []map[string]any{{"c": c.genEdgesTotal}}, nil
	case cypher == cypherCountNodes:
		return []map[string]any{{"c": c.nodesTotal}}, nil
	case cypher == cypherCountEdges:
		return []map[string]any{{"c": c.edgesTotal}}, nil
	case strings.Contains(cypher, "UNWIND $ids"):
		return []map[string]any{{"c": c.existingNodes}}, nil
	case strings.Contains(cypher, "UNWIND $edges"):
		return []map[string]any{{"c": c.existingEdges}}, nil
	default:
		// findingsQuery and anything else: no rows.
		return nil, nil
	}
}

func (c *countingGraphDB) ExecuteWrite(ctx context.Context, cypher string, params map[string]any) (int, error) {
	gen, _ := params["gen"].(string)
	switch {
	case strings.Contains(cypher, "SET n.generation_id"), strings.Contains(cypher, "SET r.generation_id"):
		c.taggedGen = append(c.taggedGen, gen)
	case strings.Contains(cypher, "DELETE r"), strings.Contains(cypher, "DELETE n"):
		// Any destructive delete during ingest is a regression: retention is
		// non-destructive now.
		c.destructive = append(c.destructive, gen)
	}
	return 0, nil
}

func stringParam(params map[string]any, key string) string {
	s, _ := params[key].(string)
	return s
}

func completeCoverageData(scanID string) *sdkingest.IngestData {
	d := validIngestDataFor(scanID)
	d.Meta.Coverage = &sdkingest.CollectionCoverage{Status: sdkingest.StatusComplete}
	return d
}

func TestPipeline_GenerationPromotedOnCompleteCoverage(t *testing.T) {
	w := &fakeWriter{}
	db := newCountingGraphDB()
	ss := &fakeScanStore{current: map[string]*model.Scan{
		"mcp": {ID: "scan-prev", Collector: "mcp", GenerationID: "gen-prev", IsCurrent: true},
	}}
	p := newTestPipeline(w, db, ss, noOpRunPP)

	res, err := p.Ingest(context.Background(), completeCoverageData("scan-gen"))
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	if res.GenerationID == "" {
		t.Fatal("expected a generation id on the result")
	}
	if res.Status != sdkingest.StatusComplete {
		t.Errorf("expected complete status, got %q", res.Status)
	}

	// Promotion happened for the mcp scope.
	if got := ss.promotedIDs(); len(got) != 1 || got[0] != "scan-gen" {
		t.Errorf("expected scan-gen promoted, got %v", got)
	}

	// Complete coverage + a prior generation → retention COUNTS the prior gen's
	// absent facts, non-destructively (so a later delete can restore it).
	if len(db.retiredPrior) == 0 {
		t.Fatal("expected retention to run against the prior generation")
	}
	for _, g := range db.retiredPrior {
		if g != "gen-prev" {
			t.Errorf("retention should target gen-prev, got %q", g)
		}
	}
	// Retention must NOT destroy any facts during ingest.
	if len(db.destructive) != 0 {
		t.Errorf("retention must be non-destructive; saw destructive deletes for %v", db.destructive)
	}

	// Generation tagging ran with the new generation id.
	if len(db.taggedGen) == 0 {
		t.Fatal("expected generation tagging to run")
	}
	for _, g := range db.taggedGen {
		if g != res.GenerationID {
			t.Errorf("tagging should use the new generation id %q, got %q", res.GenerationID, g)
		}
	}

	// Outcome persisted with succeeded write + promotion stages.
	out, ok := ss.lastOutcome("scan-gen")
	if !ok {
		t.Fatal("expected a recorded generation outcome")
	}
	if out.StageStates[sdkingest.StageWrite] != sdkingest.StageSucceeded {
		t.Errorf("write stage: got %q", out.StageStates[sdkingest.StageWrite])
	}
	if out.StageStates[sdkingest.StagePromotion] != sdkingest.StageSucceeded {
		t.Errorf("promotion stage: got %q", out.StageStates[sdkingest.StagePromotion])
	}
}

func TestPipeline_PartialCoverageRetainsPriorGeneration(t *testing.T) {
	w := &fakeWriter{}
	db := newCountingGraphDB()
	ss := &fakeScanStore{current: map[string]*model.Scan{
		"mcp": {ID: "scan-prev", Collector: "mcp", GenerationID: "gen-prev", IsCurrent: true,
			CoverageStatus: sdkingest.StatusComplete},
	}}
	p := newTestPipeline(w, db, ss, noOpRunPP)

	d := validIngestDataFor("scan-partial")
	d.Meta.Coverage = &sdkingest.CollectionCoverage{Status: sdkingest.StatusPartial}

	if _, err := p.Ingest(context.Background(), d); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	// Partial coverage must NOT retire prior facts (no retention count, and
	// certainly no destructive delete).
	if len(db.retiredPrior) != 0 {
		t.Errorf("partial coverage must retain prior generation; retire counts=%v", db.retiredPrior)
	}
	if len(db.destructive) != 0 {
		t.Errorf("partial coverage must not destroy facts; destructive=%v", db.destructive)
	}
	// A partial generation must NOT demote the complete incumbent.
	if got := ss.promotedIDs(); len(got) != 0 {
		t.Errorf("partial generation must not be promoted over complete incumbent; promotions=%v", got)
	}
}

func TestCollectorScope(t *testing.T) {
	cases := []struct {
		name string
		meta sdkingest.IngestMeta
		want string
	}{
		{"single collector mcp", sdkingest.IngestMeta{Collector: "mcp"}, "mcp"},
		{"single collector a2a", sdkingest.IngestMeta{Collector: "a2a"}, "a2a"},
		{"single collector config", sdkingest.IngestMeta{Collector: "config"}, "config"},
		{"local bundle", sdkingest.IngestMeta{Collector: "scan"}, scopeScanLocal},
		{
			"network bundle",
			sdkingest.IngestMeta{Collector: "scan", Extra: map[string]any{"network_scan_spec": "10.0.0.0/24"}},
			scopeScanNetwork,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := collectorScope(tc.meta); got != tc.want {
				t.Errorf("collectorScope(%+v) = %q, want %q", tc.meta, got, tc.want)
			}
		})
	}
	// The two bundle localities MUST be distinct scopes so they never share a
	// current pointer / retention domain.
	if collectorScope(sdkingest.IngestMeta{Collector: "scan"}) ==
		collectorScope(sdkingest.IngestMeta{Collector: "scan", Extra: map[string]any{"network_scan_spec": "x"}}) {
		t.Fatal("local and network scan bundles must occupy distinct scopes")
	}
}

// TestPipeline_NetworkScopeDoesNotDemoteLocal is the scope-separation
// counterexample: a partial network sweep (scope scan:network) must not demote
// or retire a complete local bundle (scope scan:local) even though both carry
// collector "scan".
func TestPipeline_NetworkScopeDoesNotDemoteLocal(t *testing.T) {
	w := &fakeWriter{}
	db := newCountingGraphDB()
	// A complete local bundle is the current generation for scope scan:local.
	ss := &fakeScanStore{current: map[string]*model.Scan{
		scopeScanLocal: {ID: "scan-local", Collector: "scan", Scope: scopeScanLocal,
			GenerationID: "gen-local", IsCurrent: true, CoverageStatus: sdkingest.StatusComplete},
	}}
	p := newTestPipeline(w, db, ss, noOpRunPP)

	// A partial network sweep of remote hosts.
	d := validIngestDataFor("scan-net")
	d.Meta.Collector = "scan"
	d.Meta.Extra = map[string]any{"network_scan_spec": "10.0.0.0/24"}
	d.Meta.Coverage = &sdkingest.CollectionCoverage{Status: sdkingest.StatusPartial}

	if _, err := p.Ingest(context.Background(), d); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	// The network scan is recorded under its own scope, not the local one.
	if len(ss.creates) != 1 || ss.creates[0].Scope != scopeScanNetwork {
		t.Fatalf("network scan must be scoped scan:network; creates=%+v", ss.creates)
	}
	// It is promoted independently (best/only generation for its own scope),
	// under scan:network — it never demotes scan:local.
	proms := ss.promotions
	if len(proms) != 1 || proms[0].ID != "scan-net" || proms[0].Collector != scopeScanNetwork {
		t.Fatalf("expected a single scan:network promotion of scan-net; got %+v", proms)
	}
	// It must NOT run retention against the local generation.
	if len(db.retiredPrior) != 0 {
		t.Errorf("network sweep must not retire local-scope facts; retired=%v", db.retiredPrior)
	}
	if len(db.destructive) != 0 {
		t.Errorf("network sweep must not destroy facts; destructive=%v", db.destructive)
	}
}

func TestPipeline_InventoryDeltasComputed(t *testing.T) {
	w := &fakeWriter{}
	db := newCountingGraphDB()
	// Generation-scoped after-totals: this generation observed 7 nodes / 4
	// edges. There is no prior current generation, so BeforeTotal is 0.
	db.genNodesTotal = 7
	db.genEdgesTotal = 4
	db.existingNodes = 1 // 1 of the 2 incoming nodes already existed
	db.existingEdges = 0
	ss := &fakeScanStore{}
	p := newTestPipeline(w, db, ss, noOpRunPP)

	res, err := p.Ingest(context.Background(), completeCoverageData("scan-inv"))
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if res.NodeInventory == nil || res.EdgeInventory == nil {
		t.Fatal("expected inventory deltas on the result")
	}
	// 2 distinct incoming node ids, 1 already present → 1 created, 1 updated.
	if res.NodeInventory.Created != 1 || res.NodeInventory.Updated != 1 {
		t.Errorf("node inventory: created=%d updated=%d, want 1/1", res.NodeInventory.Created, res.NodeInventory.Updated)
	}
	// Edge inventory is DISTINCT logical triples diffed against the prior
	// current generation (F6). There is no prior current generation here, so
	// nothing is "kept" (updated=0) and every triple this generation observed
	// (AfterTotal=4) is newly current → created=4.
	if res.EdgeInventory.Created != 4 || res.EdgeInventory.Updated != 0 {
		t.Errorf("edge inventory: created=%d updated=%d, want 4/0", res.EdgeInventory.Created, res.EdgeInventory.Updated)
	}
	// No prior current generation → BeforeTotal 0; AfterTotal is this
	// generation's observed count.
	if res.NodeInventory.BeforeTotal != 0 || res.NodeInventory.AfterTotal != 7 {
		t.Errorf("node before/after: got %d/%d, want 0/7", res.NodeInventory.BeforeTotal, res.NodeInventory.AfterTotal)
	}
	if res.EdgeInventory.BeforeTotal != 0 || res.EdgeInventory.AfterTotal != 4 {
		t.Errorf("edge before/after: got %d/%d, want 0/4", res.EdgeInventory.BeforeTotal, res.EdgeInventory.AfterTotal)
	}
	// Unchanged is intentionally 0 (see pipeline comment).
	if res.NodeInventory.Unchanged != 0 {
		t.Errorf("unchanged should be 0, got %d", res.NodeInventory.Unchanged)
	}
}

func TestPipeline_WriteFailureNotPromoted(t *testing.T) {
	w := &fakeWriter{nodesErr: errors.New("neo4j down")}
	db := newCountingGraphDB()
	ss := &fakeScanStore{}
	p := newTestPipeline(w, db, ss, noOpRunPP)

	_, err := p.Ingest(context.Background(), completeCoverageData("scan-wf"))
	if err == nil {
		t.Fatal("expected write error")
	}
	if len(ss.promotedIDs()) != 0 {
		t.Errorf("a failed write must not be promoted; promotions=%v", ss.promotedIDs())
	}
	out, ok := ss.lastOutcome("scan-wf")
	if !ok {
		t.Fatal("expected a failed generation outcome to be recorded")
	}
	if out.StageStates[sdkingest.StageWrite] != sdkingest.StageFailed {
		t.Errorf("write stage should be failed, got %q", out.StageStates[sdkingest.StageWrite])
	}
}

func TestPipeline_EdgeFailureRecordsPartialWrite(t *testing.T) {
	w := &fakeWriter{edgesErr: errors.New("edge write busted")}
	db := newCountingGraphDB()
	ss := &fakeScanStore{}
	p := newTestPipeline(w, db, ss, noOpRunPP)

	_, err := p.Ingest(context.Background(), completeCoverageData("scan-ef"))
	if err == nil {
		t.Fatal("expected edge-write error")
	}
	if len(ss.promotedIDs()) != 0 {
		t.Errorf("a partial write must not be promoted; promotions=%v", ss.promotedIDs())
	}
	out, ok := ss.lastOutcome("scan-ef")
	if !ok {
		t.Fatal("expected outcome recorded")
	}
	// Nodes committed, edges failed → write stage is partial, not a hidden 0/0.
	if out.StageStates[sdkingest.StageWrite] != sdkingest.StagePartial {
		t.Errorf("write stage should be partial, got %q", out.StageStates[sdkingest.StageWrite])
	}
}

// TestPipeline_PostProcessingFailureBlocksPromotion is the F4 counterexample:
// a generation whose required post-processing stage FAILED must not be promoted
// (its composite/attack-path edges are incomplete), even though node/edge
// writes committed. The generation is still recorded with an honest failed
// stage; it just never becomes the default read target.
func TestPipeline_PostProcessingFailureBlocksPromotion(t *testing.T) {
	w := &fakeWriter{}
	db := newCountingGraphDB()
	ss := &fakeScanStore{}
	failPP := func(_ context.Context, _ graph.GraphDB, _ string, _ []string) ([]graph.ProcessingStats, error) {
		return nil, errors.New("processor exploded")
	}
	p := newTestPipeline(w, db, ss, failPP)

	res, err := p.Ingest(context.Background(), completeCoverageData("scan-ppf"))
	if err != nil {
		t.Fatalf("post-processing failure must not fail the ingest: %v", err)
	}
	if len(ss.promotedIDs()) != 0 {
		t.Errorf("a failed post-processing stage must block promotion; promotions=%v", ss.promotedIDs())
	}
	if res.Status != sdkingest.StatusPartial {
		t.Errorf("expected partial status when post-processing fails, got %q", res.Status)
	}
	out, ok := ss.lastOutcome("scan-ppf")
	if !ok {
		t.Fatal("expected outcome recorded")
	}
	if out.StageStates[sdkingest.StagePostProcessing] != sdkingest.StageFailed {
		t.Errorf("post-processing stage should be failed, got %q", out.StageStates[sdkingest.StagePostProcessing])
	}
	if out.StageStates[sdkingest.StagePromotion] == sdkingest.StageSucceeded {
		t.Error("promotion stage must not be succeeded when post-processing failed")
	}
}

// TestPipeline_CredentialChainSelectionErrorFailsStage is the selection-store
// error counterexample at the pipeline level: an eligible owner artifact (a
// complete config generation) whose CurrentGenerations selection read FAILS must
// fail post-processing and NOT be promoted — a generation whose credential chain
// could not be selected must never become the default read target.
func TestPipeline_CredentialChainSelectionErrorFailsStage(t *testing.T) {
	w := &fakeWriter{}
	db := newCountingGraphDB()
	ss := &fakeScanStore{currentGensErr: errors.New("selection store down")}
	p := newTestPipeline(w, db, ss, noOpRunPP)

	// A complete config artifact is an eligible chain owner, so the selection
	// read runs and its failure must degrade post-processing.
	d := completeCoverageData("scan-selerr")
	d.Meta.Collector = "config"

	res, err := p.Ingest(context.Background(), d)
	if err != nil {
		t.Fatalf("selection failure must not hard-fail the ingest: %v", err)
	}
	if res.Status == sdkingest.StatusComplete {
		t.Errorf("ingest status = complete; want partial after selection failure")
	}
	if len(ss.promotedIDs()) != 0 {
		t.Errorf("a failed credential-chain selection must block promotion; promotions=%v", ss.promotedIDs())
	}
	out, ok := ss.lastOutcome("scan-selerr")
	if !ok {
		t.Fatal("expected outcome recorded")
	}
	if out.StageStates[sdkingest.StagePostProcessing] != sdkingest.StageFailed {
		t.Errorf("post-processing stage should be failed after selection error, got %q",
			out.StageStates[sdkingest.StagePostProcessing])
	}
	if out.StageStates[sdkingest.StagePromotion] == sdkingest.StageSucceeded {
		t.Error("promotion stage must not be succeeded when selection failed")
	}
}

// fakeSnapshotter implements findingSnapshotter with a configurable error.
type fakeSnapshotter struct{ err error }

func (f *fakeSnapshotter) InsertFindings(_ context.Context, _ string, _ []model.Finding) error {
	return f.err
}

func TestPipeline_SnapshotFailureBlocksPromotion(t *testing.T) {
	w := &fakeWriter{}
	db := newCountingGraphDB()
	ss := &fakeScanStore{}
	p := &Pipeline{
		validator:    NewValidator(),
		normalizer:   NewNormalizer(),
		writer:       w,
		graphDB:      db,
		scanStore:    ss,
		findingStore: &fakeSnapshotter{err: errors.New("pg insert down")},
		runPP:        noOpRunPP,
	}

	res, err := p.Ingest(context.Background(), completeCoverageData("scan-sf"))
	if err != nil {
		t.Fatalf("snapshot failure must not fail the ingest: %v", err)
	}
	if len(ss.promotedIDs()) != 0 {
		t.Errorf("a failed snapshot must block promotion; promotions=%v", ss.promotedIDs())
	}
	if res.Status != sdkingest.StatusPartial {
		t.Errorf("expected partial status when snapshot fails, got %q", res.Status)
	}
	out, _ := ss.lastOutcome("scan-sf")
	if out.StageStates[sdkingest.StageSnapshot] != sdkingest.StageFailed {
		t.Errorf("snapshot stage should be failed, got %q", out.StageStates[sdkingest.StageSnapshot])
	}
}
