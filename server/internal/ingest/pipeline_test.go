package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/appdb"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/adithyan-ak/agenthound/server/model"
)

// --- existing testdata-driven tests (kept; they cover the validator + normalizer
//     against real fixture files) ------------------------------------------------

func TestValidateTestDataFiles(t *testing.T) {
	v := NewValidator()

	validFiles := []struct {
		file      string
		nodeCount int
		edgeCount int
	}{
		{"valid_mcp_scan.json", 5, 4},
		{"valid_config_scan.json", 7, 8},
		{"valid_a2a_scan.json", 5, 4},
		{"valid_merged_scan.json", -1, -1}, // count varies
	}

	testdataDir := filepath.Join("..", "..", "testdata")

	for _, tc := range validFiles {
		path := filepath.Join(testdataDir, tc.file)
		data, err := os.ReadFile(path)
		if err != nil {
			// Try alternate name for merged
			if tc.file == "valid_merged_scan.json" {
				path = filepath.Join(testdataDir, "merged_scan.json")
				data, err = os.ReadFile(path)
			}
			if err != nil {
				t.Logf("skipping %s: %v", tc.file, err)
				continue
			}
		}

		var d sdkingest.IngestData
		if err := json.Unmarshal(data, &d); err != nil {
			t.Errorf("%s: parse error: %v", tc.file, err)
			continue
		}

		if err := v.Validate(&d); err != nil {
			t.Errorf("%s: validation failed: %v", tc.file, err)
			continue
		}

		if tc.nodeCount > 0 && len(d.Graph.Nodes) != tc.nodeCount {
			t.Errorf("%s: expected %d nodes, got %d", tc.file, tc.nodeCount, len(d.Graph.Nodes))
		}
		if tc.edgeCount > 0 && len(d.Graph.Edges) != tc.edgeCount {
			t.Errorf("%s: expected %d edges, got %d", tc.file, tc.edgeCount, len(d.Graph.Edges))
		}
	}
}

func TestInvalidTestDataRejected(t *testing.T) {
	v := NewValidator()
	testdataDir := filepath.Join("..", "..", "testdata")

	data, err := os.ReadFile(filepath.Join(testdataDir, "invalid_scan.json"))
	if err != nil {
		t.Skipf("testdata not found: %v", err)
	}

	var d sdkingest.IngestData
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatalf("parse error: %v", err)
	}

	err = v.Validate(&d)
	if err == nil {
		t.Fatal("expected validation error for invalid_scan.json")
	}

	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected ValidationError, got %T", err)
	}

	if len(ve.Errors) < 3 {
		t.Errorf("expected at least 3 validation errors, got %d: %+v", len(ve.Errors), ve.Errors)
	}
}

func TestMCPServerIDMergePoint(t *testing.T) {
	testdataDir := filepath.Join("..", "..", "testdata")

	mcpData, err := os.ReadFile(filepath.Join(testdataDir, "valid_mcp_scan.json"))
	if err != nil {
		t.Skipf("testdata not found: %v", err)
	}
	cfgData, err := os.ReadFile(filepath.Join(testdataDir, "valid_config_scan.json"))
	if err != nil {
		t.Skipf("testdata not found: %v", err)
	}

	var mcp, cfg sdkingest.IngestData
	if err := json.Unmarshal(mcpData, &mcp); err != nil {
		t.Fatalf("parse mcp: %v", err)
	}
	if err := json.Unmarshal(cfgData, &cfg); err != nil {
		t.Fatalf("parse config: %v", err)
	}

	mcpServerIDs := make(map[string]bool)
	for _, n := range mcp.Graph.Nodes {
		for _, k := range n.Kinds {
			if k == "MCPServer" {
				mcpServerIDs[n.ID] = true
			}
		}
	}

	cfgServerIDs := make(map[string]bool)
	for _, n := range cfg.Graph.Nodes {
		for _, k := range n.Kinds {
			if k == "MCPServer" {
				cfgServerIDs[n.ID] = true
			}
		}
	}

	overlap := 0
	for id := range mcpServerIDs {
		if cfgServerIDs[id] {
			overlap++
		}
	}

	if overlap == 0 {
		t.Errorf("no MCPServer IDs match between mcp and config scans\nmcp: %v\nconfig: %v", mcpServerIDs, cfgServerIDs)
	}
}

func TestNormalizerWithTestData(t *testing.T) {
	testdataDir := filepath.Join("..", "..", "testdata")
	data, err := os.ReadFile(filepath.Join(testdataDir, "valid_mcp_scan.json"))
	if err != nil {
		t.Skipf("testdata not found: %v", err)
	}

	var d sdkingest.IngestData
	if err := json.Unmarshal(data, &d); err != nil {
		t.Fatalf("parse: %v", err)
	}

	n := NewNormalizer()
	n.Normalize(&d)

	for _, node := range d.Graph.Nodes {
		if node.Properties["objectid"] != node.ID {
			t.Errorf("node %s: objectid mismatch: %v != %v", node.ID, node.Properties["objectid"], node.ID)
		}
	}

	for _, node := range d.Graph.Nodes {
		for k, v := range node.Properties {
			if v == nil {
				t.Errorf("node %s: nil value for key %q", node.ID, k)
			}
		}
	}
}

// --- Pipeline.Ingest unit tests ----------------------------------------------

// fakeWriter implements nodeEdgeWriter and records every call. Lets us
// assert ordering, scan-id propagation, and concurrency serialization.
type fakeWriter struct {
	mu sync.Mutex

	nodeCalls []writerNodeCall
	edgeCalls []writerEdgeCall

	// Configurable returns.
	nodesErr          error
	edgesErr          error
	nodesWrittenOnErr int
	edgesWrittenOnErr int

	// Atomic flag tripped when WriteNodes is in flight; used by the
	// concurrency test to prove the mutex actually serializes.
	inFlight    atomic.Int32
	maxInFlight atomic.Int32
}

type writerNodeCall struct {
	ScanID         string
	Nodes          []sdkingest.Node
	CompleteScopes []string
	At             time.Time
}

type writerEdgeCall struct {
	ScanID         string
	Edges          []sdkingest.Edge
	CompleteScopes []string
	At             time.Time
}

func (f *fakeWriter) WriteObservationNodes(
	_ context.Context,
	nodes []sdkingest.Node,
	scanID string,
	completeScopes []string,
) (int, error) {
	cur := f.inFlight.Add(1)
	defer f.inFlight.Add(-1)
	for {
		max := f.maxInFlight.Load()
		if cur <= max || f.maxInFlight.CompareAndSwap(max, cur) {
			break
		}
	}
	// Tiny sleep to widen the concurrency window. Real writes are far
	// slower; under -race this surfaces serialization violations.
	time.Sleep(2 * time.Millisecond)

	f.mu.Lock()
	defer f.mu.Unlock()
	f.nodeCalls = append(f.nodeCalls, writerNodeCall{
		ScanID:         scanID,
		Nodes:          nodes,
		CompleteScopes: append([]string(nil), completeScopes...),
		At:             time.Now(),
	})
	if f.nodesErr != nil {
		return f.nodesWrittenOnErr, f.nodesErr
	}
	return len(nodes), nil
}

func (f *fakeWriter) WriteObservationEdges(
	_ context.Context,
	edges []sdkingest.Edge,
	scanID string,
	completeScopes []string,
) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.edgeCalls = append(f.edgeCalls, writerEdgeCall{
		ScanID:         scanID,
		Edges:          edges,
		CompleteScopes: append([]string(nil), completeScopes...),
		At:             time.Now(),
	})
	if f.edgesErr != nil {
		return f.edgesWrittenOnErr, f.edgesErr
	}
	return len(edges), nil
}

// fakeScanStore implements the mandatory lifecycle seam.
type fakeScanStore struct {
	mu            sync.Mutex
	creates       []*model.Scan
	updates       []scanUpdate
	dirtyCoverage []string
	retired       []string
	resolvedRoots []sdkingest.CoverageRoot

	createErr  error
	resolveErr error
	updateErr  error
}

type fakeLifecycleScanStore struct {
	*fakeScanStore
	dirtyCoverage []string
	failures      []appdb.ScanFailure
}

func (s *fakeLifecycleScanStore) BeginScan(
	ctx context.Context,
	scan *model.Scan,
	dirtyCoverage []string,
) ([]string, error) {
	seen := make(map[string]bool)
	merged := append([]string(nil), s.dirtyCoverage...)
	for _, key := range merged {
		seen[key] = true
	}
	for _, key := range dirtyCoverage {
		if key != "" && !seen[key] {
			seen[key] = true
			merged = append(merged, key)
		}
	}
	s.dirtyCoverage = append([]string(nil), merged...)
	return merged, s.CreateScan(ctx, scan)
}

func (s *fakeLifecycleScanStore) RecordFailure(
	_ context.Context,
	failure appdb.ScanFailure,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, key := range failure.DirtyCoverage {
		found := false
		for _, existing := range s.dirtyCoverage {
			if existing == key {
				found = true
				break
			}
		}
		if key != "" && !found {
			s.dirtyCoverage = append(s.dirtyCoverage, key)
		}
	}
	s.failures = append(s.failures, failure)
	s.updates = append(s.updates, scanUpdate{
		ID:        failure.ID,
		Status:    failure.Status,
		NodeCount: failure.NodeWriteRows,
		EdgeCount: failure.EdgeWriteRows,
		Error:     failure.Error,
	})
	return s.updateErr
}

func (s *fakeScanStore) BeginScan(
	ctx context.Context,
	scan *model.Scan,
	dirtyCoverage []string,
) ([]string, error) {
	s.mu.Lock()
	merged := mergeCoverage(s.dirtyCoverage, dirtyCoverage)
	s.dirtyCoverage = append([]string(nil), merged...)
	s.mu.Unlock()
	return merged, s.CreateScan(ctx, scan)
}

func (s *fakeScanStore) ResolveRetiredCoverage(
	_ context.Context,
	roots []sdkingest.CoverageRoot,
) ([]string, error) {
	s.resolvedRoots = append([]sdkingest.CoverageRoot(nil), roots...)
	if len(roots) == 0 {
		return nil, s.resolveErr
	}
	return append([]string(nil), s.retired...), s.resolveErr
}

func (s *fakeScanStore) RecordFailure(
	_ context.Context,
	failure appdb.ScanFailure,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dirtyCoverage = mergeCoverage(s.dirtyCoverage, failure.DirtyCoverage)
	s.updates = append(s.updates, scanUpdate{
		ID:        failure.ID,
		Status:    failure.Status,
		NodeCount: failure.NodeWriteRows,
		EdgeCount: failure.EdgeWriteRows,
		Error:     failure.Error,
	})
	return s.updateErr
}

type scanUpdate struct {
	ID        string
	Status    string
	NodeCount int
	EdgeCount int
	Error     string
}

func (s *fakeScanStore) CreateScan(_ context.Context, scan *model.Scan) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *scan
	s.creates = append(s.creates, &cp)
	return s.createErr
}

func (s *fakeScanStore) lastUpdate(id string) (scanUpdate, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.updates) - 1; i >= 0; i-- {
		if s.updates[i].ID == id {
			return s.updates[i], true
		}
	}
	return scanUpdate{}, false
}

type fakePublisher struct {
	finalizations []appdb.FinalizeScanParams
	err           error
	lifecycle     *fakeLifecycleScanStore
	scanStore     *fakeScanStore
}

func (p *fakePublisher) FinalizeScan(
	_ context.Context,
	params appdb.FinalizeScanParams,
) (*appdb.PublicationResult, error) {
	p.finalizations = append(p.finalizations, params)
	if p.err != nil {
		return nil, p.err
	}
	scanStore := p.scanStore
	if p.lifecycle != nil {
		scanStore = p.lifecycle.fakeScanStore
		if params.Publish {
			p.lifecycle.dirtyCoverage = nil
		} else {
			p.lifecycle.dirtyCoverage = append(
				[]string(nil),
				params.DirtyCoverage...,
			)
		}
	}
	if scanStore != nil {
		scanStore.mu.Lock()
		if params.Publish {
			scanStore.dirtyCoverage = nil
		} else {
			scanStore.dirtyCoverage = append([]string(nil), params.DirtyCoverage...)
		}
		scanStore.updates = append(scanStore.updates, scanUpdate{
			ID:        params.Scan.ID,
			Status:    params.Scan.Status,
			NodeCount: params.Scan.NodeWriteRows,
			EdgeCount: params.Scan.EdgeWriteRows,
			Error:     params.Scan.Error,
		})
		scanStore.mu.Unlock()
	}
	if !params.Publish {
		return &appdb.PublicationResult{}, nil
	}
	revision := int64(7)
	publishedAt := time.Now().UTC()
	return &appdb.PublicationResult{
		Revision:    &revision,
		PublishedAt: &publishedAt,
		Published:   true,
	}, nil
}

// newTestPipeline wires the mandatory lifecycle/publication interfaces to
// in-memory recorders while retaining the production constructor's test seams.
func newTestPipeline(w nodeEdgeWriter, db graph.GraphDB, ss scanLifecycleRecorder, runPP postProcessFunc) *Pipeline {
	var scanStore *fakeScanStore
	switch store := ss.(type) {
	case *fakeScanStore:
		scanStore = store
	case *fakeLifecycleScanStore:
		scanStore = store.fakeScanStore
	}
	return &Pipeline{
		validator:  NewValidator(),
		normalizer: NewNormalizer(),
		writer:     w,
		graphDB:    db,
		scanStore:  ss,
		findingStore: &fakePublisher{
			scanStore: scanStore,
		},
		runPP: runPP,
	}
}

// validIngestDataFor returns a minimal-but-valid IngestData: 2 nodes, 1 edge
// (PROVIDES_TOOL: MCPServer -> MCPTool), ready to feed Pipeline.Ingest.
func validIngestDataFor(scanID string) *sdkingest.IngestData {
	data := validIngestData()
	data.Meta.ScanID = scanID
	return data
}

func noOpRunPP(_ context.Context, _ graph.GraphDB, _ string, _ []string) ([]graph.ProcessingStats, error) {
	return nil, nil
}

func TestPipeline_HappyPath(t *testing.T) {
	w := &fakeWriter{}
	ss := &fakeScanStore{}
	db := &graph.MockGraphDB{}

	var ppCalls int
	runPP := func(_ context.Context, _ graph.GraphDB, scanID string, completeDomains []string) ([]graph.ProcessingStats, error) {
		ppCalls++
		if scanID != "scan-happy" {
			t.Errorf("post-processor: expected scan_id=scan-happy, got %s", scanID)
		}
		wantDomain := validIngestDataFor("unused").Meta.Collection.CoverageKeys[0]
		if len(completeDomains) != 1 || completeDomains[0] != wantDomain {
			t.Errorf(
				"post-processor: expected complete domains=[%s], got %v",
				wantDomain,
				completeDomains,
			)
		}
		return []graph.ProcessingStats{{ProcessorName: "has_access_to", EdgesCreated: 3}}, nil
	}

	p := newTestPipeline(w, db, ss, runPP)
	res, err := p.Ingest(context.Background(), validIngestDataFor("scan-happy"))
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	// Result fields
	if res.ScanID != "scan-happy" {
		t.Errorf("ScanID: got %s", res.ScanID)
	}
	if res.WriteRows.Nodes != 2 {
		t.Errorf("node write rows: got %d, want 2", res.WriteRows.Nodes)
	}
	if res.WriteRows.Edges != 1 {
		t.Errorf("edge write rows: got %d, want 1", res.WriteRows.Edges)
	}
	if len(res.PostProcessingStats) != 1 || res.PostProcessingStats[0].ProcessorName != "has_access_to" {
		t.Errorf("PostProcessingStats not propagated: %+v", res.PostProcessingStats)
	}
	if res.Duration <= 0 {
		t.Errorf("Duration should be > 0, got %v", res.Duration)
	}

	// Scan store was called once create + once update(completed)
	if len(ss.creates) != 1 {
		t.Fatalf("expected 1 CreateScan, got %d", len(ss.creates))
	}
	if ss.creates[0].ID != "scan-happy" || ss.creates[0].Status != model.ScanStatusRunning {
		t.Errorf("CreateScan: got %+v", ss.creates[0])
	}
	upd, ok := ss.lastUpdate("scan-happy")
	if !ok {
		t.Fatal("expected at least one UpdateScan call")
	}
	if upd.Status != model.ScanStatusCompleted {
		t.Errorf("expected final status=completed, got %s", upd.Status)
	}
	if upd.NodeCount != 2 || upd.EdgeCount != 1 {
		t.Errorf("update counts: got nodes=%d edges=%d", upd.NodeCount, upd.EdgeCount)
	}

	// Writer received correct payload
	if len(w.nodeCalls) != 1 || len(w.nodeCalls[0].Nodes) != 2 {
		t.Errorf("WriteNodes: expected 1 call with 2 nodes; got %+v", w.nodeCalls)
	}
	if len(w.edgeCalls) != 1 || len(w.edgeCalls[0].Edges) != 1 {
		t.Errorf("WriteEdges: expected 1 call with 1 edge; got %+v", w.edgeCalls)
	}

	if ppCalls != 1 {
		t.Errorf("expected 1 post-processor invocation, got %d", ppCalls)
	}
}

func TestPipeline_ExhaustiveRootReconcilesRemovedChildAsCompleteEmpty(t *testing.T) {
	data := validIngestDataFor("scan-removed-child")
	currentChild := data.Meta.Collection.CoverageKeys[0]
	root := sdkingest.CanonicalCoverageKey("mcp", "root", "collect")
	removedChild := sdkingest.CanonicalCoverageKey(
		"mcp",
		"target",
		"https://removed.example",
	)
	data.Meta.Collection.CoverageKeys = append(
		data.Meta.Collection.CoverageKeys,
		root,
	)
	data.Meta.Collection.Outcomes = append(
		data.Meta.Collection.Outcomes,
		sdkingest.CollectionOutcome{
			Collector:   "mcp",
			CoverageKey: root,
			Target:      "mcp",
			Method:      "collect",
			State:       sdkingest.OutcomeComplete,
		},
	)
	data.Meta.Collection.AuthoritativeRoots = []sdkingest.CoverageRoot{{
		CoverageKey:       root,
		ChildCoverageKeys: []string{currentChild},
	}}

	writer := &fakeWriter{}
	store := &fakeScanStore{retired: []string{removedChild}}
	db := &graph.MockGraphDB{}
	publisher := &fakePublisher{scanStore: store}
	var postProcessDomains []string
	p := newTestPipeline(
		writer,
		db,
		store,
		func(
			_ context.Context,
			_ graph.GraphDB,
			_ string,
			domains []string,
		) ([]graph.ProcessingStats, error) {
			postProcessDomains = append([]string(nil), domains...)
			return nil, nil
		},
	)
	p.findingStore = publisher

	result, err := p.Ingest(context.Background(), data)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if result.Outcome != sdkingest.OutcomeComplete {
		t.Fatalf("result outcome = %q, want complete", result.Outcome)
	}
	wantReconciled := mergeCoverage([]string{currentChild, root, removedChild})
	if got := writer.nodeCalls[0].CompleteScopes; strings.Join(got, "\x00") != strings.Join(wantReconciled, "\x00") {
		t.Fatalf("writer complete scopes = %v, want %v", got, wantReconciled)
	}
	if strings.Join(postProcessDomains, "\x00") !=
		strings.Join(wantReconciled, "\x00") {
		t.Fatalf(
			"post-process domains = %v, want %v",
			postProcessDomains,
			wantReconciled,
		)
	}
	if len(publisher.finalizations) != 1 {
		t.Fatalf("finalizations = %d, want 1", len(publisher.finalizations))
	}
	finalized := publisher.finalizations[0]
	if got := finalized.CompleteDomains; strings.Join(got, "\x00") !=
		strings.Join(mergeCoverage([]string{currentChild, root}), "\x00") {
		t.Fatalf("promoted heads = %v, want current child and root", got)
	}
	if len(finalized.ResolvedDirtyCoverage) != 1 ||
		finalized.ResolvedDirtyCoverage[0] != removedChild {
		t.Fatalf(
			"resolved removed coverage = %v, want [%s]",
			finalized.ResolvedDirtyCoverage,
			removedChild,
		)
	}
	if len(finalized.AuthoritativeRoots) != 1 ||
		finalized.AuthoritativeRoots[0].CoverageKey != root {
		t.Fatalf("finalized authoritative roots = %+v", finalized.AuthoritativeRoots)
	}
}

func TestPipeline_TargetedScanDoesNotResolveSiblingChildren(t *testing.T) {
	store := &fakeScanStore{retired: []string{
		sdkingest.CanonicalCoverageKey("mcp", "target", "sibling"),
	}}
	writer := &fakeWriter{}
	p := newTestPipeline(
		writer,
		&graph.MockGraphDB{},
		store,
		noOpRunPP,
	)

	if _, err := p.Ingest(
		context.Background(),
		validIngestDataFor("scan-targeted"),
	); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(store.resolvedRoots) != 0 {
		t.Fatalf("targeted scan resolved authoritative roots: %+v", store.resolvedRoots)
	}
	if got := writer.nodeCalls[0].CompleteScopes; len(got) != 1 {
		t.Fatalf("targeted scan reconciled sibling scopes: %v", got)
	}
}

func TestPipeline_PublishesAtomicEmptySnapshotAfterRequiredStages(t *testing.T) {
	w := &fakeWriter{}
	ss := &fakeScanStore{}
	db := &graph.MockGraphDB{
		StatsResult: &graph.GraphStats{
			NodeCounts: map[string]int64{"MCPServer": 1},
			EdgeCounts: map[string]int64{"PROVIDES_TOOL": 1},
			TotalNodes: 1,
			TotalEdges: 1,
		},
	}
	publisher := &fakePublisher{}
	p := newTestPipeline(w, db, ss, noOpRunPP)
	p.findingStore = publisher

	result, err := p.Ingest(context.Background(), validIngestDataFor("scan-publish"))
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if result.Outcome != sdkingest.OutcomeComplete ||
		result.ProjectionStatus != model.ProjectionComplete {
		t.Fatalf("result = %+v, want complete published projection", result)
	}
	if result.PublishedRevision == nil || *result.PublishedRevision != 7 {
		t.Fatalf("published revision = %v, want 7", result.PublishedRevision)
	}
	if len(publisher.finalizations) != 1 {
		t.Fatalf("finalizations = %d, want 1", len(publisher.finalizations))
	}
	finalized := publisher.finalizations[0]
	if !finalized.Publish {
		t.Fatal("complete scan was not published")
	}
	if finalized.Findings == nil || len(finalized.Findings) != 0 {
		t.Fatalf("empty snapshot = %#v, want non-nil empty slice", finalized.Findings)
	}
	wantDomain := validIngestDataFor("unused").Meta.Collection.CoverageKeys[0]
	if len(finalized.CompleteDomains) != 1 || finalized.CompleteDomains[0] != wantDomain {
		t.Fatalf("complete domains = %v, want [%s]", finalized.CompleteDomains, wantDomain)
	}
	if finalized.GraphBefore == nil || finalized.GraphAfter == nil {
		t.Fatal("publication did not freeze before/after graph totals")
	}
}

func TestPipeline_SnapshotFailureFinalizesExplicitEmptySnapshot(t *testing.T) {
	const scanID = "scan-snapshot-retry"
	w := &fakeWriter{}
	ss := &fakeScanStore{}
	db := &graph.MockGraphDB{QueryError: errors.New("snapshot query failed")}
	publisher := &fakePublisher{scanStore: ss}
	p := newTestPipeline(w, db, ss, noOpRunPP)
	p.findingStore = publisher

	result, err := p.Ingest(context.Background(), validIngestDataFor(scanID))
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if result.Outcome != sdkingest.OutcomePartial ||
		result.ProjectionStatus != model.ProjectionIncomplete {
		t.Fatalf("result = %+v, want partial incomplete projection", result)
	}
	if len(publisher.finalizations) != 1 {
		t.Fatalf("finalizations = %d, want 1", len(publisher.finalizations))
	}
	finalized := publisher.finalizations[0]
	if finalized.Scan.ID != scanID {
		t.Fatalf("finalization scan ID = %q, want %q", finalized.Scan.ID, scanID)
	}
	if finalized.Findings == nil || len(finalized.Findings) != 0 {
		t.Fatalf("finalized snapshot = %#v, want explicit empty slice", finalized.Findings)
	}
	update, ok := ss.lastUpdate(scanID)
	if !ok || update.Status != model.ScanStatusCompletedWithErrors {
		t.Fatalf("scan update = %+v, found=%t; want completed_with_errors", update, ok)
	}
}

func TestPipeline_PartialCoverageNeverPublishesOrReconciles(t *testing.T) {
	w := &fakeWriter{}
	ss := &fakeScanStore{}
	db := &graph.MockGraphDB{}
	publisher := &fakePublisher{scanStore: ss}
	var ppDomains []string
	runPP := func(_ context.Context, _ graph.GraphDB, _ string, completeDomains []string) ([]graph.ProcessingStats, error) {
		ppDomains = append([]string(nil), completeDomains...)
		return nil, nil
	}
	p := newTestPipeline(w, db, ss, runPP)
	p.findingStore = publisher

	data := validIngestDataFor("scan-partial")
	data.Meta.Collection.State = sdkingest.OutcomePartial
	data.Meta.Collection.Outcomes[0].State = sdkingest.OutcomePartial
	result, err := p.Ingest(context.Background(), data)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if result.Outcome != sdkingest.OutcomePartial ||
		result.ProjectionStatus != model.ProjectionIncomplete {
		t.Fatalf("result = %+v, want partial incomplete projection", result)
	}
	if len(publisher.finalizations) != 1 || publisher.finalizations[0].Publish {
		t.Fatalf("partial scan publication = %+v, want withheld", publisher.finalizations)
	}
	if len(publisher.finalizations[0].CompleteDomains) != 0 {
		t.Fatalf("partial domains promoted: %v", publisher.finalizations[0].CompleteDomains)
	}
	if len(ppDomains) != 0 {
		t.Fatalf("partial coverage enabled composite replacement: %v", ppDomains)
	}
	if got := len(db.CallsTo("ExecuteWrite")); got != 0 {
		t.Fatalf("partial coverage executed %d retirement writes", got)
	}
}

func TestPipeline_IncompleteRulesetWithholdsPublication(t *testing.T) {
	tests := []struct {
		name       string
		loadState  sdkingest.OutcomeState
		loadErrors []string
		stageState sdkingest.OutcomeState
	}{
		{
			name:       "partial load",
			loadState:  sdkingest.OutcomePartial,
			stageState: sdkingest.OutcomePartial,
		},
		{
			name:       "failed load",
			loadState:  sdkingest.OutcomeFailed,
			stageState: sdkingest.OutcomeFailed,
		},
		{
			name:       "reported errors",
			loadState:  sdkingest.OutcomeComplete,
			loadErrors: []string{"custom rule parse failed"},
			stageState: sdkingest.OutcomeFailed,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			publisher := &fakePublisher{}
			p := newTestPipeline(
				&fakeWriter{},
				&graph.MockGraphDB{},
				&fakeScanStore{},
				noOpRunPP,
			)
			p.findingStore = publisher
			data := validIngestDataFor("scan-ruleset-" + strings.ReplaceAll(tt.name, " ", "-"))
			data.Meta.Ruleset.LoadState = tt.loadState
			data.Meta.Ruleset.Errors = tt.loadErrors

			result, err := p.Ingest(context.Background(), data)
			if err != nil {
				t.Fatalf("Ingest: %v", err)
			}
			if result.Outcome != sdkingest.OutcomePartial ||
				result.ProjectionStatus != model.ProjectionIncomplete ||
				result.PublishedRevision != nil {
				t.Fatalf("ruleset-incomplete result = %+v, want unpublished partial result", result)
			}
			if result.Collection.State != sdkingest.OutcomeComplete {
				t.Fatalf("result collection = %+v, want required complete report", result.Collection)
			}

			var rulesetStage *sdkingest.StageResult
			for i := range result.Stages {
				if result.Stages[i].Name == "ruleset" {
					rulesetStage = &result.Stages[i]
					break
				}
			}
			if rulesetStage == nil ||
				!rulesetStage.Required ||
				rulesetStage.State != tt.stageState ||
				rulesetStage.Error == "" {
				t.Fatalf("ruleset stage = %+v, want required %s failure detail", rulesetStage, tt.stageState)
			}
			if len(publisher.finalizations) != 1 {
				t.Fatalf("finalizations = %d, want 1", len(publisher.finalizations))
			}
			finalized := publisher.finalizations[0]
			if finalized.Publish || finalized.Ruleset != data.Meta.Ruleset {
				t.Fatalf("ruleset finalization = %+v, want persisted unpublished manifest", finalized)
			}
			scope := data.Meta.Collection.CoverageKeys[0]
			if len(finalized.DirtyCoverage) != 1 || finalized.DirtyCoverage[0] != scope {
				t.Fatalf("dirty coverage = %v, want unresolved ruleset scope %q", finalized.DirtyCoverage, scope)
			}
		})
	}
}

func TestPipeline_FailedMCPThenSuccessfulConfigKeepsMCPDirty(t *testing.T) {
	lifecycle := &fakeLifecycleScanStore{fakeScanStore: &fakeScanStore{}}
	publisher := &fakePublisher{lifecycle: lifecycle}
	p := newTestPipeline(
		&fakeWriter{},
		&graph.MockGraphDB{},
		lifecycle,
		noOpRunPP,
	)
	p.findingStore = publisher

	failedMCP := validIngestDataFor("scan-failed-mcp")
	failedMCP.Meta.Collection.State = sdkingest.OutcomeFailed
	failedMCP.Meta.Collection.Outcomes[0].State = sdkingest.OutcomeFailed
	first, err := p.Ingest(context.Background(), failedMCP)
	if err != nil {
		t.Fatalf("failed MCP ingest: %v", err)
	}
	if first.Outcome != sdkingest.OutcomePartial {
		t.Fatalf("failed MCP result = %+v", first)
	}

	successfulConfig := validIngestDataFor("scan-successful-config")
	successfulConfig.Meta.Collector = "config"
	configScope := sdkingest.CanonicalCoverageKey("config", "path", "/tmp/config.json")
	successfulConfig.Meta.Collection = &sdkingest.CollectionReport{
		State:        sdkingest.OutcomeComplete,
		CoverageKeys: []string{configScope},
		Outcomes: []sdkingest.CollectionOutcome{{
			Collector:   "config",
			CoverageKey: configScope,
			Target:      "/tmp/config.json",
			Method:      "config_discovery",
			State:       sdkingest.OutcomeComplete,
		}},
	}
	sdkingest.TagObservationDomain(&successfulConfig.Graph, configScope)
	for i := range successfulConfig.Graph.Nodes {
		successfulConfig.Graph.Nodes[i].ObservationDomains = []string{configScope}
	}
	for i := range successfulConfig.Graph.Edges {
		successfulConfig.Graph.Edges[i].ObservationDomains = []string{configScope}
	}
	second, err := p.Ingest(context.Background(), successfulConfig)
	if err != nil {
		t.Fatalf("successful config ingest: %v", err)
	}
	if second.Outcome != sdkingest.OutcomePartial ||
		second.ProjectionStatus != model.ProjectionIncomplete {
		t.Fatalf("config result laundered MCP dirtiness: %+v", second)
	}
	if len(publisher.finalizations) != 2 {
		t.Fatalf("finalizations = %d, want two", len(publisher.finalizations))
	}
	finalized := publisher.finalizations[1]
	if finalized.Publish ||
		len(finalized.DirtyCoverage) != 1 ||
		finalized.DirtyCoverage[0] != failedMCP.Meta.Collection.CoverageKeys[0] {
		t.Fatalf("config finalization = %+v, want dirty MCP only", finalized)
	}
}

func TestPipeline_PublicationFailureMarksProjectionIncomplete(t *testing.T) {
	w := &fakeWriter{}
	ss := &fakeLifecycleScanStore{fakeScanStore: &fakeScanStore{}}
	publisher := &fakePublisher{err: errors.New("publication transaction failed")}
	p := newTestPipeline(w, &graph.MockGraphDB{}, ss, noOpRunPP)
	p.findingStore = publisher

	result, err := p.Ingest(context.Background(), validIngestDataFor("scan-publication-fail"))

	if err != nil {
		t.Fatalf("post-write publication failure should be represented in stages: %v", err)
	}
	if result.Outcome != sdkingest.OutcomePartial ||
		result.ProjectionStatus != model.ProjectionIncomplete {
		t.Fatalf("result = %+v, want partial incomplete", result)
	}
	last := result.Stages[len(result.Stages)-1]
	if last.Name != "publication" || last.State != sdkingest.OutcomeFailed {
		t.Fatalf("publication stage = %+v", last)
	}
	update, ok := ss.lastUpdate("scan-publication-fail")
	if !ok || update.Status != model.ScanStatusCompletedWithErrors {
		t.Fatalf("failure lifecycle update = %+v, found=%t", update, ok)
	}
}

func TestPipeline_ObservationIncompleteFinalizeFailureMetadataWithholdsCompleteDomains(t *testing.T) {
	db := &graph.MockGraphDB{
		QueryFunc: func(
			_ context.Context,
			cypher string,
			_ map[string]any,
		) ([]map[string]any, error) {
			if strings.Contains(cypher, "incomplete_property_nodes") {
				return []map[string]any{{
					"incomplete_property_nodes":         int64(1),
					"incomplete_property_relationships": int64(0),
				}}, nil
			}
			return []map[string]any{}, nil
		},
	}
	ss := &fakeLifecycleScanStore{fakeScanStore: &fakeScanStore{}}
	publisher := &fakePublisher{err: errors.New("publication transaction failed")}
	p := newTestPipeline(&fakeWriter{}, db, ss, noOpRunPP)
	p.findingStore = publisher

	result, err := p.Ingest(
		context.Background(),
		validIngestDataFor("scan-observation-incomplete-finalize-fail"),
	)
	if err != nil {
		t.Fatalf("post-write publication failure should be represented in stages: %v", err)
	}
	if result.Outcome != sdkingest.OutcomePartial ||
		result.ProjectionStatus != model.ProjectionIncomplete {
		t.Fatalf("result = %+v, want partial incomplete", result)
	}
	if len(publisher.finalizations) != 1 ||
		len(publisher.finalizations[0].CompleteDomains) != 0 {
		t.Fatalf("finalization complete domains = %v, want none", publisher.finalizations)
	}
	if len(ss.failures) != 1 {
		t.Fatalf("recorded failures = %d, want 1", len(ss.failures))
	}
	completeDomains, ok := ss.failures[0].Metadata["complete_domains"].([]string)
	if !ok {
		t.Fatalf(
			"failure complete_domains metadata has type %T, want []string",
			ss.failures[0].Metadata["complete_domains"],
		)
	}
	if len(completeDomains) != 0 {
		t.Fatalf("failure complete_domains metadata = %v, want none", completeDomains)
	}
}

func TestPipeline_OrderingNodesBeforeEdgesBeforePostProcess(t *testing.T) {
	w := &fakeWriter{}
	ss := &fakeScanStore{}
	db := &graph.MockGraphDB{}

	var ppAt time.Time
	runPP := func(_ context.Context, _ graph.GraphDB, _ string, _ []string) ([]graph.ProcessingStats, error) {
		ppAt = time.Now()
		return nil, nil
	}

	p := newTestPipeline(w, db, ss, runPP)
	if _, err := p.Ingest(context.Background(), validIngestDataFor("scan-order")); err != nil {
		t.Fatalf("Ingest: %v", err)
	}

	if len(w.nodeCalls) != 1 || len(w.edgeCalls) != 1 {
		t.Fatal("expected one node call and one edge call")
	}
	if !w.nodeCalls[0].At.Before(w.edgeCalls[0].At) && !w.nodeCalls[0].At.Equal(w.edgeCalls[0].At) {
		t.Errorf("nodes must be written before edges; node=%v edge=%v", w.nodeCalls[0].At, w.edgeCalls[0].At)
	}
	if !w.edgeCalls[0].At.Before(ppAt) && !w.edgeCalls[0].At.Equal(ppAt) {
		t.Errorf("edges must finish before post-processing; edge=%v pp=%v", w.edgeCalls[0].At, ppAt)
	}
}

func TestPipeline_ValidationError_MissingMeta(t *testing.T) {
	w := &fakeWriter{}
	ss := &fakeScanStore{}
	p := newTestPipeline(w, &graph.MockGraphDB{}, ss, noOpRunPP)

	bad := &sdkingest.IngestData{
		// Missing meta.version, type, collector, scan_id
		Graph: sdkingest.GraphData{
			Nodes: []sdkingest.Node{{ID: "n1", Kinds: []string{"MCPServer"}}},
		},
	}

	res, err := p.Ingest(context.Background(), bad)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if res != nil {
		t.Errorf("expected nil result on validation failure, got %+v", res)
	}

	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected *ValidationError, got %T", err)
	}

	// Validator runs before scan record creation, so the scan store
	// stays untouched on validation failure.
	if len(ss.creates) != 0 || len(ss.updates) != 0 {
		t.Errorf("scan store should not be touched on validation failure; creates=%d updates=%d", len(ss.creates), len(ss.updates))
	}
	if len(w.nodeCalls) != 0 {
		t.Errorf("writer should not be called on validation failure; got %d node calls", len(w.nodeCalls))
	}
}

func TestPipeline_ValidationError_UnknownNodeKind(t *testing.T) {
	w := &fakeWriter{}
	ss := &fakeScanStore{}
	p := newTestPipeline(w, &graph.MockGraphDB{}, ss, noOpRunPP)

	bad := validIngestDataFor("scan-bad-kind")
	bad.Graph.Nodes[0].Kinds = []string{"NotARealKind"}

	_, err := p.Ingest(context.Background(), bad)
	if err == nil {
		t.Fatal("expected validation error for unknown kind")
	}
	var ve *ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("expected *ValidationError, got %T", err)
	}
	if len(w.nodeCalls) != 0 {
		t.Errorf("writer should not be called when validation fails")
	}
}

func TestPipeline_WriteNodesFailure_ScanMarkedFailed(t *testing.T) {
	wantErr := errors.New("neo4j unavailable")
	w := &fakeWriter{nodesErr: wantErr, nodesWrittenOnErr: 1}
	ss := &fakeLifecycleScanStore{fakeScanStore: &fakeScanStore{}}
	p := newTestPipeline(w, &graph.MockGraphDB{}, ss, noOpRunPP)

	res, err := p.Ingest(context.Background(), validIngestDataFor("scan-write-fail"))
	if err == nil {
		t.Fatal("expected error from write")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("expected wrapped wantErr, got %v", err)
	}
	if res == nil || res.WriteRows.Nodes != 1 {
		t.Fatalf("partial result node write rows = %+v, want 1", res)
	}

	upd, ok := ss.lastUpdate("scan-write-fail")
	if !ok {
		t.Fatal("expected scan update on failure")
	}
	if upd.Status != model.ScanStatusFailed {
		t.Errorf("expected failed status, got %s", upd.Status)
	}
	if upd.NodeCount != 1 || upd.EdgeCount != 0 {
		t.Errorf("persisted partial counts = %d/%d, want 1/0", upd.NodeCount, upd.EdgeCount)
	}
	if upd.Error == "" {
		t.Errorf("expected error message recorded, got empty string")
	}
	// Edges must not have been written if nodes failed.
	if len(w.edgeCalls) != 0 {
		t.Errorf("WriteEdges should not be called after WriteNodes fails; got %d", len(w.edgeCalls))
	}
}

func TestPipeline_LifecycleStartFailureStopsBeforeGraphMutation(t *testing.T) {
	w := &fakeWriter{}
	ss := &fakeLifecycleScanStore{fakeScanStore: &fakeScanStore{
		createErr: errors.New("postgres unavailable"),
	}}
	p := newTestPipeline(w, &graph.MockGraphDB{}, ss, noOpRunPP)

	result, err := p.Ingest(context.Background(), validIngestDataFor("scan-start-fail"))

	if err == nil {
		t.Fatal("expected lifecycle start error")
	}
	if result != nil {
		t.Fatalf("result = %+v, want nil before graph mutation", result)
	}
	if len(w.nodeCalls) != 0 || len(w.edgeCalls) != 0 {
		t.Fatalf("graph mutated after lifecycle start failure: nodes=%d edges=%d", len(w.nodeCalls), len(w.edgeCalls))
	}
}

// TestPipeline_WriteEdgesFailure_NoRollback documents an intentional design
// choice: when WriteEdges fails after a successful WriteNodes, the nodes are
// NOT rolled back. The pipeline records the scan as failed and surfaces the
// error; cleanup of partial state is the operator's responsibility (or a
// future improvement).
func TestPipeline_WriteEdgesFailure_NoRollback(t *testing.T) {
	wantErr := errors.New("edge write busted")
	w := &fakeWriter{edgesErr: wantErr, edgesWrittenOnErr: 1}
	ss := &fakeScanStore{}
	p := newTestPipeline(w, &graph.MockGraphDB{}, ss, noOpRunPP)

	res, err := p.Ingest(context.Background(), validIngestDataFor("scan-edge-fail"))
	if err == nil {
		t.Fatal("expected edge-write error")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("expected wrapped wantErr, got %v", err)
	}
	if res == nil || res.WriteRows.Nodes != 2 || res.WriteRows.Edges != 1 {
		t.Fatalf("partial result = %+v, want nodes=2 edges=1", res)
	}

	// Nodes were written before edges failed; no rollback.
	if len(w.nodeCalls) != 1 {
		t.Errorf("expected 1 WriteNodes call (no rollback), got %d", len(w.nodeCalls))
	}

	upd, ok := ss.lastUpdate("scan-edge-fail")
	if !ok {
		t.Fatal("expected scan update on failure")
	}
	if upd.Status != model.ScanStatusFailed {
		t.Errorf("expected failed status, got %s", upd.Status)
	}
	if upd.NodeCount != 2 || upd.EdgeCount != 1 {
		t.Errorf("persisted partial counts = %d/%d, want 2/1", upd.NodeCount, upd.EdgeCount)
	}
}

// TestPipeline_PostProcessorFailureMarksScanCompletedWithErrors verifies that
// when node/edge collection succeeds but analysis post-processing fails, the
// scan is recorded as completed_with_errors (NOT failed): the real, non-zero
// node/edge counts are persisted alongside the recorded error, since the graph
// was actually populated.
func TestPipeline_PostProcessorFailureMarksScanCompletedWithErrors(t *testing.T) {
	w := &fakeWriter{}
	ss := &fakeScanStore{}
	db := &graph.MockGraphDB{}
	publisher := &fakePublisher{scanStore: ss}

	runPP := func(_ context.Context, _ graph.GraphDB, _ string, _ []string) ([]graph.ProcessingStats, error) {
		return []graph.ProcessingStats{
				{ProcessorName: "has_access_to", EdgesCreated: 5},
				{ProcessorName: "can_reach", Error: "cypher syntax error"},
			},
			errors.New("post-processing partially failed")
	}

	p := newTestPipeline(w, db, ss, runPP)
	p.findingStore = publisher
	res, err := p.Ingest(context.Background(), validIngestDataFor("scan-pp-fail"))
	if err != nil {
		t.Fatalf("Ingest must not surface post-processor errors; got %v", err)
	}

	// Successful stats still propagated.
	if len(res.PostProcessingStats) != 2 {
		t.Errorf("expected 2 stats entries, got %d", len(res.PostProcessingStats))
	}

	upd, ok := ss.lastUpdate("scan-pp-fail")
	if !ok {
		t.Fatal("expected scan update")
	}
	if upd.Status != model.ScanStatusCompletedWithErrors {
		t.Errorf("expected post-processor failure to mark scan completed_with_errors; got status=%s", upd.Status)
	}
	if upd.Error == "" {
		t.Error("expected post-processing error to be recorded")
	}
	// Collection succeeded, so the real node/edge counts must still be
	// persisted (validIngestDataFor writes 2 nodes + 1 edge) — not 0/0.
	if upd.NodeCount != 2 || upd.EdgeCount != 1 {
		t.Errorf("expected committed write rows persisted (nodes=2 edges=1); got nodes=%d edges=%d", upd.NodeCount, upd.EdgeCount)
	}
	if len(publisher.finalizations) != 1 || publisher.finalizations[0].Publish {
		t.Fatalf(
			"failed composite epoch publication = %+v, want withheld",
			publisher.finalizations,
		)
	}
	if res.PublishedRevision != nil {
		t.Fatalf("failed composite epoch published revision %v", res.PublishedRevision)
	}
}

func TestPipeline_RejectsLegacyV1Artifact(t *testing.T) {
	w := &fakeWriter{}
	ss := &fakeScanStore{}
	p := newTestPipeline(w, &graph.MockGraphDB{}, ss, noOpRunPP)

	empty := &sdkingest.IngestData{
		Meta: sdkingest.IngestMeta{
			Version:          1,
			Type:             "agenthound-ingest",
			Collector:        "mcp",
			CollectorVersion: "0.1.0",
			Timestamp:        "2026-01-01T00:00:00Z",
			ScanID:           "scan-empty",
		},
		Graph: sdkingest.GraphData{},
	}

	res, err := p.Ingest(context.Background(), empty)
	if err == nil {
		t.Fatal("legacy v1 artifact was accepted")
	}
	if res != nil {
		t.Fatalf("legacy validation failure returned result: %+v", res)
	}
	if len(ss.updates) != 0 {
		t.Fatalf("legacy artifact mutated lifecycle state: %+v", ss.updates)
	}
}

func TestPipeline_NodesNoEdges(t *testing.T) {
	w := &fakeWriter{}
	ss := &fakeScanStore{}
	p := newTestPipeline(w, &graph.MockGraphDB{}, ss, noOpRunPP)

	d := validIngestDataFor("scan-no-edges")
	d.Graph.Edges = []sdkingest.Edge{}

	res, err := p.Ingest(context.Background(), d)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if res.WriteRows.Nodes != 2 {
		t.Errorf("expected 2 nodes, got %d", res.WriteRows.Nodes)
	}
	if res.WriteRows.Edges != 0 {
		t.Errorf("expected 0 edges, got %d", res.WriteRows.Edges)
	}
}

func TestPipeline_MissingLifecycleStoreStopsBeforeGraphMutation(t *testing.T) {
	w := &fakeWriter{}
	p := &Pipeline{
		validator:    NewValidator(),
		normalizer:   NewNormalizer(),
		writer:       w,
		graphDB:      &graph.MockGraphDB{},
		scanStore:    nil,
		findingStore: &fakePublisher{},
		runPP:        noOpRunPP,
	}

	res, err := p.Ingest(context.Background(), validIngestDataFor("scan-nil-store"))
	if err == nil {
		t.Fatal("expected missing lifecycle store error")
	}
	if res != nil {
		t.Fatalf("result = %+v, want nil before graph mutation", res)
	}
	if len(w.nodeCalls) != 0 || len(w.edgeCalls) != 0 {
		t.Fatal("graph mutated without lifecycle store")
	}
}

func TestPipeline_MissingPublicationStoreStopsBeforeGraphMutation(t *testing.T) {
	w := &fakeWriter{}
	p := &Pipeline{
		validator:  NewValidator(),
		normalizer: NewNormalizer(),
		writer:     w,
		graphDB:    &graph.MockGraphDB{},
		scanStore:  &fakeScanStore{},
		runPP:      noOpRunPP,
	}

	res, err := p.Ingest(context.Background(), validIngestDataFor("scan-no-publisher"))
	if err == nil {
		t.Fatal("expected missing publication store error")
	}
	if res != nil {
		t.Fatalf("result = %+v, want nil before graph mutation", res)
	}
	if len(w.nodeCalls) != 0 || len(w.edgeCalls) != 0 {
		t.Fatal("graph mutated without publication store")
	}
}

func TestPipeline_NilGraphDBSkipsPostProcessing(t *testing.T) {
	w := &fakeWriter{}
	ss := &fakeScanStore{}

	var ppCalls int
	runPP := func(_ context.Context, _ graph.GraphDB, _ string, _ []string) ([]graph.ProcessingStats, error) {
		ppCalls++
		return nil, nil
	}

	p := newTestPipeline(w, nil, ss, runPP)

	if _, err := p.Ingest(context.Background(), validIngestDataFor("scan-no-db")); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if ppCalls != 0 {
		t.Errorf("post-processor should not run when graphDB is nil; got %d calls", ppCalls)
	}
}

// TestPipeline_ConcurrentIngestSerialized fires N concurrent ingests against
// one Pipeline. The mutex must serialize them: at no point may two
// WriteNodes calls overlap, and edges from one scan must never get
// interleaved with another's. -race confirms no data races.
func TestPipeline_ConcurrentIngestSerialized(t *testing.T) {
	w := &fakeWriter{}
	ss := &fakeScanStore{}
	db := &graph.MockGraphDB{}

	p := newTestPipeline(w, db, ss, noOpRunPP)

	const N = 10
	var wg sync.WaitGroup
	errs := make(chan error, N)

	for i := 0; i < N; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			scanID := "scan-concurrent-" + intToStrI(id)
			if _, err := p.Ingest(context.Background(), validIngestDataFor(scanID)); err != nil {
				errs <- err
			}
		}(i)
	}
	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent ingest failed: %v", err)
	}

	// Mutex must keep WriteNodes serialized: max-in-flight is at most 1.
	if got := w.maxInFlight.Load(); got > 1 {
		t.Errorf("Pipeline.mu should serialize ingests; max concurrent WriteNodes was %d, want 1", got)
	}

	// All N scans completed and were recorded.
	if len(w.nodeCalls) != N {
		t.Errorf("expected %d WriteNodes calls, got %d", N, len(w.nodeCalls))
	}
	if len(ss.creates) != N {
		t.Errorf("expected %d CreateScan calls, got %d", N, len(ss.creates))
	}

	// Every scan ended in 'completed' (not failed).
	for i := 0; i < N; i++ {
		scanID := "scan-concurrent-" + intToStrI(i)
		upd, ok := ss.lastUpdate(scanID)
		if !ok {
			t.Errorf("%s: no UpdateScan", scanID)
			continue
		}
		if upd.Status != model.ScanStatusCompleted {
			t.Errorf("%s: expected completed, got %s", scanID, upd.Status)
		}
	}

	// No interleaving: the (sorted-by-time) sequence of nodeCalls must
	// have its scan_id match the corresponding edgeCalls entry.
	if len(w.nodeCalls) != len(w.edgeCalls) {
		t.Fatalf("node/edge call count mismatch: %d vs %d", len(w.nodeCalls), len(w.edgeCalls))
	}
	for i := range w.nodeCalls {
		if w.nodeCalls[i].ScanID != w.edgeCalls[i].ScanID {
			t.Errorf("interleaving detected at i=%d: node scan=%s, edge scan=%s",
				i, w.nodeCalls[i].ScanID, w.edgeCalls[i].ScanID)
		}
	}
}

// TestPipeline_PostProcessorReceivesCompleteDomains verifies that the
// post-processor epoch gate receives exact promoted scopes, not a lossy
// collector-level summary.
func TestPipeline_PostProcessorReceivesCompleteDomains(t *testing.T) {
	w := &fakeWriter{}
	ss := &fakeScanStore{}
	db := &graph.MockGraphDB{}

	var seenDomains []string
	runPP := func(_ context.Context, _ graph.GraphDB, _ string, completeDomains []string) ([]graph.ProcessingStats, error) {
		seenDomains = completeDomains
		return nil, nil
	}

	p := newTestPipeline(w, db, ss, runPP)
	d := validIngestDataFor("scan-cfg")
	d.Meta.Collector = "config"
	configScope := sdkingest.CanonicalCoverageKey("config", "path", "/tmp/config.json")
	d.Meta.Collection = &sdkingest.CollectionReport{
		State:        sdkingest.OutcomeComplete,
		CoverageKeys: []string{configScope},
		Outcomes: []sdkingest.CollectionOutcome{{
			Collector:   "config",
			CoverageKey: configScope,
			Target:      "/tmp/config.json",
			Method:      "config_discovery",
			State:       sdkingest.OutcomeComplete,
		}},
	}
	for i := range d.Graph.Nodes {
		d.Graph.Nodes[i].ObservationDomains = []string{configScope}
	}
	for i := range d.Graph.Edges {
		d.Graph.Edges[i].ObservationDomains = []string{configScope}
	}
	if _, err := p.Ingest(context.Background(), d); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(seenDomains) != 1 || seenDomains[0] != configScope {
		t.Errorf("expected complete domains=[%s], got %v", configScope, seenDomains)
	}
}

// TestPipeline_NormalizerWarningsPropagated verifies that warnings the
// normalizer emits surface in the IngestResult.
func TestPipeline_NormalizerWarningsPropagated(t *testing.T) {
	w := &fakeWriter{}
	ss := &fakeScanStore{}
	p := newTestPipeline(w, &graph.MockGraphDB{}, ss, noOpRunPP)

	d := validIngestDataFor("scan-warn")
	// A property holding a non-homogeneous slice will be JSON-serialized
	// and produce a warning.
	d.Graph.Nodes[0].Properties["mixed"] = []any{"a", 1, true}

	res, err := p.Ingest(context.Background(), d)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(res.Warnings) == 0 {
		t.Error("expected normalizer warnings, got none")
	}
}

func TestPipeline_SafeNormalizationWarningStillPublishes(t *testing.T) {
	publisher := &fakePublisher{}
	p := newTestPipeline(
		&fakeWriter{},
		&graph.MockGraphDB{},
		&fakeScanStore{},
		noOpRunPP,
	)
	p.findingStore = publisher
	data := validIngestDataFor("scan-safe-normalization-warning")
	data.Graph.Nodes[0].Properties["nested"] = map[string]any{
		"kind": "lossless-json",
	}

	result, err := p.Ingest(context.Background(), data)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if result.Outcome != sdkingest.OutcomeComplete ||
		result.NormalizationStatus != sdkingest.NormalizationStatusWarning {
		t.Fatalf("result = %+v, want published warning", result)
	}
	if len(publisher.finalizations) != 1 || !publisher.finalizations[0].Publish {
		t.Fatalf("safe warning withheld publication: %+v", publisher.finalizations)
	}
	finalized := publisher.finalizations[0]
	if finalized.NormalizationStatus != sdkingest.NormalizationStatusWarning ||
		len(finalized.NormalizationWarnings) != 1 ||
		finalized.NormalizationWarnings[0].PublicationUnsafe {
		t.Fatalf("persisted normalization classification = %+v", finalized)
	}
}

func TestPipeline_UnsafeNormalizationWarningWithholdsPublication(t *testing.T) {
	publisher := &fakePublisher{}
	p := newTestPipeline(
		&fakeWriter{},
		&graph.MockGraphDB{},
		&fakeScanStore{},
		noOpRunPP,
	)
	p.findingStore = publisher
	data := validIngestDataFor("scan-unsafe-normalization-warning")
	data.Graph.Nodes[0].Properties["nested"] = map[string]any{
		"unsupported": make(chan int),
	}

	result, err := p.Ingest(context.Background(), data)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if result.Outcome != sdkingest.OutcomePartial ||
		result.NormalizationStatus != sdkingest.NormalizationStatusDegraded {
		t.Fatalf("result = %+v, want degraded incomplete projection", result)
	}
	if len(publisher.finalizations) != 1 || publisher.finalizations[0].Publish {
		t.Fatalf("unsafe warning publication = %+v, want withheld", publisher.finalizations)
	}
	if warnings := publisher.finalizations[0].NormalizationWarnings; len(warnings) != 1 || !warnings[0].PublicationUnsafe {
		t.Fatalf("unsafe warning classification was not persisted: %+v", warnings)
	}
}

func TestPipeline_PropertyIncompleteObservationWithholdsPublication(t *testing.T) {
	db := &graph.MockGraphDB{
		QueryFunc: func(
			_ context.Context,
			cypher string,
			_ map[string]any,
		) ([]map[string]any, error) {
			if strings.Contains(cypher, "incomplete_property_nodes") {
				return []map[string]any{{
					"incomplete_property_nodes":         int64(1),
					"incomplete_property_relationships": int64(0),
				}}, nil
			}
			return []map[string]any{}, nil
		},
	}
	publisher := &fakePublisher{}
	p := newTestPipeline(&fakeWriter{}, db, &fakeScanStore{}, noOpRunPP)
	p.findingStore = publisher
	data := validIngestDataFor("scan-property-incomplete")

	result, err := p.Ingest(
		context.Background(),
		data,
	)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if result.Outcome != sdkingest.OutcomePartial ||
		result.ProjectionStatus != model.ProjectionIncomplete {
		t.Fatalf("property-incomplete result = %+v", result)
	}
	if len(publisher.finalizations) != 1 ||
		publisher.finalizations[0].Publish ||
		publisher.finalizations[0].ObservationStatus != model.LifecyclePartial {
		t.Fatalf("property-incomplete finalization = %+v", publisher.finalizations)
	}
	scope := data.Meta.Collection.CoverageKeys[0]
	if dirty := publisher.finalizations[0].DirtyCoverage; len(dirty) != 1 || dirty[0] != scope {
		t.Fatalf("property-incomplete dirty coverage = %v", dirty)
	}
}

func TestPipeline_TokenlessPublicObservationWithholdsPublication(t *testing.T) {
	db := &graph.MockGraphDB{
		QueryFunc: func(
			_ context.Context,
			cypher string,
			_ map[string]any,
		) ([]map[string]any, error) {
			if strings.Contains(cypher, "incomplete_property_nodes") {
				return []map[string]any{{
					"incomplete_property_nodes":         int64(0),
					"incomplete_property_relationships": int64(0),
					"tokenless_nodes":                   int64(1),
					"tokenless_incident_relationships":  int64(1),
				}}, nil
			}
			return []map[string]any{}, nil
		},
	}
	publisher := &fakePublisher{}
	p := newTestPipeline(&fakeWriter{}, db, &fakeScanStore{}, noOpRunPP)
	p.findingStore = publisher

	result, err := p.Ingest(
		context.Background(),
		validIngestDataFor("scan-tokenless"),
	)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if result.Outcome != sdkingest.OutcomePartial ||
		result.ProjectionStatus != model.ProjectionIncomplete {
		t.Fatalf("tokenless result = %+v, want withheld publication", result)
	}
	if len(publisher.finalizations) != 1 ||
		publisher.finalizations[0].Publish ||
		publisher.finalizations[0].ObservationDetails.TokenlessNodes != 1 ||
		publisher.finalizations[0].ObservationDetails.TokenlessIncidentRelationships != 1 {
		t.Fatalf("tokenless finalization = %+v", publisher.finalizations)
	}
}

// TestNewPipeline_ConstructsWithDefaults verifies the production
// constructor wires up validator, normalizer, and the post-processor
// runner. We pass nil for the unit-testable types we don't have here
// (Writer, GraphDB, ScanStore) — the constructor is purely structural.
func TestNewPipeline_ConstructsWithDefaults(t *testing.T) {
	p := NewPipeline(nil, nil, nil, nil)
	if p.validator == nil {
		t.Error("validator should be initialized")
	}
	if p.normalizer == nil {
		t.Error("normalizer should be initialized")
	}
	if p.runPP == nil {
		t.Error("runPP should default to analysis.RunPostProcessors")
	}
	// Nil concrete pointers must NOT become non-nil interface values
	// (that would defeat the existing `if p.scanStore != nil` guard).
	if p.writer != nil {
		t.Error("nil *graph.Writer must not surface as non-nil interface")
	}
	if p.scanStore != nil {
		t.Error("nil *appdb.ScanStore must not surface as non-nil interface")
	}
}

// TestNewPipeline_PassesConcreteThrough verifies the constructor accepts
// a real *graph.Writer and *appdb.ScanStore (passed via interface). We
// use a dummy zero-valued Writer and a typed pointer to walk through
// the non-nil branches. Construction-only — Ingest is not called.
func TestNewPipeline_PassesConcreteThrough(t *testing.T) {
	w := &graph.Writer{}
	// We don't have a real *appdb.ScanStore without a pg pool, so we
	// only validate the Writer path here. The ScanStore path is
	// exercised in production by bootstrap.go and indirectly covered
	// by integration tests.
	p := NewPipeline(w, nil, nil, nil)
	if p.writer == nil {
		t.Error("non-nil *graph.Writer should be stored as interface")
	}
}

// TestPipeline_FailScanScanStoreError exercises the recordFailure warning
// branch: WriteNodes fails AND the resulting lifecycle update also
// fails. The original write error must still be the one returned.
func TestPipeline_FailScanScanStoreError(t *testing.T) {
	wantErr := errors.New("write fail")
	w := &fakeWriter{nodesErr: wantErr}
	ss := &fakeScanStore{updateErr: errors.New("pg also down")}
	p := newTestPipeline(w, &graph.MockGraphDB{}, ss, noOpRunPP)

	_, err := p.Ingest(context.Background(), validIngestDataFor("scan-double-fail"))
	if err == nil {
		t.Fatal("expected the write error to surface even when failScan errors")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("expected the original write error, got %v", err)
	}
}

// intToStrI is a tiny helper so we avoid pulling in strconv just for the
// concurrency test's scan IDs.
func intToStrI(i int) string {
	if i == 0 {
		return "0"
	}
	var buf [20]byte
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(buf[pos:])
}
