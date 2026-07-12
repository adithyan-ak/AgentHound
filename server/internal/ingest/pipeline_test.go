package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
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
	nodesErr error
	edgesErr error

	// Atomic flag tripped when WriteNodes is in flight; used by the
	// concurrency test to prove the mutex actually serializes.
	inFlight    atomic.Int32
	maxInFlight atomic.Int32
}

type writerNodeCall struct {
	ScanID string
	Nodes  []sdkingest.Node
	At     time.Time
}

type writerEdgeCall struct {
	ScanID string
	Edges  []sdkingest.Edge
	At     time.Time
}

func (f *fakeWriter) WriteNodesForGeneration(_ context.Context, nodes []sdkingest.Node, scanID, _ string) (int, error) {
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
	f.nodeCalls = append(f.nodeCalls, writerNodeCall{ScanID: scanID, Nodes: nodes, At: time.Now()})
	if f.nodesErr != nil {
		return 0, f.nodesErr
	}
	return len(nodes), nil
}

func (f *fakeWriter) WriteEdgesForGeneration(_ context.Context, edges []sdkingest.Edge, scanID, _ string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.edgeCalls = append(f.edgeCalls, writerEdgeCall{ScanID: scanID, Edges: edges, At: time.Now()})
	if f.edgesErr != nil {
		return 0, f.edgesErr
	}
	return len(edges), nil
}

// fakeScanStore implements scanRecorder.
type fakeScanStore struct {
	mu      sync.Mutex
	creates []*model.Scan
	updates []scanUpdate

	createErr error
	updateErr error
	// currentGensErr, when set, makes CurrentGenerations fail so tests can
	// exercise the credential-chain selection-error propagation path.
	currentGensErr error

	// Generation-aware recording.
	outcomes   []*model.Scan
	promotions []scanPromotion
	// current maps a collector scope to the scan CurrentScanForScope returns.
	current map[string]*model.Scan
}

type scanUpdate struct {
	ID        string
	Status    string
	NodeCount int
	EdgeCount int
	Error     string
}

type scanPromotion struct {
	ID        string
	Collector string
}

func (s *fakeScanStore) CreateScan(_ context.Context, scan *model.Scan) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *scan
	s.creates = append(s.creates, &cp)
	return s.createErr
}

func (s *fakeScanStore) UpdateScan(_ context.Context, id, status string, nodeCount, edgeCount int, scanErr string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.updates = append(s.updates, scanUpdate{ID: id, Status: status, NodeCount: nodeCount, EdgeCount: edgeCount, Error: scanErr})
	return s.updateErr
}

func (s *fakeScanStore) RecordGenerationOutcome(_ context.Context, scan *model.Scan) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *scan
	s.outcomes = append(s.outcomes, &cp)
	return nil
}

func (s *fakeScanStore) CurrentScanForScope(_ context.Context, collector string) (*model.Scan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.current == nil {
		return nil, nil
	}
	return s.current[collector], nil
}

func (s *fakeScanStore) PromoteGeneration(_ context.Context, id, collector string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.promotions = append(s.promotions, scanPromotion{ID: id, Collector: collector})
	return nil
}

func (s *fakeScanStore) CurrentGenerations(_ context.Context) ([]model.Scan, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.currentGensErr != nil {
		return nil, s.currentGensErr
	}
	var out []model.Scan
	for _, sc := range s.current {
		if sc != nil {
			out = append(out, *sc)
		}
	}
	return out, nil
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

func (s *fakeScanStore) lastOutcome(id string) (*model.Scan, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := len(s.outcomes) - 1; i >= 0; i-- {
		if s.outcomes[i].ID == id {
			return s.outcomes[i], true
		}
	}
	return nil, false
}

func (s *fakeScanStore) promotedIDs() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]string, 0, len(s.promotions))
	for _, p := range s.promotions {
		out = append(out, p.ID)
	}
	return out
}

// newTestPipeline wires the unit-test mocks together. The production
// NewPipeline takes concrete types, so test code constructs the struct
// directly via this helper. The interface fields make this safe.
func newTestPipeline(w nodeEdgeWriter, db graph.GraphDB, ss scanRecorder, runPP postProcessFunc) *Pipeline {
	return &Pipeline{
		coord:      NewCoordinator(),
		validator:  NewValidator(),
		normalizer: NewNormalizer(),
		writer:     w,
		graphDB:    db,
		scanStore:  ss,
		runPP:      runPP,
	}
}

// validIngestDataFor returns a minimal-but-valid IngestData: 2 nodes, 1 edge
// (PROVIDES_TOOL: MCPServer -> MCPTool), ready to feed Pipeline.Ingest.
func validIngestDataFor(scanID string) *sdkingest.IngestData {
	return &sdkingest.IngestData{
		Meta: sdkingest.IngestMeta{
			Version:          1,
			Type:             "agenthound-ingest",
			Collector:        "mcp",
			CollectorVersion: "0.1.0",
			Timestamp:        "2026-01-01T00:00:00Z",
			ScanID:           scanID,
		},
		Graph: sdkingest.GraphData{
			Nodes: []sdkingest.Node{
				{ID: "srv-1", Kinds: []string{"MCPServer"}, Properties: map[string]any{"name": "s1"}},
				{ID: "tool-1", Kinds: []string{"MCPTool"}, Properties: map[string]any{"name": "t1"}},
			},
			Edges: []sdkingest.Edge{
				{Source: "srv-1", Target: "tool-1", Kind: "PROVIDES_TOOL"},
			},
		},
	}
}

func noOpRunPP(_ context.Context, _ graph.GraphDB, _ string, _ []string) ([]graph.ProcessingStats, error) {
	return nil, nil
}

func TestPipeline_HappyPath(t *testing.T) {
	w := &fakeWriter{}
	ss := &fakeScanStore{}
	db := &graph.MockGraphDB{}

	var ppCalls int
	runPP := func(_ context.Context, _ graph.GraphDB, scanID string, collectors []string) ([]graph.ProcessingStats, error) {
		ppCalls++
		if scanID != "scan-happy" {
			t.Errorf("post-processor: expected scan_id=scan-happy, got %s", scanID)
		}
		if len(collectors) != 1 || collectors[0] != "mcp" {
			t.Errorf("post-processor: expected collectors=[mcp], got %v", collectors)
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
	if res.NodesWritten != 2 {
		t.Errorf("NodesWritten: got %d, want 2", res.NodesWritten)
	}
	if res.EdgesWritten != 1 {
		t.Errorf("EdgesWritten: got %d, want 1", res.EdgesWritten)
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
	w := &fakeWriter{nodesErr: wantErr}
	ss := &fakeScanStore{}
	p := newTestPipeline(w, &graph.MockGraphDB{}, ss, noOpRunPP)

	_, err := p.Ingest(context.Background(), validIngestDataFor("scan-write-fail"))
	if err == nil {
		t.Fatal("expected error from write")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("expected wrapped wantErr, got %v", err)
	}

	upd, ok := ss.lastUpdate("scan-write-fail")
	if !ok {
		t.Fatal("expected scan update on failure")
	}
	if upd.Status != model.ScanStatusFailed {
		t.Errorf("expected failed status, got %s", upd.Status)
	}
	if upd.Error == "" {
		t.Errorf("expected error message recorded, got empty string")
	}
	// Edges must not have been written if nodes failed.
	if len(w.edgeCalls) != 0 {
		t.Errorf("WriteEdges should not be called after WriteNodes fails; got %d", len(w.edgeCalls))
	}
}

// TestPipeline_WriteEdgesFailure_NoRollback documents an intentional design
// choice: when WriteEdges fails after a successful WriteNodes, the nodes are
// NOT rolled back. The pipeline records the scan as failed and surfaces the
// error; cleanup of partial state is the operator's responsibility (or a
// future improvement).
func TestPipeline_WriteEdgesFailure_NoRollback(t *testing.T) {
	wantErr := errors.New("edge write busted")
	w := &fakeWriter{edgesErr: wantErr}
	ss := &fakeScanStore{}
	p := newTestPipeline(w, &graph.MockGraphDB{}, ss, noOpRunPP)

	_, err := p.Ingest(context.Background(), validIngestDataFor("scan-edge-fail"))
	if err == nil {
		t.Fatal("expected edge-write error")
	}
	if !errors.Is(err, wantErr) {
		t.Errorf("expected wrapped wantErr, got %v", err)
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

	runPP := func(_ context.Context, _ graph.GraphDB, _ string, _ []string) ([]graph.ProcessingStats, error) {
		return []graph.ProcessingStats{
				{ProcessorName: "has_access_to", EdgesCreated: 5},
				{ProcessorName: "can_reach", Error: "cypher syntax error"},
			},
			errors.New("post-processing partially failed")
	}

	p := newTestPipeline(w, db, ss, runPP)
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
		t.Errorf("expected real counts persisted (nodes=2 edges=1); got nodes=%d edges=%d", upd.NodeCount, upd.EdgeCount)
	}
}

func TestPipeline_EmptyData_NodesAndEdgesZero(t *testing.T) {
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
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if res.NodesWritten != 0 || res.EdgesWritten != 0 {
		t.Errorf("expected 0/0, got %d/%d", res.NodesWritten, res.EdgesWritten)
	}

	upd, _ := ss.lastUpdate("scan-empty")
	if upd.Status != model.ScanStatusCompleted {
		t.Errorf("empty ingest still completes; got %s", upd.Status)
	}
}

func TestPipeline_NodesNoEdges(t *testing.T) {
	w := &fakeWriter{}
	ss := &fakeScanStore{}
	p := newTestPipeline(w, &graph.MockGraphDB{}, ss, noOpRunPP)

	d := validIngestDataFor("scan-no-edges")
	d.Graph.Edges = nil

	res, err := p.Ingest(context.Background(), d)
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if res.NodesWritten != 2 {
		t.Errorf("expected 2 nodes, got %d", res.NodesWritten)
	}
	if res.EdgesWritten != 0 {
		t.Errorf("expected 0 edges, got %d", res.EdgesWritten)
	}
}

// TestPipeline_NilScanStore confirms that a nil ScanStore is tolerated:
// CLI ingest paths historically allowed Pipeline construction without a
// scan recorder. We pass an explicitly-nil interface (NOT a typed nil
// pointer wrapped in a non-nil interface).
func TestPipeline_NilScanStore(t *testing.T) {
	w := &fakeWriter{}
	p := &Pipeline{
		validator:  NewValidator(),
		normalizer: NewNormalizer(),
		writer:     w,
		graphDB:    &graph.MockGraphDB{},
		scanStore:  nil, // nil interface
		runPP:      noOpRunPP,
	}

	res, err := p.Ingest(context.Background(), validIngestDataFor("scan-nil-store"))
	if err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if res.ScanID != "scan-nil-store" {
		t.Errorf("ScanID: got %s", res.ScanID)
	}
}

// TestPipeline_NilGraphDBSkipsPostProcessing verifies the guard at line 102.
func TestPipeline_NilGraphDBSkipsPostProcessing(t *testing.T) {
	w := &fakeWriter{}
	ss := &fakeScanStore{}

	var ppCalls int
	runPP := func(_ context.Context, _ graph.GraphDB, _ string, _ []string) ([]graph.ProcessingStats, error) {
		ppCalls++
		return nil, nil
	}

	p := &Pipeline{
		validator:  NewValidator(),
		normalizer: NewNormalizer(),
		writer:     w,
		graphDB:    nil, // skip post-processing
		scanStore:  ss,
		runPP:      runPP,
	}

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

// TestPipeline_PostProcessorReceivesCorrectCollector verifies the
// collectors slice the Pipeline passes into RunPostProcessors comes from
// data.Meta.Collector. This is the input to the stale-edge cleanup
// scoping that the mutex documentation refers to.
func TestPipeline_PostProcessorReceivesCorrectCollector(t *testing.T) {
	w := &fakeWriter{}
	ss := &fakeScanStore{}
	db := &graph.MockGraphDB{}

	var seenCollectors []string
	runPP := func(_ context.Context, _ graph.GraphDB, _ string, collectors []string) ([]graph.ProcessingStats, error) {
		seenCollectors = collectors
		return nil, nil
	}

	p := newTestPipeline(w, db, ss, runPP)
	d := validIngestDataFor("scan-cfg")
	d.Meta.Collector = "config"
	if _, err := p.Ingest(context.Background(), d); err != nil {
		t.Fatalf("Ingest: %v", err)
	}
	if len(seenCollectors) != 1 || seenCollectors[0] != "config" {
		t.Errorf("expected collectors=[config], got %v", seenCollectors)
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

// TestPipeline_ScanStoreErrorsAreNonFatal verifies that errors from the
// scan recorder (CreateScan failing, UpdateScan failing) do not bubble up
// to the caller — pipeline writes are the source of truth, so a flaky
// PostgreSQL must not block ingest from completing.
func TestPipeline_ScanStoreErrorsAreNonFatal(t *testing.T) {
	w := &fakeWriter{}
	ss := &fakeScanStore{
		createErr: errors.New("pg create down"),
		updateErr: errors.New("pg update down"),
	}
	p := newTestPipeline(w, &graph.MockGraphDB{}, ss, noOpRunPP)

	res, err := p.Ingest(context.Background(), validIngestDataFor("scan-pg-flaky"))
	if err != nil {
		t.Fatalf("scan-store errors must be swallowed; got %v", err)
	}
	if res.NodesWritten != 2 {
		t.Errorf("expected 2 nodes written despite PG errors, got %d", res.NodesWritten)
	}
	// CreateScan + UpdateScan(completed) were both attempted.
	if len(ss.creates) != 1 {
		t.Errorf("expected 1 CreateScan attempt, got %d", len(ss.creates))
	}
	if len(ss.updates) != 1 {
		t.Errorf("expected 1 UpdateScan attempt, got %d", len(ss.updates))
	}
}

// TestPipeline_FailScanScanStoreError exercises the failScan->slog.Warn
// branch: WriteNodes fails AND the resulting failScan UpdateScan also
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
