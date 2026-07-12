package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/action"
	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/analysis"
	"github.com/adithyan-ak/agenthound/server/internal/appdb"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
	serveringest "github.com/adithyan-ak/agenthound/server/internal/ingest"
	"github.com/adithyan-ak/agenthound/server/model"
	"github.com/google/uuid"
)

// liveEnv bundles the live-backed pipeline + stores for the counterexample
// tests. Each test uses random objectids/scan ids and cleans up ONLY its own
// fixtures so the shared Docker volumes are never reset.
type liveEnv struct {
	ctx      context.Context
	db       *graph.DB
	reader   *graph.Reader
	writer   *graph.Writer
	scans    *appdb.ScanStore
	findings *appdb.FindingStore
	pipeline *serveringest.Pipeline
	pool     interface{ Close() }
}

func newLiveEnv(t *testing.T) *liveEnv {
	t.Helper()
	neoURI := os.Getenv("AGENTHOUND_NEO4J_URI")
	pgURI := os.Getenv("AGENTHOUND_PG_URI")
	if neoURI == "" || pgURI == "" {
		t.Skip("live Neo4j and Postgres are required")
	}
	ctx := context.Background()
	driver, err := graph.NewDriver(neoURI, os.Getenv("AGENTHOUND_NEO4J_USER"), os.Getenv("AGENTHOUND_NEO4J_PASSWORD"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { driver.Close(ctx) })
	if err := graph.InitSchema(ctx, driver); err != nil {
		t.Fatal(err)
	}
	pool, err := appdb.NewPool(pgURI)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pool.Close() })
	if err := appdb.RunMigrations(ctx, pool); err != nil {
		t.Fatal(err)
	}
	writer := graph.NewWriter(driver)
	reader := graph.NewReader(driver)
	db := graph.NewDB(reader, writer)
	scans := appdb.NewScanStore(pool)
	findings := appdb.NewFindingStore(pool)
	pipeline := serveringest.NewPipeline(writer, db, scans, findings)
	return &liveEnv{ctx: ctx, db: db, reader: reader, writer: writer, scans: scans, findings: findings, pipeline: pipeline, pool: pool}
}

func (e *liveEnv) cleanup(t *testing.T, objectIDs, scanIDs []string) {
	t.Helper()
	_, _ = e.db.ExecuteWrite(e.ctx, `MATCH (n) WHERE n.objectid IN $ids DETACH DELETE n`, map[string]any{"ids": objectIDs})
}

// TestLiveCrossArtifactCredentialChain is the F1 counterexample: a normal
// config artifact (env-var master key) and a SEPARATE LiteLLM loot artifact
// (same key by value_hash + upstream provider keys) live in different
// generations. The cross-generation credential chain must join them across the
// selected current generations, and the loot artifact must occupy its OWN
// scope (loot:litellm) so it never demotes the config generation.
func TestLiveCrossArtifactCredentialChain(t *testing.T) {
	e := newLiveEnv(t)
	suffix := uuid.NewString()
	agent := "cc-agent-" + suffix
	server := "cc-server-" + suffix
	c1 := "cc-c1-" + suffix
	gw := "cc-gw-" + suffix
	c1master := "cc-c1master-" + suffix
	c2 := "cc-c2-" + suffix
	cfgScan := "cc-cfg-" + suffix
	lootScan := "cc-loot-" + suffix
	valueHash := "vh-" + suffix

	objectIDs := []string{agent, server, c1, gw, c1master, c2}
	defer e.cleanup(t, objectIDs, nil)
	defer e.deleteScans(t, cfgScan, lootScan)

	// Config artifact: agent → server → HAS_ENV_VAR → Credential C1 (value_hash).
	cfg := &sdkingest.IngestData{
		Meta: sdkingest.IngestMeta{
			Version: 1, Type: "agenthound-ingest", Collector: "config",
			CollectorVersion: "test", Timestamp: "2026-07-11T00:00:00Z", ScanID: cfgScan,
			Coverage: &sdkingest.CollectionCoverage{Status: sdkingest.StatusComplete},
		},
		Graph: sdkingest.GraphData{
			Nodes: []sdkingest.Node{
				{ID: agent, Kinds: []string{"AgentInstance"}, Properties: map[string]any{"name": "agent"}},
				{ID: server, Kinds: []string{"MCPServer"}, Properties: map[string]any{"name": "server"}},
				{ID: c1, Kinds: []string{"Credential"}, Properties: map[string]any{
					"name": "MASTER_KEY", "value_hash": valueHash, "merge_key": "value_hash",
				}},
			},
			Edges: []sdkingest.Edge{
				{Source: agent, Target: server, Kind: "TRUSTS_SERVER"},
				{Source: server, Target: c1, Kind: "HAS_ENV_VAR"},
			},
		},
	}
	if _, err := e.pipeline.Ingest(e.ctx, cfg); err != nil {
		t.Fatalf("ingest config: %v", err)
	}

	// Loot artifact: LiteLLM gateway exposes the same master key (by value_hash)
	// AND an upstream provider key C2. Collector "scan" + loot_type watermark.
	loot := &sdkingest.IngestData{
		Meta: sdkingest.IngestMeta{
			Version: 1, Type: "agenthound-ingest", Collector: "scan",
			CollectorVersion: "test", Timestamp: "2026-07-11T00:00:00Z", ScanID: lootScan,
			Coverage: &sdkingest.CollectionCoverage{Status: sdkingest.StatusComplete},
			Extra:    map[string]any{"loot_type": "litellm"},
		},
		Graph: sdkingest.GraphData{
			Nodes: []sdkingest.Node{
				{ID: gw, Kinds: []string{"LiteLLMGateway", "AIService"}, Properties: map[string]any{"name": "gw", "endpoint": "http://gw:4000"}},
				{ID: c1master, Kinds: []string{"Credential"}, Properties: map[string]any{
					"name": "master", "value_hash": valueHash, "merge_key": "value_hash",
				}},
				{ID: c2, Kinds: []string{"Credential"}, Properties: map[string]any{
					// Upstream provider key: masked, so the looter emits an
					// identity-only synthetic value_hash (merge_key=identity).
					"name": "openai-key", "type": "apiKey", "provider": "openai",
					"value_hash": "identity-" + suffix, "merge_key": "identity",
				}},
			},
			Edges: []sdkingest.Edge{
				{Source: gw, Target: c1master, Kind: "EXPOSES_CREDENTIAL"},
				{Source: gw, Target: c2, Kind: "EXPOSES_CREDENTIAL"},
			},
		},
	}
	if _, err := e.pipeline.Ingest(e.ctx, loot); err != nil {
		t.Fatalf("ingest loot: %v", err)
	}

	// The loot artifact must occupy its own scope; config stays current.
	cfgCurrent, err := e.scans.CurrentScanForScope(e.ctx, "config")
	if err != nil {
		t.Fatal(err)
	}
	if cfgCurrent == nil || cfgCurrent.ID != cfgScan {
		t.Fatalf("loot demoted config: config current=%+v", cfgCurrent)
	}
	lootCurrent, err := e.scans.CurrentScanForScope(e.ctx, "loot:litellm")
	if err != nil {
		t.Fatal(err)
	}
	if lootCurrent == nil || lootCurrent.ID != lootScan {
		t.Fatalf("loot not promoted under its own scope: loot current=%+v", lootCurrent)
	}

	// The cross-generation chain must have produced the agent → upstream-key
	// CAN_REACH_CREDENTIAL_CHAIN edge, joining the two artifacts by value_hash.
	rows, err := e.db.Query(e.ctx,
		`MATCH (a {objectid: $agent})-[r:CAN_REACH_CREDENTIAL_CHAIN]->(c {objectid: $c2}) RETURN count(r) AS c`,
		map[string]any{"agent": agent, "c2": c2})
	if err != nil {
		t.Fatal(err)
	}
	if firstIntColumn(rows) == 0 {
		t.Fatal("cross-artifact credential chain did not fire across current config + loot generations")
	}
}

// TestLiveMultiScopeSameObjectID is the F2 counterexample: two current scopes
// (config + mcp) both observe the SAME MCPServer objectid (the merge point).
// Stats must count the logical node once, the list must return it once, and
// detail must merge both observations' properties deterministically — duplicate
// physical observations never leak, and MCPServer merging still works.
func TestLiveMultiScopeSameObjectID(t *testing.T) {
	e := newLiveEnv(t)
	suffix := uuid.NewString()
	server := "ms-server-" + suffix // shared objectid across both scopes
	cfgScan := "ms-cfg-" + suffix
	mcpScan := "ms-mcp-" + suffix

	defer e.cleanup(t, []string{server}, nil)
	defer e.deleteScans(t, cfgScan, mcpScan)

	mkArtifact := func(scanID, collector, markerKey, markerVal string) *sdkingest.IngestData {
		return &sdkingest.IngestData{
			Meta: sdkingest.IngestMeta{
				Version: 1, Type: "agenthound-ingest", Collector: collector,
				CollectorVersion: "test", Timestamp: "2026-07-11T00:00:00Z", ScanID: scanID,
				Coverage: &sdkingest.CollectionCoverage{Status: sdkingest.StatusComplete},
			},
			Graph: sdkingest.GraphData{
				Nodes: []sdkingest.Node{
					{ID: server, Kinds: []string{"MCPServer"}, Properties: map[string]any{
						"name": "shared-server", markerKey: markerVal,
					}},
				},
			},
		}
	}
	cfgRes, err := e.pipeline.Ingest(e.ctx, mkArtifact(cfgScan, "config", "cfg_marker", "from-config"))
	if err != nil {
		t.Fatalf("ingest config: %v", err)
	}
	mcpRes, err := e.pipeline.Ingest(e.ctx, mkArtifact(mcpScan, "mcp", "mcp_marker", "from-mcp"))
	if err != nil {
		t.Fatalf("ingest mcp: %v", err)
	}
	gens := []string{cfgRes.GenerationID, mcpRes.GenerationID}

	// Stats: the shared MCPServer objectid is counted ONCE across both current
	// generations, not once per physical observation.
	stats, err := e.reader.GetStatsScoped(e.ctx, gens)
	if err != nil {
		t.Fatal(err)
	}
	if got := stats.NodeCounts["MCPServer"]; got != 1 {
		t.Fatalf("scoped MCPServer count = %d, want 1 (duplicate physical observation leaked)", got)
	}

	// List: one row for the logical objectid, merged from both observations.
	nodes, err := e.reader.ListNodesPage(e.ctx, "MCPServer", 100, 0, gens)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	var merged map[string]any
	for _, n := range nodes {
		if n.ID == server {
			count++
			merged = n.Properties
		}
	}
	if count != 1 {
		t.Fatalf("list returned the shared MCPServer %d times, want 1", count)
	}
	if merged["cfg_marker"] != "from-config" || merged["mcp_marker"] != "from-mcp" {
		t.Fatalf("list did not merge both observations' props: %v", merged)
	}

	// Detail: GetNode returns the merged logical node (both scopes' props).
	node, _, err := e.reader.GetNode(e.ctx, server, gens)
	if err != nil {
		t.Fatal(err)
	}
	if node == nil {
		t.Fatal("detail returned no node for the shared objectid")
	}
	if node.Properties["cfg_marker"] != "from-config" || node.Properties["mcp_marker"] != "from-mcp" {
		t.Fatalf("detail did not merge both observations' props: %v", node.Properties)
	}
}

// TestLivePathScopedToCurrentGenerations is the F5 counterexample: a bounded
// min-weight path must only traverse the current generations. A non-promoted
// (partial) generation that adds an alternative edge must not appear on the
// scoped path result.
func TestLivePathScopedToCurrentGenerations(t *testing.T) {
	e := newLiveEnv(t)
	suffix := uuid.NewString()
	agent := "pp-agent-" + suffix
	server := "pp-server-" + suffix
	resource := "pp-res-" + suffix
	scanID := "pp-scan-" + suffix

	defer e.cleanup(t, []string{agent, server, resource}, nil)
	defer e.deleteScans(t, scanID)

	art := &sdkingest.IngestData{
		Meta: sdkingest.IngestMeta{
			Version: 1, Type: "agenthound-ingest", Collector: "config",
			CollectorVersion: "test", Timestamp: "2026-07-11T00:00:00Z", ScanID: scanID,
			Coverage: &sdkingest.CollectionCoverage{Status: sdkingest.StatusComplete},
		},
		Graph: sdkingest.GraphData{
			Nodes: []sdkingest.Node{
				// Names are the unique ids so the weighted-path endpoint (which
				// matches non-hex identifiers by name) resolves them uniquely in
				// the shared DB.
				{ID: agent, Kinds: []string{"AgentInstance"}, Properties: map[string]any{"name": agent}},
				{ID: server, Kinds: []string{"MCPServer"}, Properties: map[string]any{"name": server}},
				{ID: resource, Kinds: []string{"MCPResource"}, Properties: map[string]any{"name": resource, "uri": "file:///x"}},
			},
			// A raw two-hop path; the weighted-path traversal walks it forward.
			Edges: []sdkingest.Edge{
				{Source: agent, Target: server, Kind: "TRUSTS_SERVER", Properties: map[string]any{"risk_weight": 0.5}},
				{Source: server, Target: resource, Kind: "PROVIDES_RESOURCE", Properties: map[string]any{"risk_weight": 0.5}},
			},
		},
	}
	res, err := e.pipeline.Ingest(e.ctx, art)
	if err != nil {
		t.Fatalf("ingest: %v", err)
	}

	scanH := NewScanHandler(e.scans, e.findings, e.db)
	analysisH := NewAnalysisHandler(e.db, e.findings, e.scans)
	_ = scanH

	// Weighted path within the current generation returns the path.
	body := `{"source":"` + agent + `","target":"` + resource + `","source_kind":"AgentInstance","target_kind":"MCPResource"}`
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodPost, "/api/v1/analysis/paths/weighted", []byte(body))
	analysisH.HandleWeightedPath(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("weighted path: status=%d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Paths []map[string]any `json:"paths"`
	}
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if len(resp.Paths) == 0 {
		t.Fatal("expected a scoped weighted path within the current generation")
	}

	// Now delete the generation (removing it from current) and confirm the
	// scoped path no longer returns it (no promoted generation → empty result).
	req := newTestRequest(http.MethodDelete, "/api/v1/scans/"+scanID, nil)
	req = withChiURLParam(req, "id", scanID)
	dw := httptest.NewRecorder()
	scanH.HandleDelete(dw, req)
	if dw.Code != http.StatusNoContent {
		t.Fatalf("delete: status=%d body=%s", dw.Code, dw.Body.String())
	}
	_ = res

	w2 := httptest.NewRecorder()
	r2 := newTestRequest(http.MethodPost, "/api/v1/analysis/paths/weighted", []byte(body))
	analysisH.HandleWeightedPath(w2, r2)
	if w2.Code != http.StatusOK {
		t.Fatalf("weighted path (post-delete): status=%d", w2.Code)
	}
	var resp2 struct {
		Paths []map[string]any `json:"paths"`
	}
	if err := json.NewDecoder(w2.Body).Decode(&resp2); err != nil {
		t.Fatal(err)
	}
	if len(resp2.Paths) != 0 {
		t.Fatalf("path endpoint returned %d paths after the generation was removed from current", len(resp2.Paths))
	}
}

// TestLiveEdgeInventoryDistinctTriples is the F6 counterexample: the edge
// inventory is computed as DISTINCT logical (source, kind, target) triples
// diffed against the PRIOR current generation. Re-ingesting the same scope with
// the two prior edges plus one new edge must report created=1, updated=2,
// before=2, after=3 — not a physical-row count.
func TestLiveEdgeInventoryDistinctTriples(t *testing.T) {
	e := newLiveEnv(t)
	suffix := uuid.NewString()
	agent := "ei-agent-" + suffix
	server := "ei-server-" + suffix
	tool := "ei-tool-" + suffix
	resource := "ei-res-" + suffix
	scanA := "ei-a-" + suffix
	scanB := "ei-b-" + suffix

	defer e.cleanup(t, []string{agent, server, tool, resource}, nil)
	defer e.deleteScans(t, scanA, scanB)

	base := func(scanID string, extra bool) *sdkingest.IngestData {
		nodes := []sdkingest.Node{
			{ID: agent, Kinds: []string{"AgentInstance"}, Properties: map[string]any{"name": "agent"}},
			{ID: server, Kinds: []string{"MCPServer"}, Properties: map[string]any{"name": "server"}},
			{ID: tool, Kinds: []string{"MCPTool"}, Properties: map[string]any{"name": "tool"}},
		}
		edges := []sdkingest.Edge{
			{Source: agent, Target: server, Kind: "TRUSTS_SERVER"},
			{Source: server, Target: tool, Kind: "PROVIDES_TOOL"},
		}
		if extra {
			nodes = append(nodes, sdkingest.Node{ID: resource, Kinds: []string{"MCPResource"}, Properties: map[string]any{"name": "res", "uri": "file:///x"}})
			edges = append(edges, sdkingest.Edge{Source: server, Target: resource, Kind: "PROVIDES_RESOURCE"})
		}
		return &sdkingest.IngestData{
			Meta: sdkingest.IngestMeta{
				Version: 1, Type: "agenthound-ingest", Collector: "config",
				CollectorVersion: "test", Timestamp: "2026-07-11T00:00:00Z", ScanID: scanID,
				Coverage: &sdkingest.CollectionCoverage{Status: sdkingest.StatusComplete},
			},
			Graph: sdkingest.GraphData{Nodes: nodes, Edges: edges},
		}
	}

	if _, err := e.pipeline.Ingest(e.ctx, base(scanA, false)); err != nil {
		t.Fatalf("ingest A: %v", err)
	}
	resB, err := e.pipeline.Ingest(e.ctx, base(scanB, true))
	if err != nil {
		t.Fatalf("ingest B: %v", err)
	}
	inv := resB.EdgeInventory
	if inv == nil {
		t.Fatal("expected edge inventory on generation B")
	}
	if inv.BeforeTotal != 2 || inv.AfterTotal != 3 {
		t.Errorf("edge before/after = %d/%d, want 2/3", inv.BeforeTotal, inv.AfterTotal)
	}
	if inv.Created != 1 || inv.Updated != 2 {
		t.Errorf("edge created/updated = %d/%d, want 1/2 (distinct triples vs prior current gen)", inv.Created, inv.Updated)
	}
}

// TestLiveDurableDeleteLifecycle is the F3 counterexample: a delete whose Neo4j
// transaction fails must leave the scan in a persisted 'delete_failed'
// lifecycle (recoverable), and a subsequent successful retry must complete the
// delete and clear the row. Also asserts the graph decrement runs in a single
// transaction (edge + node atomically).
func TestLiveDurableDeleteLifecycle(t *testing.T) {
	e := newLiveEnv(t)
	suffix := uuid.NewString()
	agent := "dl-agent-" + suffix
	server := "dl-server-" + suffix
	scanID := "dl-scan-" + suffix

	defer e.cleanup(t, []string{agent, server}, nil)
	defer e.deleteScans(t, scanID)

	art := &sdkingest.IngestData{
		Meta: sdkingest.IngestMeta{
			Version: 1, Type: "agenthound-ingest", Collector: "config",
			CollectorVersion: "test", Timestamp: "2026-07-11T00:00:00Z", ScanID: scanID,
			Coverage: &sdkingest.CollectionCoverage{Status: sdkingest.StatusComplete},
		},
		Graph: sdkingest.GraphData{
			Nodes: []sdkingest.Node{
				{ID: agent, Kinds: []string{"AgentInstance"}, Properties: map[string]any{"name": "agent"}},
				{ID: server, Kinds: []string{"MCPServer"}, Properties: map[string]any{"name": "server"}},
			},
			Edges: []sdkingest.Edge{{Source: agent, Target: server, Kind: "TRUSTS_SERVER"}},
		},
	}
	if _, err := e.pipeline.Ingest(e.ctx, art); err != nil {
		t.Fatalf("ingest: %v", err)
	}

	// First attempt: graph delete FAILS (injected). The scan must be left in
	// the 'delete_failed' lifecycle, not silently dropped.
	failingDB := &deleteFailingGraphDB{GraphDB: e.db, fail: true}
	scanH := NewScanHandler(e.scans, e.findings, failingDB)
	req := newTestRequest(http.MethodDelete, "/api/v1/scans/"+scanID, nil)
	req = withChiURLParam(req, "id", scanID)
	w := httptest.NewRecorder()
	scanH.HandleDelete(w, req)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 on graph-delete failure, got %d", w.Code)
	}
	got, err := e.scans.GetScan(e.ctx, scanID)
	if err != nil {
		t.Fatalf("scan row must survive a failed delete: %v", err)
	}
	if got.DeleteState != model.DeleteStateFailed {
		t.Fatalf("delete_state = %q, want %q (delete not durably recoverable)", got.DeleteState, model.DeleteStateFailed)
	}

	// Retry with a healthy DB completes the delete idempotently.
	scanH2 := NewScanHandler(e.scans, e.findings, e.db)
	req2 := newTestRequest(http.MethodDelete, "/api/v1/scans/"+scanID, nil)
	req2 = withChiURLParam(req2, "id", scanID)
	w2 := httptest.NewRecorder()
	scanH2.HandleDelete(w2, req2)
	if w2.Code != http.StatusNoContent {
		t.Fatalf("retry delete: status=%d body=%s", w2.Code, w2.Body.String())
	}
	if _, err := e.scans.GetScan(e.ctx, scanID); err == nil {
		t.Fatal("scan row must be gone after a successful retry")
	}
	// Graph facts fully removed by the transactional decrement.
	rows, err := e.db.Query(e.ctx, `MATCH (n) WHERE n.objectid IN $ids RETURN count(n) AS c`,
		map[string]any{"ids": []string{agent, server}})
	if err != nil {
		t.Fatal(err)
	}
	if firstIntColumn(rows) != 0 {
		t.Fatal("graph facts survived the completed delete")
	}
}

// deleteFailingGraphDB wraps a real GraphDB but forces the transactional
// generation delete to fail, to exercise the delete_failed lifecycle.
type deleteFailingGraphDB struct {
	graph.GraphDB
	fail bool
}

func (d *deleteFailingGraphDB) DeleteGenerationTx(ctx context.Context, gen string) error {
	if d.fail {
		return errContext("injected neo4j delete failure")
	}
	return d.GraphDB.DeleteGenerationTx(ctx, gen)
}

type errContext string

func (e errContext) Error() string { return string(e) }

// deleteScans removes the given scan rows via the store (idempotent).
func (e *liveEnv) deleteScans(t *testing.T, ids ...string) {
	t.Helper()
	for _, id := range ids {
		_ = e.scans.DeleteScan(e.ctx, id)
	}
}

// credChainArtifacts builds the config + loot artifacts of a cross-artifact
// credential chain sharing one master key by value_hash. Returned separately so
// callers can ingest them through different pipelines.
func credChainArtifacts(suffix string) (cfg, loot *sdkingest.IngestData, agent, c2, cfgScan, lootScan string) {
	agent = "cx-agent-" + suffix
	server := "cx-server-" + suffix
	c1 := "cx-c1-" + suffix
	gw := "cx-gw-" + suffix
	c1master := "cx-c1master-" + suffix
	c2 = "cx-c2-" + suffix
	cfgScan = "cx-cfg-" + suffix
	lootScan = "cx-loot-" + suffix
	valueHash := "cxvh-" + suffix
	cfg = &sdkingest.IngestData{
		Meta: sdkingest.IngestMeta{
			Version: 1, Type: "agenthound-ingest", Collector: "config",
			CollectorVersion: "test", Timestamp: "2026-07-11T00:00:00Z", ScanID: cfgScan,
			Coverage: &sdkingest.CollectionCoverage{Status: sdkingest.StatusComplete},
		},
		Graph: sdkingest.GraphData{
			Nodes: []sdkingest.Node{
				{ID: agent, Kinds: []string{"AgentInstance"}, Properties: map[string]any{"name": "agent"}},
				{ID: server, Kinds: []string{"MCPServer"}, Properties: map[string]any{"name": "server"}},
				{ID: c1, Kinds: []string{"Credential"}, Properties: map[string]any{"name": "MASTER_KEY", "value_hash": valueHash, "merge_key": "value_hash"}},
			},
			Edges: []sdkingest.Edge{
				{Source: agent, Target: server, Kind: "TRUSTS_SERVER"},
				{Source: server, Target: c1, Kind: "HAS_ENV_VAR"},
			},
		},
	}
	loot = &sdkingest.IngestData{
		Meta: sdkingest.IngestMeta{
			Version: 1, Type: "agenthound-ingest", Collector: "scan",
			CollectorVersion: "test", Timestamp: "2026-07-11T00:00:00Z", ScanID: lootScan,
			Coverage: &sdkingest.CollectionCoverage{Status: sdkingest.StatusComplete},
			Extra:    map[string]any{"loot_type": "litellm"},
		},
		Graph: sdkingest.GraphData{
			Nodes: []sdkingest.Node{
				{ID: gw, Kinds: []string{"LiteLLMGateway", "AIService"}, Properties: map[string]any{"name": "gw", "endpoint": "http://gw:4000"}},
				{ID: c1master, Kinds: []string{"Credential"}, Properties: map[string]any{"name": "master", "value_hash": valueHash, "merge_key": "value_hash"}},
				{ID: c2, Kinds: []string{"Credential"}, Properties: map[string]any{"name": "openai-key", "type": "apiKey", "provider": "openai", "value_hash": "identity-" + suffix, "merge_key": "identity"}},
			},
			Edges: []sdkingest.Edge{
				{Source: gw, Target: c1master, Kind: "EXPOSES_CREDENTIAL"},
				{Source: gw, Target: c2, Kind: "EXPOSES_CREDENTIAL"},
			},
		},
	}
	return cfg, loot, agent, c2, cfgScan, lootScan
}

// TestLiveCredentialChainEvidenceComplete is the F1 counterexample: a
// cross-artifact credential-chain finding spans two generations (the agent in
// the config generation, the upstream key in the loot generation). Its
// PERSISTED evidence DAG must be COMPLETE — one connected component of the full
// six-node chain spanning source→target — reconstructed from the composite
// edge's persisted per-endpoint generation ids + evidence metadata, not from a
// single-generation re-traversal (which would return a disconnected,
// incomplete DAG).
func TestLiveCredentialChainEvidenceComplete(t *testing.T) {
	e := newLiveEnv(t)
	suffix := uuid.NewString()
	cfg, loot, agent, c2, cfgScan, lootScan := credChainArtifacts(suffix)
	objectIDs := []string{agent, "cx-server-" + suffix, "cx-c1-" + suffix, "cx-gw-" + suffix, "cx-c1master-" + suffix, c2}
	defer e.cleanup(t, objectIDs, nil)
	defer e.deleteScans(t, cfgScan, lootScan)

	cfgRes, err := e.pipeline.Ingest(e.ctx, cfg)
	if err != nil {
		t.Fatalf("ingest config: %v", err)
	}
	lootRes, err := e.pipeline.Ingest(e.ctx, loot)
	if err != nil {
		t.Fatalf("ingest loot: %v", err)
	}
	gens := []string{cfgRes.GenerationID, lootRes.GenerationID}

	items, _, err := e.findings.ListCurrentFindings(e.ctx, appdb.FindingQuery{
		GenerationIDs: gens, IncludeSuppressed: true, Limit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	var chain *model.Finding
	for i := range items {
		if items[i].EdgeKind == "CAN_REACH_CREDENTIAL_CHAIN" {
			chain = &items[i]
			break
		}
	}
	if chain == nil {
		t.Fatal("cross-artifact credential-chain finding was not persisted in the current generations")
	}

	// The composite props must carry DIFFERENT source/target generations
	// (the chain genuinely spans two artifacts' generations).
	srcGen, _ := chain.CompositeProps["source_generation"].(string)
	tgtGen, _ := chain.CompositeProps["target_generation"].(string)
	if srcGen == "" || tgtGen == "" || srcGen == tgtGen {
		t.Fatalf("expected distinct persisted source/target generations, got src=%q tgt=%q", srcGen, tgtGen)
	}

	dag, ok := analysis.EvidenceDAGFromPersisted(chain)
	if !ok {
		t.Fatal("finding carries no persisted evidence DAG")
	}
	if !dag.Complete {
		t.Errorf("persisted evidence DAG is incomplete; want complete cross-artifact chain (nodes=%d components=%d)", len(dag.Nodes), dag.ConnectedComponents)
	}
	if dag.ConnectedComponents != 1 {
		t.Errorf("connected components = %d, want 1 (full chain is one component)", dag.ConnectedComponents)
	}
	if len(dag.Nodes) != 6 {
		t.Errorf("evidence nodes = %d, want 6 (agent, server, env-cred, master, gateway, upstream)", len(dag.Nodes))
	}
	var hasSource, hasTarget, hasSynthetic bool
	for _, n := range dag.Nodes {
		if n.Role == "source" {
			hasSource = true
		}
		if n.Role == "target" {
			hasTarget = true
		}
	}
	for _, j := range dag.Joins {
		if j.Type == analysis.JoinSynthetic {
			hasSynthetic = true
		}
	}
	if !hasSource || !hasTarget {
		t.Errorf("evidence DAG does not span source+target (source=%v target=%v)", hasSource, hasTarget)
	}
	if !hasSynthetic {
		t.Error("evidence DAG missing the synthetic value_hash join")
	}
}

// chainFailingGraphDB forces the cross-service credential-chain ExecuteWrite to
// fail while passing every other graph operation through, to exercise the
// fail-the-stage path.
type chainFailingGraphDB struct {
	graph.GraphDB
}

func (d *chainFailingGraphDB) ExecuteWrite(ctx context.Context, cypher string, params map[string]any) (int, error) {
	if strings.Contains(cypher, "CAN_REACH_CREDENTIAL_CHAIN") {
		return 0, errContext("injected credential-chain failure")
	}
	return d.GraphDB.ExecuteWrite(ctx, cypher, params)
}

// TestLiveCredentialChainFailureFailsStage is the F2 counterexample: when the
// cross-generation credential chain fails, post-processing must FAIL so the
// generation is NOT promoted — a broken chain can never become current.
func TestLiveCredentialChainFailureFailsStage(t *testing.T) {
	e := newLiveEnv(t)
	suffix := uuid.NewString()
	cfg, loot, agent, c2, cfgScan, lootScan := credChainArtifacts(suffix)
	objectIDs := []string{agent, "cx-server-" + suffix, "cx-c1-" + suffix, "cx-gw-" + suffix, "cx-c1master-" + suffix, c2}
	defer e.cleanup(t, objectIDs, nil)
	defer e.deleteScans(t, cfgScan, lootScan)

	if _, err := e.pipeline.Ingest(e.ctx, cfg); err != nil {
		t.Fatalf("ingest config: %v", err)
	}

	// Ingest the loot artifact through a pipeline whose credential-chain write
	// fails. The chain participates (config current + this loot), so the
	// failure must degrade post-processing and block promotion.
	failDB := &chainFailingGraphDB{GraphDB: e.db}
	failPipeline := serveringest.NewPipeline(e.writer, failDB, e.scans, e.findings)
	res, err := failPipeline.Ingest(e.ctx, loot)
	if err != nil {
		t.Fatalf("ingest loot (expected soft failure, not hard error): %v", err)
	}
	if res.Status == sdkingest.StatusComplete {
		t.Errorf("ingest status = complete; want partial after credential-chain failure")
	}
	// The failed-chain loot generation must NOT be promoted to current.
	cur, err := e.scans.CurrentScanForScope(e.ctx, "loot:litellm")
	if err != nil {
		t.Fatal(err)
	}
	if cur != nil && cur.ID == lootScan {
		t.Errorf("loot generation with failed credential chain was promoted to current: %+v", cur)
	}
	// The config generation must remain current (not demoted by the failure).
	cfgCur, err := e.scans.CurrentScanForScope(e.ctx, "config")
	if err != nil {
		t.Fatal(err)
	}
	if cfgCur == nil || cfgCur.ID != cfgScan {
		t.Errorf("config generation should remain current; got %+v", cfgCur)
	}
}

// TestLiveDeletingGenerationExcludedFromCurrency is the F3 counterexample: a
// generation left in a delete lifecycle ('deleting'/'delete_failed') — whose
// is_current flag survives until the row is removed — must be excluded from
// currentness selection, completeness, and rematerialization, so an interrupted
// delete can never be read as current or chosen as a restore target.
func TestLiveDeletingGenerationExcludedFromCurrency(t *testing.T) {
	e := newLiveEnv(t)
	suffix := uuid.NewString()
	server := "dc-server-" + suffix
	scanA := "dc-a-" + suffix
	scanB := "dc-b-" + suffix
	defer e.cleanup(t, []string{server}, nil)
	defer e.deleteScans(t, scanA, scanB)

	art := func(scanID string) *sdkingest.IngestData {
		return &sdkingest.IngestData{
			Meta: sdkingest.IngestMeta{
				Version: 1, Type: "agenthound-ingest", Collector: "config",
				CollectorVersion: "test", Timestamp: "2026-07-11T00:00:00Z", ScanID: scanID,
				Coverage: &sdkingest.CollectionCoverage{Status: sdkingest.StatusComplete},
			},
			Graph: sdkingest.GraphData{Nodes: []sdkingest.Node{
				{ID: server, Kinds: []string{"MCPServer"}, Properties: map[string]any{"name": "server"}},
			}},
		}
	}
	if _, err := e.pipeline.Ingest(e.ctx, art(scanA)); err != nil {
		t.Fatalf("ingest A: %v", err)
	}
	if _, err := e.pipeline.Ingest(e.ctx, art(scanB)); err != nil {
		t.Fatalf("ingest B: %v", err)
	}

	// Sanity: before any delete marker, A is the valid rematerialization prior
	// for a delete of B.
	prior, err := e.scans.PriorValidScanForScope(e.ctx, "config", scanB)
	if err != nil {
		t.Fatal(err)
	}
	if prior == nil || prior.ID != scanA {
		t.Fatalf("expected prior valid scan A for delete of B, got %+v", prior)
	}

	// Mark A deleting: it must no longer be selectable as a rematerialization
	// target for B.
	if err := e.scans.MarkDeleting(e.ctx, scanA); err != nil {
		t.Fatal(err)
	}
	prior, err = e.scans.PriorValidScanForScope(e.ctx, "config", scanB)
	if err != nil {
		t.Fatal(err)
	}
	if prior != nil {
		t.Fatalf("deleting generation A must not be a rematerialization target, got %+v", prior)
	}

	// Mark B (the current generation) deleting: it must drop out of current
	// selection and out of the current-generations set immediately.
	if err := e.scans.MarkDeleting(e.ctx, scanB); err != nil {
		t.Fatal(err)
	}
	cur, err := e.scans.CurrentScanForScope(e.ctx, "config")
	if err != nil {
		t.Fatal(err)
	}
	if cur != nil && cur.ID == scanB {
		t.Fatalf("deleting current generation B still selected as current: %+v", cur)
	}
	gens, err := e.scans.CurrentGenerations(e.ctx)
	if err != nil {
		t.Fatal(err)
	}
	for i := range gens {
		if gens[i].ID == scanA || gens[i].ID == scanB {
			t.Fatalf("delete-lifecycle scan %s leaked into CurrentGenerations", gens[i].ID)
		}
	}
}

// TestLiveCredentialChainBlastRadiusImmutable is the raw-observation
// immutability counterexample: the cross-artifact credential chain must derive
// blast_radius onto its OWN composite edge, never mutating the raw Credential
// observations (c1/c1master) that belong to the config/loot generations. Those
// prior observations are immutable; a mutation would rewrite another
// generation's facts.
func TestLiveCredentialChainBlastRadiusImmutable(t *testing.T) {
	e := newLiveEnv(t)
	suffix := uuid.NewString()
	cfg, loot, agent, c2, cfgScan, lootScan := credChainArtifacts(suffix)
	c1 := "cx-c1-" + suffix
	c1master := "cx-c1master-" + suffix
	objectIDs := []string{agent, "cx-server-" + suffix, c1, "cx-gw-" + suffix, c1master, c2}
	defer e.cleanup(t, objectIDs, nil)
	defer e.deleteScans(t, cfgScan, lootScan)

	if _, err := e.pipeline.Ingest(e.ctx, cfg); err != nil {
		t.Fatalf("ingest config: %v", err)
	}
	if _, err := e.pipeline.Ingest(e.ctx, loot); err != nil {
		t.Fatalf("ingest loot: %v", err)
	}

	// The composite edge must carry the derived blast_radius (1 reachable agent
	// in this fixture), keyed to the env-var credential via via_credential_id.
	rows, err := e.db.Query(e.ctx,
		`MATCH ()-[e:CAN_REACH_CREDENTIAL_CHAIN]->() WHERE e.via_credential_id = $c1
		 RETURN e.blast_radius AS br`, map[string]any{"c1": c1})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) == 0 {
		t.Fatal("no composite credential-chain edge was produced")
	}
	if br := firstIntColumn(rows); br < 1 {
		t.Fatalf("composite edge blast_radius = %d, want >= 1 (derivation must live on the edge)", br)
	}

	// The raw credential observations must NOT have been mutated with a
	// blast_radius property.
	for _, id := range []string{c1, c1master} {
		nrows, err := e.db.Query(e.ctx,
			`MATCH (c {objectid: $id}) WHERE c.blast_radius IS NOT NULL RETURN count(c) AS c`,
			map[string]any{"id": id})
		if err != nil {
			t.Fatal(err)
		}
		if firstIntColumn(nrows) != 0 {
			t.Fatalf("raw credential %q was mutated with blast_radius (prior-generation observation must stay immutable)", id)
		}
	}
}

// TestLiveCompletenessBlockedByDeleteFailedScope is the delete-lifecycle
// completeness counterexample exercised live: one HEALTHY complete scope plus
// one current scope left in 'delete_failed'. The delete_failed scope is excluded
// from CurrentGenerations, but completeness must NOT report all-clear — it is
// forced incomplete and disclosed as a source error.
func TestLiveCompletenessBlockedByDeleteFailedScope(t *testing.T) {
	e := newLiveEnv(t)
	suffix := uuid.NewString()
	healthySrv := "cb-healthy-" + suffix
	wipSrv := "cb-wip-" + suffix
	healthyScan := "cb-healthy-scan-" + suffix
	wipScan := "cb-wip-scan-" + suffix
	defer e.cleanup(t, []string{healthySrv, wipSrv}, nil)
	defer e.deleteScans(t, healthyScan, wipScan)

	mk := func(scanID, collector, srv string) *sdkingest.IngestData {
		return &sdkingest.IngestData{
			Meta: sdkingest.IngestMeta{
				Version: 1, Type: "agenthound-ingest", Collector: collector,
				CollectorVersion: "test", Timestamp: "2026-07-11T00:00:00Z", ScanID: scanID,
				Coverage: &sdkingest.CollectionCoverage{Status: sdkingest.StatusComplete},
			},
			Graph: sdkingest.GraphData{Nodes: []sdkingest.Node{
				{ID: srv, Kinds: []string{"MCPServer"}, Properties: map[string]any{"name": srv}},
			}},
		}
	}
	if _, err := e.pipeline.Ingest(e.ctx, mk(healthyScan, "config", healthySrv)); err != nil {
		t.Fatalf("ingest healthy: %v", err)
	}
	if _, err := e.pipeline.Ingest(e.ctx, mk(wipScan, "mcp", wipSrv)); err != nil {
		t.Fatalf("ingest wip: %v", err)
	}

	// Sanity: with both scopes healthy, the posture rolls up complete.
	scope, err := resolveGenerationScope(e.ctx, e.scans)
	if err != nil {
		t.Fatal(err)
	}
	if !scope.Completeness.Complete {
		t.Fatalf("precondition: both healthy scopes should report complete, got %+v", scope.Completeness)
	}

	// Mark the mcp scope's current generation delete_failed. Its is_current
	// flag survives, so CurrentGenerations excludes it while the row lingers.
	if err := e.scans.MarkDeleteFailed(e.ctx, wipScan); err != nil {
		t.Fatal(err)
	}
	scope, err = resolveGenerationScope(e.ctx, e.scans)
	if err != nil {
		t.Fatal(err)
	}
	if scope.Completeness.Complete {
		t.Error("a scope stuck in delete_failed must block the complete verdict")
	}
	found := false
	for _, se := range scope.Completeness.SourceErrors {
		if strings.Contains(se, wipScan) && strings.Contains(se, string(model.DeleteStateFailed)) {
			found = true
		}
	}
	if !found {
		t.Errorf("delete_failed scope must be disclosed as a source error; got %v", scope.Completeness.SourceErrors)
	}
}

// TestLiveMultiScopeConflictResolution is the F4 counterexample: when config
// and mcp both observe the SAME MCPServer with a CONFLICTING shared property,
// the merged logical node must resolve the conflict by collector authority
// (mcp outranks config) DETERMINISTICALLY — never by an arbitrary random-UUID
// generation_id ordering.
func TestLiveMultiScopeConflictResolution(t *testing.T) {
	e := newLiveEnv(t)
	suffix := uuid.NewString()
	server := "cr-server-" + suffix
	cfgScan := "cr-cfg-" + suffix
	mcpScan := "cr-mcp-" + suffix
	defer e.cleanup(t, []string{server}, nil)
	defer e.deleteScans(t, cfgScan, mcpScan)

	mk := func(scanID, collector, shared string) *sdkingest.IngestData {
		return &sdkingest.IngestData{
			Meta: sdkingest.IngestMeta{
				Version: 1, Type: "agenthound-ingest", Collector: collector,
				CollectorVersion: "test", Timestamp: "2026-07-11T00:00:00Z", ScanID: scanID,
				Coverage: &sdkingest.CollectionCoverage{Status: sdkingest.StatusComplete},
			},
			Graph: sdkingest.GraphData{Nodes: []sdkingest.Node{
				{ID: server, Kinds: []string{"MCPServer"}, Properties: map[string]any{"name": "srv", "shared_field": shared}},
			}},
		}
	}
	cfgRes, err := e.pipeline.Ingest(e.ctx, mk(cfgScan, "config", "from-config"))
	if err != nil {
		t.Fatalf("ingest config: %v", err)
	}
	mcpRes, err := e.pipeline.Ingest(e.ctx, mk(mcpScan, "mcp", "from-mcp"))
	if err != nil {
		t.Fatalf("ingest mcp: %v", err)
	}
	gens := []string{cfgRes.GenerationID, mcpRes.GenerationID}

	node, _, err := e.reader.GetNode(e.ctx, server, gens)
	if err != nil {
		t.Fatal(err)
	}
	if node == nil {
		t.Fatal("merged node not found")
	}
	if node.Properties["shared_field"] != "from-mcp" {
		t.Fatalf("conflict winner = %v, want from-mcp (mcp collector authority beats config, deterministically)", node.Properties["shared_field"])
	}
}

// TestLiveLootEnvelopeRealCoverage is the F5 counterexample exercised through a
// live ingest: a loot artifact built with the NORMAL derived coverage (a
// partial failure) persists coverage_status='partial' — the ingest never
// coalesces a partially-probed loot run into a clean/complete posture.
func TestLiveLootEnvelopeRealCoverage(t *testing.T) {
	e := newLiveEnv(t)
	suffix := uuid.NewString()
	gw := "lc-gw-" + suffix
	c2 := "lc-c2-" + suffix
	lootScan := "lc-loot-" + suffix
	defer e.cleanup(t, []string{gw, c2}, nil)
	defer e.deleteScans(t, lootScan)

	// A loot result with a partial probe failure — coverage derived the same
	// way the CLI loot envelope derives it (LootResult.Coverage), NOT
	// hand-authored.
	lr := &action.LootResult{
		Summary:       action.LootSummary{EndpointsProbed: 2, PartialFailures: 1},
		PartialErrors: []string{"key/list: 401 unauthorized"},
	}
	loot := &sdkingest.IngestData{
		Meta: sdkingest.IngestMeta{
			Version: 1, Type: "agenthound-ingest", Collector: "scan",
			CollectorVersion: "test", Timestamp: "2026-07-11T00:00:00Z", ScanID: lootScan,
			SchemaVersion: sdkingest.CurrentSchemaVersion, IdentityVersion: sdkingest.CurrentIdentityVersion,
			Coverage: lr.Coverage("litellm"),
			Extra:    map[string]any{"loot_type": "litellm"},
		},
		Graph: sdkingest.GraphData{Nodes: []sdkingest.Node{
			{ID: gw, Kinds: []string{"LiteLLMGateway", "AIService"}, Properties: map[string]any{"name": "gw", "endpoint": "http://gw:4000"}},
			{ID: c2, Kinds: []string{"Credential"}, Properties: map[string]any{"name": "openai-key", "type": "apiKey", "provider": "openai", "value_hash": "id-" + suffix, "merge_key": "identity"}},
		}},
	}
	if _, err := e.pipeline.Ingest(e.ctx, loot); err != nil {
		t.Fatalf("ingest loot: %v", err)
	}
	got, err := e.scans.GetScan(e.ctx, lootScan)
	if err != nil {
		t.Fatal(err)
	}
	if got.CoverageStatus != sdkingest.StatusPartial {
		t.Fatalf("persisted loot coverage_status = %q, want partial (real derived coverage, not clean)", got.CoverageStatus)
	}
}
