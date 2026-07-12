package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/analysis"
	"github.com/adithyan-ak/agenthound/server/internal/appdb"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
	serveringest "github.com/adithyan-ak/agenthound/server/internal/ingest"
	"github.com/google/uuid"
)

func TestLiveImmutableGenerationObservations(t *testing.T) {
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
	defer driver.Close(ctx)
	if err := graph.InitSchema(ctx, driver); err != nil {
		t.Fatal(err)
	}
	pool, err := appdb.NewPool(pgURI)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if err := appdb.RunMigrations(ctx, pool); err != nil {
		t.Fatal(err)
	}

	writer := graph.NewWriter(driver)
	reader := graph.NewReader(driver)
	db := graph.NewDB(reader, writer)
	scans := appdb.NewScanStore(pool)
	findings := appdb.NewFindingStore(pool)
	pipeline := serveringest.NewPipeline(writer, db, scans, findings)

	suffix := uuid.NewString()
	ids := liveObservationIDs{
		agent: "live-agent-" + suffix, server: "live-server-" + suffix,
		reader: "live-reader-" + suffix, outbound: "live-outbound-" + suffix,
		resource: "live-resource-" + suffix,
	}
	scanA, scanP, scanB := "live-scan-a-"+suffix, "live-scan-p-"+suffix, "live-scan-b-"+suffix
	var genA, genP, genB string
	defer func() {
		// Remove only this test's random fixtures; never reset shared volumes.
		_, _ = db.ExecuteWrite(ctx, `MATCH (n) WHERE n.objectid IN $ids DETACH DELETE n`, map[string]any{
			"ids": []string{ids.agent, ids.server, ids.reader, ids.outbound, ids.resource},
		})
		_, _ = pool.Exec(ctx, `DELETE FROM scans WHERE id = ANY($1)`, []string{scanA, scanP, scanB})
	}()

	resA, err := pipeline.Ingest(ctx, liveObservationArtifact(scanA, ids, "A", sdkingest.StatusComplete))
	if err != nil {
		t.Fatalf("ingest A: %v", err)
	}
	genA = resA.GenerationID
	assertLiveNodeMarker(t, ctx, reader, ids.server, genA, "A")
	assertLiveComposite(t, ctx, db, genA, "CAN_EXFILTRATE_VIA", true)

	// Partial P writes a different immutable observation, but cannot mutate or
	// replace A's promoted view.
	resP, err := pipeline.Ingest(ctx, liveObservationArtifact(scanP, ids, "P", sdkingest.StatusPartial))
	if err != nil {
		t.Fatalf("ingest partial P: %v", err)
	}
	genP = resP.GenerationID
	current, err := scans.CurrentScanForScope(ctx, "config")
	if err != nil {
		t.Fatal(err)
	}
	if current == nil || current.GenerationID != genA {
		t.Fatalf("partial P replaced A: current=%+v, want generation %s", current, genA)
	}
	assertLiveNodeMarker(t, ctx, reader, ids.server, genA, "A")
	assertLiveNodeMarker(t, ctx, reader, ids.server, genP, "P")

	// No processor may join observations from different generations.
	rows, err := db.Query(ctx, `MATCH (a)-[r]->(b)
WHERE a.generation_id <> b.generation_id AND
      (a.generation_id IN $gens OR b.generation_id IN $gens)
RETURN count(r) AS c`, map[string]any{"gens": []string{genA, genP}})
	if err != nil {
		t.Fatal(err)
	}
	if firstIntColumn(rows) != 0 {
		t.Fatal("processor created a cross-generation relationship")
	}

	// Complete B supersedes A without overwriting it.
	resB, err := pipeline.Ingest(ctx, liveObservationArtifact(scanB, ids, "B", sdkingest.StatusComplete))
	if err != nil {
		t.Fatalf("ingest B: %v", err)
	}
	genB = resB.GenerationID
	assertLiveNodeMarker(t, ctx, reader, ids.server, genB, "B")
	assertLiveNodeMarker(t, ctx, reader, ids.server, genA, "A")
	assertLiveComposite(t, ctx, db, genA, "CAN_EXFILTRATE_VIA", true)
	assertLiveComposite(t, ctx, db, genB, "CAN_EXFILTRATE_VIA", true)

	// Delete B through the real coordinated handler. PriorValidScanForScope
	// must skip partial P and rematerialize complete A.
	scanH := NewScanHandler(scans, findings, db)
	scanH.SetCoordinator(pipeline.Coordinator())
	w := httptest.NewRecorder()
	req := newTestRequest(http.MethodDelete, "/api/v1/scans/"+scanB, nil)
	req = withChiURLParam(req, "id", scanB)
	scanH.HandleDelete(w, req)
	if w.Code != http.StatusNoContent {
		t.Fatalf("delete B: status=%d body=%s", w.Code, w.Body.String())
	}
	current, err = scans.CurrentScanForScope(ctx, "config")
	if err != nil {
		t.Fatal(err)
	}
	if current == nil || current.GenerationID != genA {
		t.Fatalf("delete B did not restore A: current=%+v want=%s", current, genA)
	}
	assertLiveNodeMarker(t, ctx, reader, ids.server, genA, "A")
	assertLiveComposite(t, ctx, db, genA, "CAN_EXFILTRATE_VIA", true)
	assertLiveComposite(t, ctx, db, genB, "CAN_EXFILTRATE_VIA", false)

	// Persisted impact/composite evidence must survive subsequent graph
	// mutation. Mutate the live A composite after its finding snapshot, then
	// verify detail still reports the snapshotted "high" sensitivity.
	items, _, err := findings.ListCurrentFindings(ctx, appdb.FindingQuery{
		GenerationIDs: []string{genA}, IncludeSuppressed: true, Limit: 100,
	})
	if err != nil {
		t.Fatal(err)
	}
	var findingID string
	for _, f := range items {
		if f.EdgeKind == "CAN_EXFILTRATE_VIA" {
			findingID = f.ID
			if f.CompositeProps["resource_sensitivity"] != "high" {
				t.Fatalf("persisted composite sensitivity=%v, want high", f.CompositeProps["resource_sensitivity"])
			}
			break
		}
	}
	if findingID == "" {
		t.Fatal("expected persisted CAN_EXFILTRATE_VIA finding")
	}
	if _, err := db.ExecuteWrite(ctx, `MATCH ()-[r:CAN_EXFILTRATE_VIA]->()
WHERE r.generation_id = $gen SET r.resource_sensitivity = 'mutated'`, map[string]any{"gen": genA}); err != nil {
		t.Fatal(err)
	}
	analysisH := NewAnalysisHandler(db, findings, scans)
	w = httptest.NewRecorder()
	req = newTestRequest(http.MethodGet, "/api/v1/analysis/findings/"+findingID, nil)
	req = withChiURLParam(req, "id", findingID)
	analysisH.HandleFindingDetail(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("detail: status=%d body=%s", w.Code, w.Body.String())
	}
	var detail analysis.FindingDetail
	if err := json.NewDecoder(w.Body).Decode(&detail); err != nil {
		t.Fatal(err)
	}
	if detail.CompositeProps["resource_sensitivity"] != "high" {
		t.Fatalf("detail used mutable graph evidence: got %v want high", detail.CompositeProps["resource_sensitivity"])
	}
	if detail.Impact == nil || detail.Impact.DataSensitivity != "high" {
		t.Fatalf("impact did not use persisted evidence: %+v", detail.Impact)
	}

	// Complete the artifact → ingest → findings/detail/export E2E journey
	// against the same promoted generation and live stores.
	dashboardH := NewDashboardHandler(reader, findings, scans, pool)
	w = httptest.NewRecorder()
	req = newTestRequest(http.MethodGet, "/api/v1/analysis/export", nil)
	dashboardH.HandleExport(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("export: status=%d body=%s", w.Code, w.Body.String())
	}
	if w.Body.Len() == 0 {
		t.Fatal("export returned an empty body")
	}
}

type liveObservationIDs struct {
	agent, server, reader, outbound, resource string
}

func liveObservationArtifact(scanID string, ids liveObservationIDs, marker string, status sdkingest.CollectionStatus) *sdkingest.IngestData {
	return &sdkingest.IngestData{
		Meta: sdkingest.IngestMeta{
			Version: 1, Type: "agenthound-ingest", Collector: "config",
			CollectorVersion: "test", Timestamp: "2026-07-11T00:00:00Z", ScanID: scanID,
			Coverage: &sdkingest.CollectionCoverage{Status: status},
		},
		Graph: sdkingest.GraphData{
			Nodes: []sdkingest.Node{
				{ID: ids.agent, Kinds: []string{"AgentInstance"}, Properties: map[string]any{"name": "agent"}},
				{ID: ids.server, Kinds: []string{"MCPServer"}, Properties: map[string]any{"name": "server", "marker": marker}},
				{ID: ids.reader, Kinds: []string{"MCPTool"}, Properties: map[string]any{
					"name": "reader", "description": "read secret", "capability_surface": []string{"file_read"},
				}},
				{ID: ids.outbound, Kinds: []string{"MCPTool"}, Properties: map[string]any{
					"name": "outbound", "description": "send", "capability_surface": []string{"email_send"},
				}},
				{ID: ids.resource, Kinds: []string{"MCPResource"}, Properties: map[string]any{
					"name": "secret", "uri": "file:///secret", "uri_scheme": "file", "sensitivity": "high",
				}},
			},
			Edges: []sdkingest.Edge{
				{Source: ids.agent, Target: ids.server, Kind: "TRUSTS_SERVER"},
				{Source: ids.server, Target: ids.reader, Kind: "PROVIDES_TOOL"},
				{Source: ids.server, Target: ids.outbound, Kind: "PROVIDES_TOOL"},
				{Source: ids.server, Target: ids.resource, Kind: "PROVIDES_RESOURCE"},
			},
		},
	}
}

func assertLiveNodeMarker(t *testing.T, ctx context.Context, reader *graph.Reader, id, gen, want string) {
	t.Helper()
	node, _, err := reader.GetNode(ctx, id, []string{gen})
	if err != nil {
		t.Fatal(err)
	}
	if node == nil || node.Properties["marker"] != want {
		t.Fatalf("node %s generation %s marker=%v, want %s", id, gen, node, want)
	}
}

func assertLiveComposite(t *testing.T, ctx context.Context, db graph.GraphDB, gen, kind string, want bool) {
	t.Helper()
	rows, err := db.Query(ctx, `MATCH ()-[r]->()
WHERE r.generation_id = $gen AND type(r) = $kind RETURN count(r) AS c`,
		map[string]any{"gen": gen, "kind": kind})
	if err != nil {
		t.Fatal(err)
	}
	got := firstIntColumn(rows) > 0
	if got != want {
		t.Fatalf("generation %s composite %s exists=%v, want %v", gen, kind, got, want)
	}
}
