package qdrantloot

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/action"
)

const collectionsBody = `{"result":{"collections":[{"name":"docs"},{"name":"chat-history"}]},"status":"ok","time":0.001}`

func qdrantStub(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/collections" && r.Method == "GET":
			_, _ = w.Write([]byte(collectionsBody))
		case r.URL.Path == "/collections/docs" && r.Method == "GET":
			_, _ = w.Write([]byte(`{"result":{"points_count":1200,"config":{},"payload_schema":{}},"status":"ok"}`))
		case r.URL.Path == "/collections/chat-history" && r.Method == "GET":
			_, _ = w.Write([]byte(`{"result":{"points_count":340,"config":{},"payload_schema":{}},"status":"ok"}`))
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestLoot_QdrantHappy(t *testing.T) {
	srv := qdrantStub(t)
	defer srv.Close()

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.LootOptions{})
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	if got := len(res.IngestData.Graph.Nodes); got != 1 {
		t.Fatalf("nodes: got %d, want 1 (QdrantInstance)", got)
	}
	node := res.IngestData.Graph.Nodes[0]
	if node.Kinds[0] != "QdrantInstance" {
		t.Errorf("kind = %v, want QdrantInstance", node.Kinds)
	}
	if cc, _ := node.Properties["collection_count"].(int); cc != 2 {
		t.Errorf("collection_count = %v, want 2", node.Properties["collection_count"])
	}
	// Sorted: chat-history before docs.
	names, _ := node.Properties["collections"].([]string)
	if len(names) != 2 || names[0] != "chat-history" || names[1] != "docs" {
		t.Errorf("collections = %v, want [chat-history docs] sorted", names)
	}
	if tp, _ := node.Properties["total_points"].(int64); tp != 1540 {
		t.Errorf("total_points = %v, want 1540", node.Properties["total_points"])
	}
	if ap, _ := node.Properties["anonymous_listing"].(bool); !ap {
		t.Errorf("anonymous_listing = %v, want true", node.Properties["anonymous_listing"])
	}
	if res.Summary.CredentialsFound != 0 {
		t.Errorf("CredentialsFound = %d, want 0 for metadata-only discovery", res.Summary.CredentialsFound)
	}
	if res.Summary.PartialFailures != 0 {
		t.Errorf("PartialFailures = %d, want 0", res.Summary.PartialFailures)
	}
}

// A collection that returns a bad shape is counted in the inventory but
// must not inflate total_points (defensive parse → zero, recorded as a
// partial failure).
func TestLoot_Qdrant_CollectionDetailBadJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/collections":
			_, _ = w.Write([]byte(`{"result":{"collections":[{"name":"docs"}]},"status":"ok"}`))
		case "/collections/docs":
			_, _ = w.Write([]byte(`not-json`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.LootOptions{})
	if err != nil {
		t.Fatalf("Loot should not error on partial failures: %v", err)
	}
	node := res.IngestData.Graph.Nodes[0]
	if cc, _ := node.Properties["collection_count"].(int); cc != 1 {
		t.Errorf("collection_count = %v, want 1", node.Properties["collection_count"])
	}
	if tp, _ := node.Properties["total_points"].(int64); tp != 0 {
		t.Errorf("total_points = %v, want 0 (bad detail must not fabricate points)", node.Properties["total_points"])
	}
	if res.Summary.PartialFailures != 1 {
		t.Errorf("PartialFailures = %d, want 1", res.Summary.PartialFailures)
	}
}

// A closed/unreachable port (and a non-200 listing) must not error — the
// QdrantInstance node is still emitted and the failure recorded.
func TestLoot_Qdrant_CollectionsListFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	}))
	defer srv.Close()

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.LootOptions{})
	if err != nil {
		t.Fatalf("Loot should not error on partial failures: %v", err)
	}
	if got := len(res.IngestData.Graph.Nodes); got != 1 {
		t.Fatalf("nodes: got %d, want 1 (QdrantInstance still emitted)", got)
	}
	if _, ok := res.IngestData.Graph.Nodes[0].Properties["collection_count"]; ok {
		t.Errorf("collection_count should be absent when /collections fails")
	}
	if res.Summary.PartialFailures != 1 {
		t.Errorf("PartialFailures = %d, want 1", res.Summary.PartialFailures)
	}
}

// TestLoot_Qdrant_ManyCollectionsConcurrent exercises the bounded worker
// pool with more collections than the concurrency bound, where half the
// per-collection detail probes fail. It asserts the aggregation is
// correct and order-independent: total_points sums only the good
// collections, PartialFailures counts the bad ones, and the collections
// list stays sorted regardless of goroutine completion order. Run under
// -race, it also guards the disjoint-slot writes against data races.
func TestLoot_Qdrant_ManyCollectionsConcurrent(t *testing.T) {
	const n = 50
	names := make([]string, 0, n)
	points := make(map[string]int64, n)
	bad := make(map[string]bool, n)
	var wantTotal int64
	wantFailures := 0
	for i := 0; i < n; i++ {
		nm := fmt.Sprintf("col-%02d", i)
		names = append(names, nm)
		if i%2 == 1 {
			bad[nm] = true
			wantFailures++
		} else {
			p := int64((i + 1) * 10)
			points[nm] = p
			wantTotal += p
		}
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/collections" {
			var sb strings.Builder
			sb.WriteString(`{"result":{"collections":[`)
			for i, nm := range names {
				if i > 0 {
					sb.WriteByte(',')
				}
				sb.WriteString(`{"name":"`)
				sb.WriteString(nm)
				sb.WriteString(`"}`)
			}
			sb.WriteString(`]},"status":"ok"}`)
			_, _ = w.Write([]byte(sb.String()))
			return
		}
		name := strings.TrimPrefix(r.URL.Path, "/collections/")
		if bad[name] {
			_, _ = w.Write([]byte(`not-json`))
			return
		}
		_, _ = fmt.Fprintf(w, `{"result":{"points_count":%d},"status":"ok"}`, points[name])
	}))
	defer srv.Close()

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.LootOptions{})
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	node := res.IngestData.Graph.Nodes[0]
	if cc, _ := node.Properties["collection_count"].(int); cc != n {
		t.Errorf("collection_count = %v, want %d", node.Properties["collection_count"], n)
	}
	if tp, _ := node.Properties["total_points"].(int64); tp != wantTotal {
		t.Errorf("total_points = %v, want %d", node.Properties["total_points"], wantTotal)
	}
	if res.Summary.PartialFailures != wantFailures {
		t.Errorf("PartialFailures = %d, want %d", res.Summary.PartialFailures, wantFailures)
	}
	// Assert the FULL collections slice, not just first/last: the names
	// arrive pre-sorted from sort.Strings before the pool runs, so this
	// pins both completeness AND ascending order against a future refactor
	// that moves assembly into the concurrent fold (where completion order
	// could leak through).
	got, _ := node.Properties["collections"].([]string)
	if len(got) != n {
		t.Fatalf("collections length = %d, want %d", len(got), n)
	}
	for i, nm := range names {
		if got[i] != nm {
			t.Errorf("collections[%d] = %q, want %q (sorted order broken)", i, got[i], nm)
		}
	}

	// Assert PartialErrors content/format, not just the count: the worker
	// pre-formats "collections/%s: %v" into a per-index slot (looter.go),
	// so a dropped name or mangled prefix would still pass the count check
	// above. Spot-check one bad collection's entry is present and well-formed.
	if len(res.PartialErrors) != wantFailures {
		t.Fatalf("PartialErrors length = %d, want %d", len(res.PartialErrors), wantFailures)
	}
	wantPrefix := "collections/col-01: " // col-01 is bad (odd index)
	var found bool
	for _, pe := range res.PartialErrors {
		if strings.HasPrefix(pe, wantPrefix) {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("PartialErrors missing well-formed entry with prefix %q; got %v", wantPrefix, res.PartialErrors)
	}
}

// TestLoot_Qdrant_ZeroCollections pins the conc=0 boundary: an anonymous
// Qdrant with zero collections must clamp the worker count to 0 (no
// goroutines spawned), drain the empty index channel, and return without
// deadlocking — emitting the node with collection_count=0, total_points=0.
// This is the riskiest new edge of the worker pool; a deadlock here would
// hang every scan of an empty instance.
func TestLoot_Qdrant_ZeroCollections(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/collections" {
			_, _ = w.Write([]byte(`{"result":{"collections":[]},"status":"ok"}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.LootOptions{})
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	if got := len(res.IngestData.Graph.Nodes); got != 1 {
		t.Fatalf("nodes: got %d, want 1 (QdrantInstance still emitted)", got)
	}
	node := res.IngestData.Graph.Nodes[0]
	if cc, _ := node.Properties["collection_count"].(int); cc != 0 {
		t.Errorf("collection_count = %v, want 0", node.Properties["collection_count"])
	}
	if tp, _ := node.Properties["total_points"].(int64); tp != 0 {
		t.Errorf("total_points = %v, want 0", node.Properties["total_points"])
	}
	if res.Summary.PartialFailures != 0 {
		t.Errorf("PartialFailures = %d, want 0", res.Summary.PartialFailures)
	}
}

// TestLoot_Qdrant_PointsCountAbsent — points_count is nullable per
// Qdrant's OpenAPI. A missing/null value must be counted as "unknown"
// and not conflated with a real zero via points_count_unknown.
func TestLoot_Qdrant_PointsCountAbsent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/collections":
			_, _ = w.Write([]byte(`{"result":{"collections":[{"name":"grey-status"},{"name":"real-empty"}]},"status":"ok"}`))
		case "/collections/grey-status":
			_, _ = w.Write([]byte(`{"result":{"config":{},"payload_schema":{}},"status":"ok"}`))
		case "/collections/real-empty":
			_, _ = w.Write([]byte(`{"result":{"points_count":0,"config":{}},"status":"ok"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.LootOptions{})
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	node := res.IngestData.Graph.Nodes[0]
	if got, _ := node.Properties["points_count_unknown"].(int); got != 1 {
		t.Errorf("points_count_unknown = %v, want 1 (grey-status → nil)", got)
	}
	if tp, _ := node.Properties["total_points"].(int64); tp != 0 {
		t.Errorf("total_points = %v, want 0 (real-empty contributes 0; grey-status is not counted)", tp)
	}
}

// TestLoot_Qdrant_PointsScrollDisabled — default run never issues /points/scroll.
func TestLoot_Qdrant_PointsScrollDisabled(t *testing.T) {
	var scrollHit atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "/points/scroll") {
			scrollHit.Store(true)
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"result":{"points":[]}}`))
			return
		}
		switch r.URL.Path {
		case "/collections":
			_, _ = w.Write([]byte(collectionsBody))
		default:
			_, _ = w.Write([]byte(`{"result":{"points_count":1},"status":"ok"}`))
		}
	}))
	defer srv.Close()

	l := &Looter{}
	_, err := l.Loot(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.LootOptions{})
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	if scrollHit.Load() {
		t.Error("Looter issued /points/scroll without --include-points")
	}
}

// TestLoot_Qdrant_PointsScrollEnabled_SinglePage — one page with 3
// points and next_page_offset=null → 3 :MCPResource + 3
// PROVIDES_RESOURCE edges from one POST.
func TestLoot_Qdrant_PointsScrollEnabled_SinglePage(t *testing.T) {
	var postCount atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/collections":
			_, _ = w.Write([]byte(`{"result":{"collections":[{"name":"docs"}]},"status":"ok"}`))
		case r.URL.Path == "/collections/docs" && r.Method == "GET":
			_, _ = w.Write([]byte(`{"result":{"points_count":3},"status":"ok"}`))
		case r.URL.Path == "/collections/docs/points/scroll" && r.Method == "POST":
			postCount.Add(1)
			_, _ = w.Write([]byte(`{"result":{"points":[{"id":1,"payload":{"a":1}},{"id":2,"payload":{"a":2}},{"id":3,"payload":{"a":3}}],"next_page_offset":null},"status":"ok"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.LootOptions{
		Extras: map[string]any{"include-points": true, "points-per-collection": 10},
	})
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	if got := postCount.Load(); got != 1 {
		t.Errorf("POST /points/scroll count = %d, want 1", got)
	}
	var resourceCount, edgeCount int
	for _, n := range res.IngestData.Graph.Nodes {
		if n.Kinds[0] == "MCPResource" {
			resourceCount++
		}
	}
	for _, e := range res.IngestData.Graph.Edges {
		if e.Kind == "PROVIDES_RESOURCE" {
			edgeCount++
			if e.SourceKind != "QdrantInstance" || e.TargetKind != "MCPResource" {
				t.Errorf("edge kinds = %s → %s", e.SourceKind, e.TargetKind)
			}
		}
	}
	if resourceCount != 3 {
		t.Errorf("MCPResource count = %d, want 3", resourceCount)
	}
	if edgeCount != 3 {
		t.Errorf("PROVIDES_RESOURCE count = %d, want 3", edgeCount)
	}
}

// TestLoot_Qdrant_PointsScrollEnabled_Paginated — 3 pages, offsets
// forwarded verbatim, all 9 points emitted.
func TestLoot_Qdrant_PointsScrollEnabled_Paginated(t *testing.T) {
	var (
		mu         sync.Mutex
		seenOffset []string
	)
	pages := []string{
		`{"result":{"points":[{"id":1,"payload":{}},{"id":2,"payload":{}},{"id":3,"payload":{}}],"next_page_offset":100},"status":"ok"}`,
		`{"result":{"points":[{"id":4,"payload":{}},{"id":5,"payload":{}},{"id":6,"payload":{}}],"next_page_offset":200},"status":"ok"}`,
		`{"result":{"points":[{"id":7,"payload":{}},{"id":8,"payload":{}},{"id":9,"payload":{}}],"next_page_offset":null},"status":"ok"}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/collections":
			_, _ = w.Write([]byte(`{"result":{"collections":[{"name":"docs"}]},"status":"ok"}`))
		case r.URL.Path == "/collections/docs" && r.Method == "GET":
			_, _ = w.Write([]byte(`{"result":{"points_count":9},"status":"ok"}`))
		case r.URL.Path == "/collections/docs/points/scroll" && r.Method == "POST":
			body, _ := io.ReadAll(r.Body)
			var req map[string]any
			_ = json.Unmarshal(body, &req)
			off := "start"
			if v, ok := req["offset"]; ok {
				off = fmt.Sprintf("%v", v)
			}
			mu.Lock()
			pageIdx := len(seenOffset)
			seenOffset = append(seenOffset, off)
			mu.Unlock()
			if pageIdx >= len(pages) {
				w.WriteHeader(400)
				return
			}
			_, _ = w.Write([]byte(pages[pageIdx]))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.LootOptions{
		Extras: map[string]any{"include-points": true, "points-per-collection": 100},
	})
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	mu.Lock()
	got := append([]string(nil), seenOffset...)
	mu.Unlock()
	if len(got) != 3 {
		t.Fatalf("offset sequence = %v, want 3 pages", got)
	}
	if got[0] != "start" || got[1] != "100" || got[2] != "200" {
		t.Errorf("offset sequence = %v, want [start 100 200]", got)
	}
	var resourceCount int
	for _, n := range res.IngestData.Graph.Nodes {
		if n.Kinds[0] == "MCPResource" {
			resourceCount++
		}
	}
	if resourceCount != 9 {
		t.Errorf("MCPResource count across pagination = %d, want 9", resourceCount)
	}
}

// TestLoot_Qdrant_PointsScrollEnabled_PerCollectionCap — cap 5 halts
// the scroll even when next_page_offset is non-null.
func TestLoot_Qdrant_PointsScrollEnabled_PerCollectionCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/collections":
			_, _ = w.Write([]byte(`{"result":{"collections":[{"name":"docs"}]},"status":"ok"}`))
		case r.URL.Path == "/collections/docs" && r.Method == "GET":
			_, _ = w.Write([]byte(`{"result":{"points_count":100},"status":"ok"}`))
		case r.URL.Path == "/collections/docs/points/scroll" && r.Method == "POST":
			var pts strings.Builder
			pts.WriteString(`{"result":{"points":[`)
			for i := 0; i < 10; i++ {
				if i > 0 {
					pts.WriteByte(',')
				}
				fmt.Fprintf(&pts, `{"id":%d,"payload":{}}`, i)
			}
			pts.WriteString(`],"next_page_offset":999},"status":"ok"}`)
			_, _ = w.Write([]byte(pts.String()))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.LootOptions{
		Extras: map[string]any{"include-points": true, "points-per-collection": 5},
	})
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	var resourceCount int
	for _, n := range res.IngestData.Graph.Nodes {
		if n.Kinds[0] == "MCPResource" {
			resourceCount++
		}
	}
	if resourceCount != 5 {
		t.Errorf("per-collection cap emission count = %d, want 5", resourceCount)
	}
}

// TestLoot_Qdrant_PointsScrollEnabled_GlobalCap — global cap 4 halts
// scrolling across multiple collections (3 collections × 3 points).
func TestLoot_Qdrant_PointsScrollEnabled_GlobalCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/collections":
			_, _ = w.Write([]byte(`{"result":{"collections":[{"name":"a"},{"name":"b"},{"name":"c"}]},"status":"ok"}`))
		case strings.HasSuffix(r.URL.Path, "/points/scroll") && r.Method == "POST":
			_, _ = w.Write([]byte(`{"result":{"points":[{"id":1,"payload":{}},{"id":2,"payload":{}},{"id":3,"payload":{}}],"next_page_offset":null},"status":"ok"}`))
		case strings.HasPrefix(r.URL.Path, "/collections/") && r.Method == "GET":
			_, _ = w.Write([]byte(`{"result":{"points_count":3},"status":"ok"}`))
		default:
			w.WriteHeader(404)
		}
	}))
	defer srv.Close()

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.LootOptions{
		Extras: map[string]any{
			"include-points":        true,
			"points-per-collection": 10,
			"max-total-resources":   4,
		},
	})
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	var resourceCount int
	for _, n := range res.IngestData.Graph.Nodes {
		if n.Kinds[0] == "MCPResource" {
			resourceCount++
		}
	}
	if resourceCount > 4 {
		t.Errorf("global cap emission count = %d, want ≤ 4", resourceCount)
	}
	if resourceCount == 0 {
		t.Errorf("global cap emission count = 0, want > 0 (cap is a bound, not a block)")
	}
}
