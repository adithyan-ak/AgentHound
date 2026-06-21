package qdrantloot

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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
