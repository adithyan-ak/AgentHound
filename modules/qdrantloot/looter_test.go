package qdrantloot

import (
	"context"
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
