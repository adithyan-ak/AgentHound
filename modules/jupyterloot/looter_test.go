package jupyterloot

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/action"
)

// sessionsBody now includes an empty-path console kernel — must still
// be counted in active_sessions (the old code silently dropped these).
const sessionsBody = `[
	{"id":"sess-1","path":"demo.ipynb","name":"demo"},
	{"id":"sess-2","path":"","name":"console-kernel-only"}
]`

// contentsBody at the root: two leaves (a notebook and a file) plus a
// subdirectory that the recursive walker must descend into.
const contentsBody = `{"content":[
	{"name":"demo.ipynb","path":"demo.ipynb","type":"notebook","mimetype":"application/x-ipynb+json"},
	{"name":"utils.py","path":"utils.py","type":"file","mimetype":"text/x-python"},
	{"name":"data","path":"data","type":"directory","mimetype":""}
]}`

// contentsDataBody at /api/contents/data: two nested leaves the
// recursive walker must find.
const contentsDataBody = `{"content":[
	{"name":"nested.ipynb","path":"data/nested.ipynb","type":"notebook","mimetype":"application/x-ipynb+json"},
	{"name":"raw.csv","path":"data/raw.csv","type":"file","mimetype":"text/csv"}
]}`

func jupyterStub(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/sessions":
			_, _ = w.Write([]byte(sessionsBody))
		case "/api/contents/":
			_, _ = w.Write([]byte(contentsBody))
		case "/api/contents/data":
			_, _ = w.Write([]byte(contentsDataBody))
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestLoot_JupyterHappy(t *testing.T) {
	srv := jupyterStub(t)
	defer srv.Close()

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.LootOptions{})
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	// 1 JupyterServer + 2 root leaves (notebook + file) + 2 nested
	// leaves (nested notebook + csv) = 5 nodes; 4 PROVIDES_RESOURCE
	// edges. The recursive walker must find the nested/ leaves.
	if got := len(res.IngestData.Graph.Nodes); got != 5 {
		t.Errorf("nodes: got %d, want 5 (1 JupyterServer + 4 resources)", got)
	}
	if got := len(res.IngestData.Graph.Edges); got != 4 {
		t.Errorf("edges: got %d, want 4 PROVIDES_RESOURCE edges", got)
	}
	// Empty-path session is still counted (U-LOW-8 regression guard).
	as, _ := res.IngestData.Graph.Nodes[0].Properties["active_sessions"].(int)
	if as != 2 {
		t.Errorf("active_sessions = %d, want 2 (empty-path console kernel must be counted)", as)
	}
	if res.Summary.CredentialsFound != 0 {
		t.Errorf("CredentialsFound = %d, want 0 for resource-only discoveries", res.Summary.CredentialsFound)
	}
	if res.IngestData.Graph.Nodes[0].Kinds[0] != "JupyterServer" {
		t.Errorf("first node kind = %v, want JupyterServer", res.IngestData.Graph.Nodes[0].Kinds)
	}
	// Every subsequent node is an :MCPResource with jupyter:// URI.
	for _, n := range res.IngestData.Graph.Nodes[1:] {
		if n.Kinds[0] != "MCPResource" {
			t.Errorf("resource node kind = %v, want MCPResource", n.Kinds)
		}
		if uri, _ := n.Properties["uri"].(string); !strings.HasPrefix(uri, "jupyter://") {
			t.Errorf("uri = %q, want jupyter:// prefix", uri)
		}
	}
	for _, e := range res.IngestData.Graph.Edges {
		if e.Kind != "PROVIDES_RESOURCE" {
			t.Errorf("edge kind = %q, want PROVIDES_RESOURCE", e.Kind)
		}
		if e.SourceKind != "JupyterServer" || e.TargetKind != "MCPResource" {
			t.Errorf("edge endpoints = %s -> %s, want JupyterServer -> MCPResource", e.SourceKind, e.TargetKind)
		}
	}
}

func TestLoot_Jupyter_SessionsFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/sessions":
			w.WriteHeader(403)
		case "/api/contents/":
			_, _ = w.Write([]byte(contentsBody))
		case "/api/contents/data":
			_, _ = w.Write([]byte(contentsDataBody))
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
	if res.Summary.PartialFailures != 1 {
		t.Errorf("partial failures: got %d, want 1 (sessions 403)", res.Summary.PartialFailures)
	}
	// Notebooks should still be listed from /api/contents (recursive).
	if got := len(res.IngestData.Graph.Nodes); got < 2 {
		t.Errorf("nodes: got %d, want at least 2 (JupyterServer + resources)", got)
	}
}

func TestLoot_Jupyter_AllFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
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
	if res.Summary.PartialFailures != 2 {
		t.Errorf("partial failures: got %d, want 2", res.Summary.PartialFailures)
	}
}

// TestLoot_Jupyter_RecursiveContents — a 3-level tree
// (/api/contents/, /api/contents/a, /api/contents/a/b) must be walked
// entirely and all leaves emitted.
func TestLoot_Jupyter_RecursiveContents(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/sessions":
			_, _ = w.Write([]byte(`[]`))
		case "/api/contents/":
			_, _ = w.Write([]byte(`{"content":[
				{"name":"root.ipynb","path":"root.ipynb","type":"notebook"},
				{"name":"a","path":"a","type":"directory"}
			]}`))
		case "/api/contents/a":
			_, _ = w.Write([]byte(`{"content":[
				{"name":"a.ipynb","path":"a/a.ipynb","type":"notebook"},
				{"name":"b","path":"a/b","type":"directory"}
			]}`))
		case "/api/contents/a/b":
			_, _ = w.Write([]byte(`{"content":[
				{"name":"deep.ipynb","path":"a/b/deep.ipynb","type":"notebook"}
			]}`))
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
	got := notebookPaths(res)
	want := []string{"root.ipynb", "a/a.ipynb", "a/b/deep.ipynb"}
	for _, w := range want {
		found := false
		for _, g := range got {
			if g == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("recursive walk missed %q; got %v", w, got)
		}
	}
}

// TestLoot_Jupyter_MaxDepthCap — with --max-depth=2, notebooks at
// depth 3 (a/b/deep.ipynb) must not be emitted.
func TestLoot_Jupyter_MaxDepthCap(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/sessions":
			_, _ = w.Write([]byte(`[]`))
		case "/api/contents/":
			_, _ = w.Write([]byte(`{"content":[
				{"name":"root.ipynb","path":"root.ipynb","type":"notebook"},
				{"name":"a","path":"a","type":"directory"}
			]}`))
		case "/api/contents/a":
			_, _ = w.Write([]byte(`{"content":[
				{"name":"a.ipynb","path":"a/a.ipynb","type":"notebook"},
				{"name":"b","path":"a/b","type":"directory"}
			]}`))
		case "/api/contents/a/b":
			_, _ = w.Write([]byte(`{"content":[
				{"name":"deep.ipynb","path":"a/b/deep.ipynb","type":"notebook"}
			]}`))
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
		Extras: map[string]any{"max-depth": 2},
	})
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	got := notebookPaths(res)
	// With max-depth=2, root (depth 1) and a/ (depth 2) leaves are
	// discovered; a/b/deep.ipynb (depth 3) must be excluded.
	for _, g := range got {
		if strings.Contains(g, "a/b/") {
			t.Errorf("max-depth=2 leaked depth-3 path %q; got %v", g, got)
		}
	}
	// root.ipynb + a/a.ipynb should still be present.
	wantContains := []string{"root.ipynb", "a/a.ipynb"}
	for _, w := range wantContains {
		found := false
		for _, g := range got {
			if g == w {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("expected %q at depth ≤ 2; got %v", w, got)
		}
	}
}

// TestLoot_Jupyter_SubdirForbidden — root lists 3 subdirs; one returns
// 403; the walker records a per-directory partial failure and emits
// notebooks from the other two subdirs.
func TestLoot_Jupyter_SubdirForbidden(t *testing.T) {
	var (
		mu   sync.Mutex
		hits = map[string]int{}
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/sessions":
			_, _ = w.Write([]byte(`[]`))
		case "/api/contents/":
			_, _ = w.Write([]byte(`{"content":[
				{"name":"a","path":"a","type":"directory"},
				{"name":"forbidden","path":"forbidden","type":"directory"},
				{"name":"c","path":"c","type":"directory"}
			]}`))
		case "/api/contents/a":
			_, _ = w.Write([]byte(`{"content":[{"name":"a.ipynb","path":"a/a.ipynb","type":"notebook"}]}`))
		case "/api/contents/forbidden":
			w.WriteHeader(403)
		case "/api/contents/c":
			_, _ = w.Write([]byte(`{"content":[{"name":"c.ipynb","path":"c/c.ipynb","type":"notebook"}]}`))
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
	// Both readable subdirs' notebooks must land.
	got := notebookPaths(res)
	for _, want := range []string{"a/a.ipynb", "c/c.ipynb"} {
		found := false
		for _, g := range got {
			if g == want {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("subdir-forbidden walk missed %q; got %v", want, got)
		}
	}
	// The forbidden subtree must appear in PartialErrors with a
	// well-formed prefix.
	var sawForbidden bool
	wantPrefix := "api/contents/forbidden:"
	for _, pe := range res.PartialErrors {
		if strings.HasPrefix(pe, wantPrefix) {
			sawForbidden = true
			break
		}
	}
	if !sawForbidden {
		t.Errorf("PartialErrors missing entry with prefix %q; got %v", wantPrefix, res.PartialErrors)
	}
	// Confirm the forbidden dir was probed exactly once (walk did not
	// retry).
	mu.Lock()
	if hits["/api/contents/forbidden"] != 1 {
		t.Errorf("forbidden dir probed %d times, want 1", hits["/api/contents/forbidden"])
	}
	mu.Unlock()
}

// notebookPaths returns the path property of every :MCPResource node.
func notebookPaths(res *action.LootResult) []string {
	var out []string
	for _, n := range res.IngestData.Graph.Nodes {
		if len(n.Kinds) == 0 || n.Kinds[0] != "MCPResource" {
			continue
		}
		uri, _ := n.Properties["uri"].(string)
		// Extract the path portion after jupyter://host:port/
		idx := strings.Index(uri, "://")
		if idx < 0 {
			continue
		}
		rest := uri[idx+3:]
		slash := strings.Index(rest, "/")
		if slash < 0 {
			continue
		}
		out = append(out, rest[slash+1:])
	}
	return out
}

// Force fmt import so build stays green if imports narrow later.
var _ = fmt.Sprintf
