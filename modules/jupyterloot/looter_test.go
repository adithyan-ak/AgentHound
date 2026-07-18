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
	props := res.IngestData.Graph.Nodes[0].Properties
	if props["auth_required"] != false ||
		props["auth_method"] != "none" ||
		props["auth_assurance"] != "unauthenticated" ||
		props["auth_evidence"] != "anonymous_probe_succeeded" ||
		props["is_anonymous_loot"] != true ||
		props["anonymous_access_observed"] != true {
		t.Errorf("anonymous protected-operation posture = %+v", props)
	}
	if props["sessions_access"] != "anonymous" ||
		props["contents_access"] != "anonymous" {
		t.Errorf("protected endpoint access = %+v", props)
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
	props := res.IngestData.Graph.Nodes[0].Properties
	if props["auth_required"] != true ||
		props["auth_method"] != "unknown" ||
		props["auth_assurance"] != "unknown" ||
		props["auth_evidence"] != "unknown" ||
		props["is_anonymous_loot"] != true {
		t.Errorf("mixed protected endpoint posture = %+v", props)
	}
	if props["sessions_access"] != "denied" ||
		props["contents_access"] != "anonymous" {
		t.Errorf("mixed protected endpoint access = %+v", props)
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
	props := res.IngestData.Graph.Nodes[0].Properties
	if _, concluded := props["auth_required"]; concluded {
		t.Errorf("non-auth failures concluded auth_required: %+v", props)
	}
	if props["auth_method"] != "unknown" ||
		props["auth_assurance"] != "unknown" ||
		props["auth_evidence"] != "unknown" ||
		props["is_anonymous_loot"] != false {
		t.Errorf("indeterminate protected endpoint posture = %+v", props)
	}
}

func TestLootJupyterRejectsMalformedSuccessfulContents(t *testing.T) {
	for _, body := range []string{
		`{}`,
		`{"content":null}`,
		`{"content":{}}`,
	} {
		t.Run(body, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch request.URL.Path {
				case "/api/sessions":
					http.Error(w, "unavailable", http.StatusInternalServerError)
				case "/api/contents/":
					_, _ = w.Write([]byte(body))
				default:
					http.NotFound(w, request)
				}
			}))
			t.Cleanup(server.Close)

			result, err := (&Looter{}).Loot(
				context.Background(),
				action.Target{Address: strings.TrimPrefix(server.URL, "http://")},
				action.LootOptions{},
			)
			if err != nil {
				t.Fatalf("Loot: %v", err)
			}
			if result.Summary.PartialFailures != 2 {
				t.Fatalf("partial failures = %d, want 2", result.Summary.PartialFailures)
			}
			properties := result.IngestData.Graph.Nodes[0].Properties
			if properties["contents_access"] != "unknown" ||
				properties["anonymous_access_observed"] != false ||
				properties["is_anonymous_loot"] != false ||
				properties["auth_method"] != "unknown" {
				t.Fatalf("malformed contents produced access evidence: %+v", properties)
			}
		})
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
	if res.Summary.PartialFailures != 1 {
		t.Fatalf("partial failures = %d, want 1", res.Summary.PartialFailures)
	}
	if len(res.PartialErrors) != 1 ||
		!strings.Contains(res.PartialErrors[0], "max-depth=2") {
		t.Fatalf("depth truncation diagnostic = %v", res.PartialErrors)
	}
}

func TestFetchContentsRecursiveCountsDirectoriesAgainstMaxItems(t *testing.T) {
	var subdirectoryRequests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/contents/" {
			_, _ = w.Write([]byte(`{"content":[
				{"name":"a","path":"a","type":"directory"},
				{"name":"b","path":"b","type":"directory"},
				{"name":"c","path":"c","type":"directory"}
			]}`))
			return
		}
		subdirectoryRequests++
		_, _ = w.Write([]byte(`{"content":[]}`))
	}))
	defer srv.Close()

	_, _, _, truncation, err := fetchContentsRecursive(
		context.Background(), srv.Client(), srv.URL, "", 2, DefaultMaxDepth, "",
	)
	if err != nil {
		t.Fatalf("fetchContentsRecursive: %v", err)
	}
	if !truncation.maxItems {
		t.Fatal("max-items exhaustion was not reported as truncation")
	}
	if subdirectoryRequests != 0 {
		t.Fatalf("subdirectory requests = %d, want 0 after max-items budget is exhausted", subdirectoryRequests)
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

func TestLoot_RetriesDeniedRootsAndPropagatesSuppliedBearer(t *testing.T) {
	for _, supplied := range []string{"secret-token", "Bearer secret-token"} {
		t.Run(supplied, func(t *testing.T) {
			var (
				mu   sync.Mutex
				hits = map[string][]string{}
			)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				mu.Lock()
				hits[r.URL.Path] = append(hits[r.URL.Path], r.Header.Get("Authorization"))
				mu.Unlock()

				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/api/sessions":
					if r.Header.Get("Authorization") == "" {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					if r.Header.Get("Authorization") != "Bearer secret-token" {
						t.Errorf("sessions Authorization = %q", r.Header.Get("Authorization"))
						w.WriteHeader(http.StatusForbidden)
						return
					}
					_, _ = w.Write([]byte(sessionsBody))
				case "/api/contents/":
					if r.Header.Get("Authorization") == "" {
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					if r.Header.Get("Authorization") != "Bearer secret-token" {
						t.Errorf("contents Authorization = %q", r.Header.Get("Authorization"))
						w.WriteHeader(http.StatusForbidden)
						return
					}
					_, _ = w.Write([]byte(`{"content":[
						{"name":"private","path":"private","type":"directory"}
					]}`))
				case "/api/contents/private":
					if r.Header.Get("Authorization") != "Bearer secret-token" {
						t.Errorf("recursive Authorization = %q", r.Header.Get("Authorization"))
						w.WriteHeader(http.StatusForbidden)
						return
					}
					_, _ = w.Write([]byte(`{"content":[
						{"name":"secret.ipynb","path":"private/secret.ipynb","type":"notebook"}
					]}`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			res, err := (&Looter{}).Loot(context.Background(), action.Target{
				Kind:    "host",
				Address: strings.TrimPrefix(srv.URL, "http://"),
			}, action.LootOptions{
				Credentials: map[string]string{"token": supplied},
			})
			if err != nil {
				t.Fatalf("Loot: %v", err)
			}
			props := res.IngestData.Graph.Nodes[0].Properties
			if props["auth_required"] != true ||
				props["auth_method"] != "bearer" ||
				props["auth_assurance"] != "moderate" ||
				props["auth_evidence"] != "configured_credential" ||
				props["is_anonymous_loot"] != false ||
				props["anonymous_access_observed"] != false {
				t.Errorf("bearer protected-operation posture = %+v", props)
			}
			if props["sessions_access"] != "bearer" ||
				props["contents_access"] != "bearer" {
				t.Errorf("bearer protected endpoint access = %+v", props)
			}
			if got := notebookPaths(res); len(got) != 1 || got[0] != "private/secret.ipynb" {
				t.Errorf("credentialed recursive paths = %v", got)
			}

			mu.Lock()
			defer mu.Unlock()
			if got := hits["/api/sessions"]; len(got) != 2 ||
				got[0] != "" || got[1] != "Bearer secret-token" {
				t.Errorf("sessions attempts = %v", got)
			}
			if got := hits["/api/contents/"]; len(got) != 2 ||
				got[0] != "" || got[1] != "Bearer secret-token" {
				t.Errorf("contents attempts = %v", got)
			}
			if got := hits["/api/contents/private"]; len(got) != 1 ||
				got[0] != "Bearer secret-token" {
				t.Errorf("recursive attempts = %v", got)
			}
		})
	}
}

func TestLoot_DoesNotSendSuppliedTokenWhenAnonymousControlsSucceed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("Authorization = %q, want empty control request", got)
		}
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/sessions":
			_, _ = w.Write([]byte(`[]`))
		case "/api/contents/":
			_, _ = w.Write([]byte(`{"content":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	res, err := (&Looter{}).Loot(context.Background(), action.Target{
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.LootOptions{
		Credentials: map[string]string{"token": "secret-token"},
	})
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	props := res.IngestData.Graph.Nodes[0].Properties
	if props["auth_method"] != "none" ||
		props["is_anonymous_loot"] != true {
		t.Errorf("anonymous controls with an unused credential = %+v", props)
	}
}

func TestLoot_WrongTokenDoesNotInventBearerAuthentication(t *testing.T) {
	var (
		mu   sync.Mutex
		hits = map[string][]string{}
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path] = append(hits[r.URL.Path], r.Header.Get("Authorization"))
		mu.Unlock()
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()

	res, err := (&Looter{}).Loot(context.Background(), action.Target{
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.LootOptions{
		Credentials: map[string]string{"token": "wrong-token"},
	})
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	props := res.IngestData.Graph.Nodes[0].Properties
	if props["auth_required"] != true ||
		props["auth_method"] != "unknown" ||
		props["auth_assurance"] != "unknown" ||
		props["auth_evidence"] != "unknown" ||
		props["is_anonymous_loot"] != false {
		t.Errorf("wrong-token posture = %+v", props)
	}
	if props["sessions_access"] != "denied" ||
		props["contents_access"] != "denied" {
		t.Errorf("wrong-token protected endpoint access = %+v", props)
	}
	if res.Summary.PartialFailures != 2 {
		t.Errorf("PartialFailures = %d, want 2", res.Summary.PartialFailures)
	}
	for _, partial := range res.PartialErrors {
		if strings.Contains(partial, "wrong-token") {
			t.Errorf("partial error leaked token: %q", partial)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	for _, path := range []string{"/api/sessions", "/api/contents/"} {
		got := hits[path]
		if len(got) != 2 || got[0] != "" || got[1] != "Bearer wrong-token" {
			t.Errorf("%s attempts = %v", path, got)
		}
	}
}

func TestLoot_MixedProtectedAuthorizationRemainsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/sessions":
			if got := r.Header.Get("Authorization"); got != "" {
				t.Errorf("anonymous sessions request sent Authorization %q", got)
			}
			_, _ = w.Write([]byte(`[]`))
		case "/api/contents/":
			if r.Header.Get("Authorization") == "" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			if r.Header.Get("Authorization") != "Bearer secret-token" {
				t.Errorf("contents Authorization = %q", r.Header.Get("Authorization"))
				w.WriteHeader(http.StatusForbidden)
				return
			}
			_, _ = w.Write([]byte(`{"content":[]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	res, err := (&Looter{}).Loot(context.Background(), action.Target{
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.LootOptions{
		Credentials: map[string]string{"token": "secret-token"},
	})
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	props := res.IngestData.Graph.Nodes[0].Properties
	if props["auth_required"] != true ||
		props["auth_method"] != "unknown" ||
		props["auth_assurance"] != "unknown" ||
		props["auth_evidence"] != "unknown" ||
		props["is_anonymous_loot"] != true ||
		props["anonymous_access_observed"] != true {
		t.Errorf("mixed protected-operation posture = %+v", props)
	}
	if props["sessions_access"] != "anonymous" ||
		props["contents_access"] != "bearer" {
		t.Errorf("mixed protected endpoint access = %+v", props)
	}
}

func TestLoot_PasswordOrCustomDenialDoesNotGuessMechanism(t *testing.T) {
	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		if got := r.Header.Get("Authorization"); got != "" {
			t.Errorf("unexpected Authorization = %q", got)
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	res, err := (&Looter{}).Loot(context.Background(), action.Target{
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.LootOptions{
		Credentials: map[string]string{"password": "not-supported"},
	})
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	if requests != 2 {
		t.Fatalf("requests = %d, want one credential-free attempt per protected root", requests)
	}
	props := res.IngestData.Graph.Nodes[0].Properties
	if props["auth_required"] != true ||
		props["auth_method"] != "unknown" ||
		props["auth_evidence"] != "unknown" {
		t.Errorf("password/custom denial posture = %+v", props)
	}
}

func TestLoot_RejectsMalformedTokenBeforeNetworkAccess(t *testing.T) {
	tests := []string{
		"Bearer",
		"Basic secret-token",
		"Bearer one two",
		"one two",
		"secret\r\ninjected",
	}
	for _, token := range tests {
		t.Run(strings.ReplaceAll(token, " ", "_"), func(t *testing.T) {
			requests := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				requests++
				w.WriteHeader(http.StatusOK)
			}))
			defer srv.Close()

			_, err := (&Looter{}).Loot(context.Background(), action.Target{
				Address: strings.TrimPrefix(srv.URL, "http://"),
			}, action.LootOptions{
				Credentials: map[string]string{"token": token},
			})
			if err == nil {
				t.Fatal("Loot error = nil, want malformed token rejection")
			}
			if strings.Contains(err.Error(), token) {
				t.Fatalf("error leaked supplied token %q: %v", token, err)
			}
			if requests != 0 {
				t.Fatalf("requests = %d, want 0", requests)
			}
		})
	}
}
