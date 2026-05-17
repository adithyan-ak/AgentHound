package jupyterloot

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/action"
)

const sessionsBody = `[{"id":"sess-1","path":"demo.ipynb","name":"demo","notebook":{"path":"demo.ipynb"}}]`
const contentsBody = `{"content":[{"name":"demo.ipynb","path":"demo.ipynb","type":"notebook","mimetype":"application/x-ipynb+json"},{"name":"utils.py","path":"utils.py","type":"file","mimetype":"text/x-python"},{"name":"data","path":"data","type":"directory","mimetype":""}]}`

func jupyterStub(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/sessions":
			_, _ = w.Write([]byte(sessionsBody))
		case "/api/contents/":
			_, _ = w.Write([]byte(contentsBody))
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
	// 1 JupyterServer + 2 MCPResource (notebook + file; directory skipped)
	if got := len(res.IngestData.Graph.Nodes); got != 3 {
		t.Errorf("nodes: got %d, want 3 (1 JupyterServer + 2 resources)", got)
	}
	if res.IngestData.Graph.Nodes[0].Kinds[0] != "JupyterServer" {
		t.Errorf("first node kind = %v, want JupyterServer", res.IngestData.Graph.Nodes[0].Kinds)
	}
	for _, n := range res.IngestData.Graph.Nodes[1:] {
		if n.Kinds[0] != "MCPResource" {
			t.Errorf("resource node kind = %v, want MCPResource", n.Kinds)
		}
		if uri, _ := n.Properties["uri"].(string); !strings.HasPrefix(uri, "jupyter://") {
			t.Errorf("uri = %q, want jupyter:// prefix", uri)
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
	// Notebooks should still be listed from /api/contents
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
