package mlflowloot

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/action"
)

const experimentsBody = `{"experiments":[{"experiment_id":"0","name":"Default"},{"experiment_id":"1","name":"Fine-tune-v3"}]}`
const runsBody = `{"runs":[{"info":{"run_id":"abc123"}},{"info":{"run_id":"def456"}}]}`

func mlflowStub(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/2.0/mlflow/experiments/search" && r.Method == "GET":
			_, _ = w.Write([]byte(experimentsBody))
		case r.URL.Path == "/api/2.0/mlflow/runs/search" && r.Method == "POST":
			_, _ = w.Write([]byte(runsBody))
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestLoot_MLflowHappy(t *testing.T) {
	srv := mlflowStub(t)
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
		t.Errorf("nodes: got %d, want 1 (MLflowServer)", got)
	}
	node := res.IngestData.Graph.Nodes[0]
	if node.Kinds[0] != "MLflowServer" {
		t.Errorf("kind = %v, want MLflowServer", node.Kinds)
	}
	if ec, _ := node.Properties["experiment_count"].(int); ec != 2 {
		t.Errorf("experiment_count = %v, want 2", node.Properties["experiment_count"])
	}
	// 2 experiments x 2 runs each = 4 total runs
	if tr, _ := node.Properties["total_runs"].(int); tr != 4 {
		t.Errorf("total_runs = %v, want 4", node.Properties["total_runs"])
	}
}

func TestLoot_MLflow_FetchRunsUsesPOST(t *testing.T) {
	var gotMethod string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/2.0/mlflow/experiments/search" {
			_, _ = w.Write([]byte(`{"experiments":[{"experiment_id":"1","name":"X"}]}`))
			return
		}
		if r.URL.Path == "/api/2.0/mlflow/runs/search" {
			gotMethod = r.Method
			gotBody, _ = io.ReadAll(r.Body)
			_, _ = w.Write([]byte(`{"runs":[]}`))
			return
		}
		w.WriteHeader(404)
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
	if gotMethod != "POST" {
		t.Errorf("fetchRuns method = %q, want POST", gotMethod)
	}
	var parsed map[string]any
	if err := json.Unmarshal(gotBody, &parsed); err != nil {
		t.Fatalf("runs/search body not valid JSON: %v", err)
	}
	ids, ok := parsed["experiment_ids"].([]any)
	if !ok || len(ids) == 0 {
		t.Errorf("runs/search body missing experiment_ids: %s", string(gotBody))
	}
}

func TestLoot_MLflow_ExperimentsFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
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
	if res.Summary.PartialFailures != 1 {
		t.Errorf("partial failures: got %d, want 1", res.Summary.PartialFailures)
	}
}
