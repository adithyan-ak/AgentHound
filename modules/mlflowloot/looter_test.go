package mlflowloot

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/action"
)

const experimentsBody = `{"experiments":[{"experiment_id":"0","name":"Default"},{"experiment_id":"1","name":"Fine-tune-v3"}],"next_page_token":""}`
const runsBody = `{"runs":[{"info":{"run_id":"abc123"}},{"info":{"run_id":"def456"}}],"next_page_token":""}`

func mlflowStub(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/2.0/mlflow/experiments/search" && r.Method == "GET":
			_, _ = w.Write([]byte(experimentsBody))
		case r.URL.Path == "/api/2.0/mlflow/runs/search" && r.Method == "POST":
			_, _ = w.Write([]byte(runsBody))
		case r.URL.Path == "/api/2.0/mlflow/registered-models/search" && r.Method == "GET":
			_, _ = w.Write([]byte(`{"registered_models":[],"next_page_token":""}`))
		case r.URL.Path == "/api/2.0/mlflow/model-versions/search" && r.Method == "GET":
			_, _ = w.Write([]byte(`{"model_versions":[],"next_page_token":""}`))
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
	if rmc, _ := node.Properties["registered_model_count"].(int); rmc != 0 {
		t.Errorf("registered_model_count = %v, want 0", node.Properties["registered_model_count"])
	}
	if mvc, _ := node.Properties["model_version_count"].(int); mvc != 0 {
		t.Errorf("model_version_count = %v, want 0", node.Properties["model_version_count"])
	}
	if res.Summary.CredentialsFound != 0 {
		t.Errorf("CredentialsFound = %d, want 0 for metadata-only discoveries", res.Summary.CredentialsFound)
	}
}

func TestLoot_MLflow_FetchRunsUsesPOST(t *testing.T) {
	var gotMethod string
	var gotBody []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/2.0/mlflow/experiments/search" {
			_, _ = w.Write([]byte(`{"experiments":[{"experiment_id":"1","name":"X"}],"next_page_token":""}`))
			return
		}
		if r.URL.Path == "/api/2.0/mlflow/runs/search" {
			gotMethod = r.Method
			gotBody, _ = io.ReadAll(r.Body)
			_, _ = w.Write([]byte(`{"runs":[],"next_page_token":""}`))
			return
		}
		if strings.HasPrefix(r.URL.Path, "/api/2.0/mlflow/registered-models/search") ||
			strings.HasPrefix(r.URL.Path, "/api/2.0/mlflow/model-versions/search") {
			_, _ = w.Write([]byte(`{"registered_models":[],"model_versions":[],"next_page_token":""}`))
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
	if _, ok := parsed["max_results"]; !ok {
		t.Errorf("runs/search body missing max_results: %s", string(gotBody))
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
	// 401 on every endpoint → 3 partial failures (experiments,
	// registered-models, model-versions).
	if res.Summary.PartialFailures < 1 {
		t.Errorf("partial failures: got %d, want at least 1", res.Summary.PartialFailures)
	}
}

// TestLoot_MLflow_SendsMaxResults locks in the fix for U-CRIT-2: modern
// MLflow (2.22.x+) rejects GET /experiments/search without max_results
// with HTTP 400 INVALID_PARAMETER_VALUE. Every outgoing GET must carry
// ?max_results=<n>.
func TestLoot_MLflow_SendsMaxResults(t *testing.T) {
	var (
		mu      sync.Mutex
		queries = map[string]string{}
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		mu.Lock()
		queries[r.URL.Path] = r.URL.RawQuery
		mu.Unlock()
		switch r.URL.Path {
		case "/api/2.0/mlflow/experiments/search":
			_, _ = w.Write([]byte(`{"experiments":[],"next_page_token":""}`))
		case "/api/2.0/mlflow/registered-models/search":
			_, _ = w.Write([]byte(`{"registered_models":[],"next_page_token":""}`))
		case "/api/2.0/mlflow/model-versions/search":
			_, _ = w.Write([]byte(`{"model_versions":[],"next_page_token":""}`))
		default:
			w.WriteHeader(404)
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
	mu.Lock()
	defer mu.Unlock()
	for _, path := range []string{
		"/api/2.0/mlflow/experiments/search",
		"/api/2.0/mlflow/registered-models/search",
		"/api/2.0/mlflow/model-versions/search",
	} {
		q, ok := queries[path]
		if !ok {
			t.Errorf("%s never queried", path)
			continue
		}
		if !strings.Contains(q, "max_results=") {
			t.Errorf("%s query %q missing max_results (would 400 on modern MLflow)", path, q)
		}
	}
}

// TestLoot_MLflow_Paginates walks a 3-page experiments fixture and
// verifies all pages are fetched (next_page_token followed).
func TestLoot_MLflow_Paginates(t *testing.T) {
	var (
		mu       sync.Mutex
		pagesHit []string
	)
	pages := map[string]string{
		"":     `{"experiments":[{"experiment_id":"a","name":"A"}],"next_page_token":"tok2"}`,
		"tok2": `{"experiments":[{"experiment_id":"b","name":"B"}],"next_page_token":"tok3"}`,
		"tok3": `{"experiments":[{"experiment_id":"c","name":"C"}],"next_page_token":""}`,
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/2.0/mlflow/experiments/search":
			token := r.URL.Query().Get("page_token")
			mu.Lock()
			pagesHit = append(pagesHit, token)
			mu.Unlock()
			body, ok := pages[token]
			if !ok {
				w.WriteHeader(400)
				return
			}
			_, _ = w.Write([]byte(body))
		case "/api/2.0/mlflow/runs/search":
			_, _ = w.Write([]byte(`{"runs":[],"next_page_token":""}`))
		default:
			// registered-models, model-versions
			_, _ = w.Write([]byte(`{"registered_models":[],"model_versions":[],"next_page_token":""}`))
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
	mu.Lock()
	got := append([]string(nil), pagesHit...)
	mu.Unlock()
	if len(got) != 3 {
		t.Fatalf("page tokens requested = %v, want [\"\", \"tok2\", \"tok3\"]", got)
	}
	want := []string{"", "tok2", "tok3"}
	for i, tok := range got {
		if tok != want[i] {
			t.Errorf("page token order = %v, want %v", got, want)
			break
		}
	}
	if ec, _ := res.IngestData.Graph.Nodes[0].Properties["experiment_count"].(int); ec != 3 {
		t.Errorf("experiment_count after pagination = %v, want 3", ec)
	}
}

// TestLoot_MLflow_RegisteredModels stubs the Registry endpoints and
// asserts each model version emits one :MCPResource + PROVIDES_RESOURCE
// edge — NOT a :Credential (verified via mlflow/store/model_registry/
// sqlalchemy_store.py:1291-1306: get_model_version_download_uri
// returns raw storage URIs, not presigned credentials).
func TestLoot_MLflow_RegisteredModels(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/2.0/mlflow/experiments/search":
			_, _ = w.Write([]byte(`{"experiments":[],"next_page_token":""}`))
		case "/api/2.0/mlflow/registered-models/search":
			_, _ = w.Write([]byte(`{"registered_models":[{"name":"fraud-detector"},{"name":"support-agent"}],"next_page_token":""}`))
		case "/api/2.0/mlflow/model-versions/search":
			_, _ = w.Write([]byte(`{"model_versions":[{"name":"fraud-detector","version":"3"},{"name":"support-agent","version":"1"}],"next_page_token":""}`))
		case "/api/2.0/mlflow/model-versions/get-download-uri":
			name := r.URL.Query().Get("name")
			ver := r.URL.Query().Get("version")
			_, _ = fmt.Fprintf(w, `{"artifact_uri":"s3://ml-artifacts/%s/%s/model"}`, name, ver)
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
	if got, _ := res.IngestData.Graph.Nodes[0].Properties["registered_model_count"].(int); got != 2 {
		t.Errorf("registered_model_count = %v, want 2", got)
	}
	if got, _ := res.IngestData.Graph.Nodes[0].Properties["model_version_count"].(int); got != 2 {
		t.Errorf("model_version_count = %v, want 2", got)
	}
	var resourceNodes, credNodes int
	for _, n := range res.IngestData.Graph.Nodes {
		if len(n.Kinds) == 0 {
			continue
		}
		switch n.Kinds[0] {
		case "MCPResource":
			resourceNodes++
			if uri, _ := n.Properties["uri"].(string); !strings.HasPrefix(uri, "s3://") {
				t.Errorf("resource uri = %q, want s3:// prefix from fixture", uri)
			}
			if mt, _ := n.Properties["mime_type"].(string); mt != "application/x-mlflow-model" {
				t.Errorf("resource mime_type = %q, want application/x-mlflow-model", mt)
			}
		case "Credential":
			credNodes++
		}
	}
	if resourceNodes != 2 {
		t.Errorf(":MCPResource count = %d, want 2 (one per model version)", resourceNodes)
	}
	if credNodes != 0 {
		t.Errorf(":Credential count = %d, want 0 (Model Registry URIs are NOT credentials)", credNodes)
	}
	var edges int
	for _, e := range res.IngestData.Graph.Edges {
		if e.Kind == "PROVIDES_RESOURCE" && e.SourceKind == "MLflowServer" && e.TargetKind == "MCPResource" {
			edges++
		}
	}
	if edges != 2 {
		t.Errorf("PROVIDES_RESOURCE edges = %d, want 2", edges)
	}
}

// TestLoot_MLflow_ArtifactSensitivity locks in the sensitivity
// auto-classification heuristic per docs/reference/graph-model.md:248-256.
func TestLoot_MLflow_ArtifactSensitivity(t *testing.T) {
	cases := []struct {
		uri  string
		want string
	}{
		{"s3://prod-bucket/model.pkl", "critical"},   // cloud + "prod"
		{"file:///etc/mlflow/model.pkl", "critical"}, // file:///etc/
		{"s3://experiments/model.pkl", "high"},       // cloud, no "prod"
		{"gs://ml-artifacts/model.pkl", "high"},      // cloud
		{"file:///tmp/local.pkl", "medium"},          // plain file://
		{"dbfs:/Users/x/model", "high"},              // dbfs cloud
		{"s3://bucket/secrets.pem", "critical"},      // .pem extension
		{"s3://bucket/config.env", "critical"},       // .env extension
		{"artifacts:/models/x", "high"},              // fallback
	}
	for _, tc := range cases {
		got := classifyArtifactSensitivity(tc.uri)
		if got != tc.want {
			t.Errorf("classifyArtifactSensitivity(%q) = %q, want %q", tc.uri, got, tc.want)
		}
	}
}

// TestLoot_MLflow_RegistryPartialFailure — Registry endpoints return
// 404 (older MLflow without the Model Registry API); the tracking
// probes still land and Registry failures are recorded as partials.
func TestLoot_MLflow_RegistryPartialFailure(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/2.0/mlflow/experiments/search":
			_, _ = w.Write([]byte(experimentsBody))
		case "/api/2.0/mlflow/runs/search":
			_, _ = w.Write([]byte(runsBody))
		default:
			// registered-models, model-versions → 404
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
	// experiment_count + total_runs still populated.
	if _, ok := res.IngestData.Graph.Nodes[0].Properties["experiment_count"]; !ok {
		t.Errorf("experiment_count missing after Registry 404")
	}
	// Registry probes recorded as partials.
	if res.Summary.PartialFailures < 2 {
		t.Errorf("partial failures: got %d, want at least 2 (registered-models + model-versions)", res.Summary.PartialFailures)
	}
}
