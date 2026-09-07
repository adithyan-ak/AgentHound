package mlflowcollect

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/adithyan-ak/agenthound/modules/mlflowfp"
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
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

func TestFingerprintAndLootPropertiesComposeOnSameEndpoint(t *testing.T) {
	srv := mlflowStub(t)
	defer srv.Close()
	target := action.Target{Kind: "host", Address: strings.TrimPrefix(srv.URL, "http://")}

	fingerprinter, err := mlflowfp.New()
	if err != nil {
		t.Fatalf("new fingerprinter: %v", err)
	}
	fingerprint, err := fingerprinter.Fingerprint(context.Background(), target)
	if err != nil {
		t.Fatalf("fingerprint: %v", err)
	}
	collection, err := (&Collector{}).Collect(context.Background(), target, action.CollectOptions{})
	if err != nil {
		t.Fatalf("collection: %v", err)
	}
	fingerprintNode := fingerprint.IngestData.Graph.Nodes[0]
	lootNode := collection.IngestData.Graph.Nodes[0]
	if fingerprintNode.ID != lootNode.ID {
		t.Fatalf("same endpoint IDs differ: %q != %q", fingerprintNode.ID, lootNode.ID)
	}
	for key, fingerprintValue := range fingerprintNode.Properties {
		if lootValue, shared := lootNode.Properties[key]; shared &&
			!reflect.DeepEqual(fingerprintValue, lootValue) {
			t.Errorf("shared property %q conflicts: fingerprint=%#v collection=%#v", key, fingerprintValue, lootValue)
		}
	}
	if fingerprintNode.Properties["discovered_via"] != "network_scan" ||
		lootNode.Properties["collection_observed"] != true {
		t.Errorf("action provenance not separated: fingerprint=%+v collection=%+v", fingerprintNode.Properties, lootNode.Properties)
	}
}

func TestCollect_MLflowHappy(t *testing.T) {
	srv := mlflowStub(t)
	defer srv.Close()

	l := &Collector{}
	res, err := l.Collect(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.CollectOptions{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := len(res.IngestData.Graph.Nodes); got != 1 {
		t.Errorf("nodes: got %d, want 1 (MLflowServer)", got)
	}
	node := res.IngestData.Graph.Nodes[0]
	if node.Kinds[0] != "MLflowServer" {
		t.Errorf("kind = %v, want MLflowServer", node.Kinds)
	}
	if node.Properties["collection_observed"] != true {
		t.Errorf("MLflowServer missing collection_observed: %+v", node.Properties)
	}
	if _, exists := node.Properties["discovered_via"]; exists {
		t.Errorf("direct collection claimed discovery provenance: %+v", node.Properties)
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
	if res.Inventory == nil || res.Inventory.Name != "model_registry" ||
		res.Inventory.State != ingest.OutcomeComplete || res.Inventory.Items != 0 {
		t.Fatalf("inventory = %+v, want complete empty model registry", res.Inventory)
	}
	assertAnonymousInventoryClaim(t, node.Properties)
}

func TestCollect_MLflow_FetchRunsUsesPOST(t *testing.T) {
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

	l := &Collector{}
	_, err := l.Collect(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.CollectOptions{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
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

func TestCollect_MLflow_ExperimentsFail(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401)
	}))
	defer srv.Close()

	l := &Collector{}
	res, err := l.Collect(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.CollectOptions{})
	if err != nil {
		t.Fatalf("Collect should not error on partial failures: %v", err)
	}
	// 401 on every endpoint → 3 partial failures (experiments,
	// registered-models, model-versions).
	if res.Summary.PartialFailures < 1 {
		t.Errorf("partial failures: got %d, want at least 1", res.Summary.PartialFailures)
	}
	assertNoAnonymousInventoryClaim(t, res.IngestData.Graph.Nodes[0].Properties)
}

func TestCollect_MLflow_ExperimentsMalformedOrUnavailableDoesNotClaimAnonymousAccess(t *testing.T) {
	t.Run("malformed success shape", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{}`))
		}))
		defer srv.Close()

		res, err := (&Collector{}).Collect(context.Background(), action.Target{
			Kind: "host", Address: strings.TrimPrefix(srv.URL, "http://"),
		}, action.CollectOptions{})
		if err != nil {
			t.Fatalf("Collect: %v", err)
		}
		assertNoAnonymousInventoryClaim(t, res.IngestData.Graph.Nodes[0].Properties)
	})

	t.Run("transport failure", func(t *testing.T) {
		srv := httptest.NewServer(http.NotFoundHandler())
		address := strings.TrimPrefix(srv.URL, "http://")
		srv.Close()

		res, err := (&Collector{}).Collect(context.Background(), action.Target{
			Kind: "host", Address: address,
		}, action.CollectOptions{})
		if err != nil {
			t.Fatalf("Collect: %v", err)
		}
		assertNoAnonymousInventoryClaim(t, res.IngestData.Graph.Nodes[0].Properties)
	})
}

func assertAnonymousInventoryClaim(t *testing.T, props map[string]any) {
	t.Helper()
	if props["auth_method"] != string(common.AuthNone) ||
		props["auth_assurance"] != string(common.AuthAssuranceUnauthenticated) ||
		props["auth_evidence"] != common.AuthEvidenceAnonymousProbeSucceeded ||
		props["probe_status"] != string(common.VerificationVerified) {
		t.Fatalf("anonymous inventory evidence = %+v", props)
	}
	if _, ok := props["last_verified_at"].(string); !ok {
		t.Fatalf("last_verified_at missing from anonymous inventory evidence: %+v", props)
	}
}

func assertNoAnonymousInventoryClaim(t *testing.T, props map[string]any) {
	t.Helper()
	for _, key := range []string{
		"auth_method", "auth_assurance", "auth_evidence", "probe_status",
		"last_verified_at",
	} {
		if value, present := props[key]; present {
			t.Errorf("failed inventory fabricated %s=%v: %+v", key, value, props)
		}
	}
}

// TestCollect_MLflow_SendsMaxResults locks in the fix for U-CRIT-2: modern
// MLflow (2.22.x+) rejects GET /experiments/search without max_results
// with HTTP 400 INVALID_PARAMETER_VALUE. Every outgoing GET must carry
// ?max_results=<n>.
func TestCollect_MLflow_SendsMaxResults(t *testing.T) {
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

	l := &Collector{}
	_, err := l.Collect(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.CollectOptions{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
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

// TestCollect_MLflow_Paginates walks a 3-page experiments fixture and
// verifies all pages are fetched (next_page_token followed).
func TestCollect_MLflow_Paginates(t *testing.T) {
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

	l := &Collector{}
	res, err := l.Collect(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.CollectOptions{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
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

// TestCollect_MLflow_RegisteredModels stubs the Registry endpoints and
// asserts each model version emits one ModelArtifact, while their shared S3
// root emits one ArtifactStore — NOT a Credential (verified via mlflow/store/model_registry/
// sqlalchemy_store.py:1291-1306: get_model_version_download_uri
// returns raw storage URIs, not presigned credentials).
func TestCollect_MLflow_RegisteredModels(t *testing.T) {
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

	l := &Collector{}
	res, err := l.Collect(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.CollectOptions{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got, _ := res.IngestData.Graph.Nodes[0].Properties["registered_model_count"].(int); got != 2 {
		t.Errorf("registered_model_count = %v, want 2", got)
	}
	if got, _ := res.IngestData.Graph.Nodes[0].Properties["model_version_count"].(int); got != 2 {
		t.Errorf("model_version_count = %v, want 2", got)
	}
	var artifactNodes, storeNodes, resourceNodes, credNodes int
	for _, n := range res.IngestData.Graph.Nodes {
		if len(n.Kinds) == 0 {
			continue
		}
		switch n.Kinds[0] {
		case "ModelArtifact":
			artifactNodes++
			if uri, _ := n.Properties["storage_uri"].(string); !strings.HasPrefix(uri, "s3://ml-artifacts/") {
				t.Errorf("artifact storage_uri = %q, want sanitized s3 fixture URI", uri)
			}
		case "ArtifactStore":
			storeNodes++
			if n.Properties["root_uri"] != "s3://ml-artifacts" || n.Properties["scope"] != "remote" {
				t.Errorf("artifact store = %+v", n.Properties)
			}
		case "MCPResource":
			resourceNodes++
		case "Credential":
			credNodes++
		}
	}
	if artifactNodes != 2 || storeNodes != 1 {
		t.Errorf("typed nodes = artifacts:%d stores:%d, want 2 and 1", artifactNodes, storeNodes)
	}
	if resourceNodes != 0 {
		t.Errorf(":MCPResource count = %d, want zero non-MCP resources", resourceNodes)
	}
	if credNodes != 0 {
		t.Errorf(":Credential count = %d, want 0 (Model Registry URIs are NOT credentials)", credNodes)
	}
	var provides, stored int
	for _, e := range res.IngestData.Graph.Edges {
		if e.Kind == "PROVIDES_RESOURCE" && e.SourceKind == "MLflowServer" && e.TargetKind == "ModelArtifact" {
			provides++
			if e.Properties["evidence_state"] != "verified" {
				t.Errorf("model inventory evidence = %+v", e.Properties)
			}
		}
		if e.Kind == "STORED_IN" && e.SourceKind == "ModelArtifact" && e.TargetKind == "ArtifactStore" {
			stored++
			if e.Properties["evidence_state"] != "observed" {
				t.Errorf("storage evidence = %+v", e.Properties)
			}
		}
	}
	if provides != 2 || stored != 2 {
		t.Errorf("typed edges = provides:%d stored:%d, want 2 and 2", provides, stored)
	}
	if res.Inventory == nil || res.Inventory.State != ingest.OutcomeComplete || res.Inventory.Items != 2 {
		t.Fatalf("inventory = %+v, want complete two-version registry", res.Inventory)
	}
}

// TestCollect_MLflow_ArtifactSensitivity locks in the sensitivity
// auto-classification heuristic per docs/reference/graph-model.md:248-256.
func TestCollect_MLflow_ArtifactSensitivity(t *testing.T) {
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

func TestCanonicalArtifactStoreIdentityAndRedaction(t *testing.T) {
	sanitized := sanitizeArtifactURI("s3://user:secret@ML-BUCKET/models/v1?token=secret#fragment")
	if sanitized != "s3://ml-bucket/models/v1" {
		t.Fatalf("sanitized URI = %q", sanitized)
	}
	remoteA, ok := canonicalArtifactStore(sanitized, "mlflow-a")
	if !ok || remoteA.RootURI != "s3://ml-bucket" || remoteA.Scope != "remote" {
		t.Fatalf("remote store = %+v, ok=%v", remoteA, ok)
	}
	remoteB, ok := canonicalArtifactStore("s3://ml-bucket/other", "mlflow-b")
	if !ok || remoteA.ID != remoteB.ID {
		t.Fatalf("same remote root did not converge: %+v %+v", remoteA, remoteB)
	}

	localA, ok := canonicalArtifactStore("file:///tmp/a/model", "mlflow-a")
	if !ok || localA.RootURI != "file:///" || localA.Scope != "service" {
		t.Fatalf("local store = %+v, ok=%v", localA, ok)
	}
	localB, ok := canonicalArtifactStore("file:///tmp/b/model", "mlflow-b")
	if !ok || localA.ID == localB.ID {
		t.Fatalf("local stores from different services merged: %+v %+v", localA, localB)
	}

	for _, unresolved := range []string{
		"models:/fraud/1", "runs:/run-1/model", "mlflow-artifacts:/exp/run/artifacts/model",
	} {
		if _, ok := canonicalArtifactStore(unresolved, "mlflow-a"); ok {
			t.Errorf("unresolved locator %q created an ArtifactStore", unresolved)
		}
		if got := sanitizeArtifactURI(unresolved); got == "" {
			t.Errorf("unresolved locator %q was not retained as sanitized metadata", unresolved)
		}
	}
}

func TestArtifactLocationPreservesSchemeSpecificIdentity(t *testing.T) {
	t.Run("Azure filesystem is part of identity", func(t *testing.T) {
		alpha := "abfss://alpha@account.dfs.core.windows.net/models/v1"
		beta := "abfss://beta@account.dfs.core.windows.net/models/v1"
		if got := sanitizeArtifactURI(alpha); got != alpha {
			t.Fatalf("sanitized ABFSS locator = %q, want %q", got, alpha)
		}
		alphaStore, alphaOK := canonicalArtifactStore(alpha, "mlflow")
		betaStore, betaOK := canonicalArtifactStore(beta, "mlflow")
		if !alphaOK || !betaOK || alphaStore.ID == betaStore.ID {
			t.Fatalf("distinct Azure filesystems collapsed: %+v/%t %+v/%t", alphaStore, alphaOK, betaStore, betaOK)
		}
		if alphaStore.RootURI != "abfss://alpha@account.dfs.core.windows.net" {
			t.Fatalf("Azure root = %q", alphaStore.RootURI)
		}
	})

	t.Run("object key path is reported material", func(t *testing.T) {
		raw := "s3://fixture-bucket/models/./version"
		if got := sanitizeArtifactURI(raw); got != raw {
			t.Fatalf("sanitized object locator = %q, want %q", got, raw)
		}
	})
}

func TestCollect_MLflow_RegistryLimitAndLookupFailureAreIncomplete(t *testing.T) {
	for _, tc := range []struct {
		name      string
		download  int
		wantState ingest.OutcomeState
	}{
		{name: "pagination limit", download: http.StatusOK, wantState: ingest.OutcomeTruncated},
		{name: "download lookup failure", download: http.StatusInternalServerError, wantState: ingest.OutcomePartial},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch r.URL.Path {
				case "/api/2.0/mlflow/experiments/search":
					_, _ = w.Write([]byte(`{"experiments":[],"next_page_token":""}`))
				case "/api/2.0/mlflow/registered-models/search":
					next := ""
					if tc.wantState == ingest.OutcomeTruncated {
						next = "more"
					}
					_, _ = fmt.Fprintf(w, `{"registered_models":[{"name":"model"}],"next_page_token":%q}`, next)
				case "/api/2.0/mlflow/model-versions/search":
					next := ""
					if tc.wantState == ingest.OutcomeTruncated {
						next = "more"
					}
					_, _ = fmt.Fprintf(w, `{"model_versions":[{"name":"model","version":"1"}],"next_page_token":%q}`, next)
				case "/api/2.0/mlflow/model-versions/get-download-uri":
					if tc.download != http.StatusOK {
						w.WriteHeader(tc.download)
						return
					}
					_, _ = w.Write([]byte(`{"artifact_uri":"s3://bucket/model/1"}`))
				default:
					http.NotFound(w, r)
				}
			}))
			defer srv.Close()

			res, err := (&Collector{}).Collect(context.Background(), action.Target{
				Address: strings.TrimPrefix(srv.URL, "http://"),
			}, action.CollectOptions{MaxItems: 1})
			if err != nil {
				t.Fatalf("Collect: %v", err)
			}
			if res.Inventory == nil || res.Inventory.State != tc.wantState || res.Inventory.Items != 1 {
				t.Fatalf("inventory = %+v, want %s with one artifact", res.Inventory, tc.wantState)
			}
			var artifacts, resources int
			for _, node := range res.IngestData.Graph.Nodes {
				switch node.Kinds[0] {
				case "ModelArtifact":
					artifacts++
				case "MCPResource":
					resources++
				}
			}
			if artifacts != 1 || resources != 0 {
				t.Fatalf("nodes = artifacts:%d MCPResources:%d", artifacts, resources)
			}
		})
	}
}

// TestCollect_MLflow_RegistryPartialFailure — Registry endpoints return
// 404 (older MLflow without the Model Registry API); the tracking
// probes still land and Registry failures are recorded as partials.
func TestCollect_MLflow_RegistryPartialFailure(t *testing.T) {
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

	l := &Collector{}
	res, err := l.Collect(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.CollectOptions{})
	if err != nil {
		t.Fatalf("Collect should not error on partial failures: %v", err)
	}
	// experiment_count + total_runs still populated.
	if _, ok := res.IngestData.Graph.Nodes[0].Properties["experiment_count"]; !ok {
		t.Errorf("experiment_count missing after Registry 404")
	}
	// Registry probes recorded as partials.
	if res.Summary.PartialFailures < 2 {
		t.Errorf("partial failures: got %d, want at least 2 (registered-models + model-versions)", res.Summary.PartialFailures)
	}
	if res.Inventory == nil || res.Inventory.State != ingest.OutcomeFailed {
		t.Fatalf("unavailable registry inventory = %+v, want failed", res.Inventory)
	}
}

func TestCollect_CancellationStopsPerItemWalks(t *testing.T) {
	tests := []struct {
		name            string
		cancelPath      string
		experimentsBody string
		versionsBody    string
		wantProbes      int
	}{
		{
			name:            "runs",
			cancelPath:      "/api/2.0/mlflow/runs/search",
			experimentsBody: `{"experiments":[{"experiment_id":"1"},{"experiment_id":"2"},{"experiment_id":"3"}]}`,
			versionsBody:    `{"model_versions":[]}`,
			wantProbes:      3,
		},
		{
			name:            "download URI",
			cancelPath:      "/api/2.0/mlflow/model-versions/get-download-uri",
			experimentsBody: `{"experiments":[]}`,
			versionsBody:    `{"model_versions":[{"name":"one","version":"1"},{"name":"two","version":"1"},{"name":"three","version":"1"}]}`,
			wantProbes:      5,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			started := make(chan struct{})
			requestRelease := make(chan struct{})
			var canceledCalls atomic.Int32
			var signalOnce sync.Once
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == tc.cancelPath {
					canceledCalls.Add(1)
					signalOnce.Do(func() { close(started) })
					<-requestRelease
					return
				}
				switch r.URL.Path {
				case "/api/2.0/mlflow/experiments/search":
					_, _ = w.Write([]byte(tc.experimentsBody))
				case "/api/2.0/mlflow/registered-models/search":
					_, _ = w.Write([]byte(`{"registered_models":[]}`))
				case "/api/2.0/mlflow/model-versions/search":
					_, _ = w.Write([]byte(tc.versionsBody))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer srv.Close()

			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan *action.CollectResult, 1)
			go func() {
				res, _ := (&Collector{}).Collect(ctx, action.Target{
					Kind:    "host",
					Address: strings.TrimPrefix(srv.URL, "http://"),
				}, action.CollectOptions{})
				done <- res
			}()

			select {
			case <-started:
				cancel()
				close(requestRelease)
			case <-time.After(2 * time.Second):
				cancel()
				close(requestRelease)
				t.Fatalf("request to %s did not start", tc.cancelPath)
			}

			var res *action.CollectResult
			select {
			case res = <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("Collect did not return after cancellation")
			}
			if got := canceledCalls.Load(); got != 1 {
				t.Fatalf("requests to %s after cancellation = %d, want 1", tc.cancelPath, got)
			}
			if got := res.Summary.EndpointsProbed; got != tc.wantProbes {
				t.Fatalf("endpoints probed = %d, want %d", got, tc.wantProbes)
			}
			if res.Inventory == nil || res.Inventory.State == ingest.OutcomeComplete {
				t.Fatalf("canceled inventory became authoritative: %+v", res.Inventory)
			}
		})
	}
}
