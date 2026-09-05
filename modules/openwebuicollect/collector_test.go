package openwebuicollect

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/adithyan-ak/agenthound/modules/openwebuifp"
	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/common"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
)

// configBody matches Open WebUI's real /api/config shape (verified
// across v0.1.111..v0.9.6 + main). No `default_user_role` and no
// `ollama` sub-object — both were absent from every version.
const configBody = `{"status":true,"name":"Open WebUI","version":"0.6.32","features":{"auth":false,"enable_signup":true}}`

// openaiConfigBody mirrors GET /openai/config: parallel OPENAI_API_KEYS /
// OPENAI_API_BASE_URLS arrays. The empty-key entry at index 1 must be
// skipped.
const openaiConfigBody = `{"ENABLE_OPENAI_API":true,"OPENAI_API_BASE_URLS":["https://api.openai.com/v1","http://10.0.0.5:11434/v1"],"OPENAI_API_KEYS":["sk-proj-secret-abc123",""]}`

// stubRoute is a single stub-server handler entry.
type stubRoute struct {
	body   string
	status int // 0 => 200
}

// openwebuiStubOptions configures which endpoints the stub serves.
type openwebuiStubOptions struct {
	apiKey              string
	config              string
	openaiConfig        string
	ollamaConfig        string
	retrievalConfig     string
	retrievalEmbedding  string
	externalConnections string
	// If not nil, override with explicit status codes for specific paths.
	overrides map[string]stubRoute
	// Tracks all (method, path) pairs the stub sees.
	tracker *sync.Map
}

func openwebuiStub(t *testing.T, opts openwebuiStubOptions) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if opts.tracker != nil {
			opts.tracker.Store(r.Method+" "+r.URL.Path, true)
		}
		w.Header().Set("Content-Type", "application/json")
		if o, ok := opts.overrides[r.URL.Path]; ok {
			if o.status != 0 {
				w.WriteHeader(o.status)
			}
			_, _ = w.Write([]byte(o.body))
			return
		}
		if r.URL.Path != "/api/config" {
			if opts.apiKey != "" && r.Header.Get("Authorization") != "Bearer "+opts.apiKey {
				w.WriteHeader(401)
				return
			}
		}
		switch r.URL.Path {
		case "/api/version":
			_, _ = w.Write([]byte(`{"version":"0.6.32"}`))
		case "/api/config":
			body := opts.config
			if body == "" {
				body = configBody
			}
			_, _ = w.Write([]byte(body))
		case "/openai/config":
			body := opts.openaiConfig
			if body == "" {
				body = `{}`
			}
			_, _ = w.Write([]byte(body))
		case "/ollama/config":
			body := opts.ollamaConfig
			if body == "" {
				body = `{}`
			}
			_, _ = w.Write([]byte(body))
		case "/api/v1/retrieval/config":
			body := opts.retrievalConfig
			if body == "" {
				body = `{}`
			}
			_, _ = w.Write([]byte(body))
		case "/api/v1/retrieval/embedding":
			body := opts.retrievalEmbedding
			if body == "" {
				body = `{}`
			}
			_, _ = w.Write([]byte(body))
		case "/api/v1/knowledge/external/connections":
			body := opts.externalConnections
			if body == "" {
				body = `{"items":[],"total":0}`
			}
			_, _ = w.Write([]byte(body))
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestFingerprintAndLootPropertiesComposeOnSameEndpoint(t *testing.T) {
	srv := openwebuiStub(t, openwebuiStubOptions{})
	defer srv.Close()
	target := action.Target{Kind: "host", Address: addrOf(srv)}

	fingerprinter, err := openwebuifp.New()
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
		if key == "last_verified_at" {
			continue
		}
		if lootValue, shared := lootNode.Properties[key]; shared &&
			!reflect.DeepEqual(fingerprintValue, lootValue) {
			t.Errorf("shared property %q conflicts: fingerprint=%#v collection=%#v", key, fingerprintValue, lootValue)
		}
	}
	if _, exists := fingerprintNode.Properties["auth_method"]; exists {
		t.Errorf("fingerprint authored auth_method: %+v", fingerprintNode.Properties)
	}
	if lootNode.Properties["auth_method"] != string(common.AuthNone) ||
		lootNode.Properties["auth_evidence"] != common.AuthEvidenceAnonymousProbeSucceeded {
		t.Errorf("looter lost affirmative anonymous evidence: %+v", lootNode.Properties)
	}
	if fingerprintNode.Properties["discovered_via"] != "network_scan" ||
		lootNode.Properties["collection_observed"] != true {
		t.Errorf("action provenance not separated: fingerprint=%+v collection=%+v", fingerprintNode.Properties, lootNode.Properties)
	}
}

func TestProtectedFingerprintLeavesAuthOwnershipToLooter(t *testing.T) {
	srv := openwebuiStub(t, openwebuiStubOptions{
		config: `{"status":true,"name":"Open WebUI","version":"0.6.32","features":{"auth":true,"enable_signup":false}}`,
	})
	defer srv.Close()
	target := action.Target{Kind: "host", Address: addrOf(srv)}

	fingerprinter, err := openwebuifp.New()
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
	fingerprintProps := fingerprint.IngestData.Graph.Nodes[0].Properties
	lootProps := collection.IngestData.Graph.Nodes[0].Properties
	for _, key := range []string{"auth_method", "auth_assurance", "auth_evidence"} {
		if _, exists := fingerprintProps[key]; exists {
			t.Errorf("protected public fingerprint authored %s: %+v", key, fingerprintProps)
		}
	}
	if lootProps["auth_required"] != true ||
		lootProps["auth_method"] != string(common.AuthUnknown) ||
		lootProps["auth_evidence"] != common.AuthEvidenceUnknown {
		t.Errorf("protected looter evidence = %+v", lootProps)
	}
}

func TestProtectedPostureIsStableAcrossCredentialAttempts(t *testing.T) {
	const acceptedKey = "sk-accepted-openwebui-admin-key"
	srv := openwebuiStub(t, openwebuiStubOptions{
		apiKey:       acceptedKey,
		config:       `{"status":true,"name":"Open WebUI","version":"0.6.32","features":{"auth":true,"enable_signup":false}}`,
		openaiConfig: `{}`,
	})
	defer srv.Close()

	target := action.Target{Kind: "host", Address: addrOf(srv)}
	collect := func(key string) ingest.Node {
		t.Helper()
		opts := action.CollectOptions{}
		if key != "" {
			opts.Extras = map[string]any{"api-key": key}
		}
		result, err := (&Collector{}).Collect(context.Background(), target, opts)
		if err != nil {
			t.Fatalf("collect with credential %q: %v", key, err)
		}
		return result.IngestData.Graph.Nodes[0]
	}

	nodes := []ingest.Node{
		collect(""),
		collect(acceptedKey),
		collect("sk-rejected-openwebui-admin-key"),
	}
	want := map[string]any{
		"auth_required":  true,
		"auth_method":    string(common.AuthUnknown),
		"auth_assurance": string(common.AuthAssuranceUnknown),
		"auth_evidence":  common.AuthEvidenceUnknown,
	}
	for index, node := range nodes {
		if node.ID != nodes[0].ID {
			t.Fatalf("attempt %d service ID = %q, want shared endpoint ID %q", index, node.ID, nodes[0].ID)
		}
		for key, value := range want {
			if node.Properties[key] != value {
				t.Errorf("attempt %d %s = %v, want %v", index, key, node.Properties[key], value)
			}
		}
	}
}

func addrOf(srv *httptest.Server) string {
	return strings.TrimPrefix(srv.URL, "http://")
}

// TestCollect_OpenWebUI_AnonymousPosture — no api-key supplied, only the
// posture props land. Instance node carries signup_enabled + auth_required.
func TestCollect_OpenWebUI_AnonymousPosture(t *testing.T) {
	srv := openwebuiStub(t, openwebuiStubOptions{})
	defer srv.Close()

	l := &Collector{}
	res, err := l.Collect(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.CollectOptions{})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := len(res.IngestData.Graph.Nodes); got != 1 {
		t.Fatalf("nodes: got %d, want 1 (OpenWebUIInstance)", got)
	}
	node := res.IngestData.Graph.Nodes[0]
	if node.Kinds[0] != "OpenWebUIInstance" {
		t.Errorf("kind = %v, want OpenWebUIInstance", node.Kinds)
	}
	if node.Properties["collection_observed"] != true {
		t.Errorf("OpenWebUIInstance missing collection_observed: %+v", node.Properties)
	}
	if _, exists := node.Properties["discovered_via"]; exists {
		t.Errorf("direct collection claimed discovery provenance: %+v", node.Properties)
	}
	if se, _ := node.Properties["signup_enabled"].(bool); !se {
		t.Errorf("signup_enabled = %v, want true", node.Properties["signup_enabled"])
	}
	if ar, ok := node.Properties["auth_required"].(bool); !ok || ar {
		t.Errorf("auth_required = %v, want false", node.Properties["auth_required"])
	}
	if _, ok := node.Properties["default_user_role"]; ok {
		t.Errorf("default_user_role should not be set (dead field removed)")
	}
	if res.Summary.CredentialsFound != 0 {
		t.Errorf("CredentialsFound = %d, want 0 in anonymous mode", res.Summary.CredentialsFound)
	}
	if got := len(res.IngestData.Graph.Edges); got != 0 {
		t.Errorf("edges: got %d, want 0 in anonymous mode", got)
	}
	if res.Inventory == nil || res.Inventory.Name != "configuration" || res.Inventory.State != ingest.OutcomeFailed {
		t.Fatalf("anonymous backend inventory = %+v, want failed until admin config is read", res.Inventory)
	}
}

// TestCollect_OpenWebUI_AuthenticatedCredentials — /openai/config path
// still works end-to-end, emitting 1 Credential and 1 EXPOSES_CREDENTIAL
// edge for the non-empty key.
func TestCollect_OpenWebUI_AuthenticatedCredentials(t *testing.T) {
	const key = "sk-operator-admin-token"
	srv := openwebuiStub(t, openwebuiStubOptions{
		apiKey:       key,
		openaiConfig: openaiConfigBody,
	})
	defer srv.Close()

	l := &Collector{}
	res, err := l.Collect(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.CollectOptions{
		Extras: map[string]any{"api-key": key},
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := len(res.IngestData.Graph.Nodes); got != 2 {
		t.Fatalf("nodes: got %d, want 2 (instance + 1 credential)", got)
	}
	var cred *struct {
		valueHash string
		hasValue  bool
		mergeKey  string
	}
	for _, n := range res.IngestData.Graph.Nodes {
		if n.Kinds[0] != "Credential" {
			continue
		}
		vh, _ := n.Properties["value_hash"].(string)
		_, hasVal := n.Properties["value"]
		mk, _ := n.Properties["merge_key"].(string)
		cred = &struct {
			valueHash string
			hasValue  bool
			mergeKey  string
		}{valueHash: vh, hasValue: hasVal, mergeKey: mk}
	}
	if cred == nil {
		t.Fatal("no Credential node emitted")
	}
	wantHash := common.HashCredentialValue("sk-proj-secret-abc123")
	if cred.valueHash != wantHash {
		t.Errorf("value_hash = %q, want %q", cred.valueHash, wantHash)
	}
	if !cred.hasValue {
		t.Errorf("raw value was not captured")
	}
	if cred.mergeKey != "value_hash" {
		t.Errorf("merge_key = %q, want value_hash", cred.mergeKey)
	}
	if res.Summary.CredentialsFound != 1 {
		t.Errorf("CredentialsFound = %d, want 1", res.Summary.CredentialsFound)
	}
	if got := len(res.IngestData.Graph.Edges); got != 1 {
		t.Fatalf("edges: got %d, want 1", got)
	}
	e := res.IngestData.Graph.Edges[0]
	if e.Kind != "EXPOSES_CREDENTIAL" || e.SourceKind != "AIService" || e.TargetKind != "Credential" {
		t.Errorf("edge = %+v, want EXPOSES_CREDENTIAL AIService->Credential", e)
	}
}

func TestCollect_OpenWebUI_RawValueGated(t *testing.T) {
	const key = "sk-operator-admin-token"
	srv := openwebuiStub(t, openwebuiStubOptions{
		apiKey:       key,
		openaiConfig: openaiConfigBody,
	})
	defer srv.Close()

	l := &Collector{}
	res, err := l.Collect(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.CollectOptions{
		Extras: map[string]any{"api-key": key},
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var found bool
	for _, n := range res.IngestData.Graph.Nodes {
		if n.Kinds[0] != "Credential" {
			continue
		}
		found = true
		if v, _ := n.Properties["value"].(string); v != "sk-proj-secret-abc123" {
			t.Errorf("value = %q, want raw observed key", v)
		}
		if _, ok := n.Properties["value_hash"]; !ok {
			t.Errorf("value_hash must remain populated even with raw value")
		}
	}
	if !found {
		t.Fatal("no Credential node emitted")
	}
}

// TestCollect_OpenWebUI_ConfigFails — non-2xx on /api/config is a partial
// failure, not a fatal error. Instance node still emitted.
func TestCollect_OpenWebUI_ConfigFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	l := &Collector{}
	res, err := l.Collect(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.CollectOptions{})
	if err != nil {
		t.Fatalf("Collect should not error on partial failures: %v", err)
	}
	if got := len(res.IngestData.Graph.Nodes); got != 1 {
		t.Fatalf("nodes: got %d, want 1 (OpenWebUIInstance still emitted)", got)
	}
	if _, ok := res.IngestData.Graph.Nodes[0].Properties["signup_enabled"]; ok {
		t.Errorf("signup_enabled should be absent when /api/config fails")
	}
	if res.Summary.PartialFailures != 1 {
		t.Errorf("PartialFailures = %d, want 1", res.Summary.PartialFailures)
	}
}

// TestCollect_OpenWebUI_AuthRejected — /openai/config returns 401 (e.g.
// non-admin key). Anonymous posture still lands and the credential
// probe records a partial failure.
func TestCollect_OpenWebUI_AuthRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/config":
			_, _ = w.Write([]byte(configBody))
		default:
			w.WriteHeader(401)
		}
	}))
	defer srv.Close()

	l := &Collector{}
	res, err := l.Collect(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.CollectOptions{
		Extras: map[string]any{"api-key": "sk-nonadmin"},
	})
	if err != nil {
		t.Fatalf("Collect should not error on partial failures: %v", err)
	}
	if se, _ := res.IngestData.Graph.Nodes[0].Properties["signup_enabled"].(bool); !se {
		t.Errorf("anonymous posture must land even when auth probes fail")
	}
	if res.Summary.CredentialsFound != 0 {
		t.Errorf("CredentialsFound = %d, want 0 when auth rejected", res.Summary.CredentialsFound)
	}
	// Authenticated probes all return 401 and remain non-fatal journal evidence.
	if res.Summary.PartialFailures < 1 {
		t.Errorf("PartialFailures = %d, want at least 1", res.Summary.PartialFailures)
	}
}

// TestCollect_OpenWebUI_OllamaConfig_KeyField — the primary shape:
// OLLAMA_API_CONFIGS keyed by string index, per-URL config uses `key`.
// Asserts 1 Credential + 1 :OllamaInstance placeholder + 1 :USES_BACKEND
// edge + canonicalized backend URL list.
func TestCollect_OpenWebUI_OllamaConfig_KeyField(t *testing.T) {
	const key = "admin-jwt"
	srv := openwebuiStub(t, openwebuiStubOptions{
		apiKey:       key,
		ollamaConfig: `{"ENABLE_OLLAMA_API":true,"OLLAMA_BASE_URLS":["http://10.0.0.5:11434"],"OLLAMA_API_CONFIGS":{"0":{"key":"sk-ollama-idx","enable":true}}}`,
	})
	defer srv.Close()

	l := &Collector{}
	res, err := l.Collect(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.CollectOptions{
		Extras: map[string]any{"api-key": key},
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var credCount, ollamaCount, backendEdgeCount int
	for _, n := range res.IngestData.Graph.Nodes {
		switch n.Kinds[0] {
		case "Credential":
			credCount++
			if vh, _ := n.Properties["value_hash"].(string); vh != common.HashCredentialValue("sk-ollama-idx") {
				t.Errorf("value_hash mismatch: %v", vh)
			}
			if n.Properties["material_status"] != "observed" ||
				n.Properties["exposure_status"] != "exposed" {
				t.Errorf("observed OpenWebUI secret missing evidence state: %+v", n.Properties)
			}
		case "OllamaInstance":
			ollamaCount++
			if _, claimed := n.Properties["auth_method"]; claimed {
				t.Errorf("configured backend claimed observed auth: %+v", n.Properties)
			}
			if _, claimed := n.Properties["probe_status"]; claimed {
				t.Errorf("configured backend claimed a probe result: %+v", n.Properties)
			}
			if _, claimed := n.Properties["discovered_via"]; claimed {
				t.Errorf("configured backend overwrote active discovery provenance: %+v", n.Properties)
			}
			if n.Properties["configuration_observed"] != true ||
				n.Properties["configured_auth_method"] != "apiKey" {
				t.Errorf("configured backend evidence missing: %+v", n.Properties)
			}
		}
	}
	if credCount != 1 {
		t.Errorf("Credential count = %d, want 1", credCount)
	}
	if ollamaCount != 1 {
		t.Errorf("OllamaInstance placeholder count = %d, want 1", ollamaCount)
	}
	for _, e := range res.IngestData.Graph.Edges {
		if e.Kind == "EXPOSES" {
			t.Fatalf("collector emitted deprecated Open WebUI backend edge: %+v", e)
		}
		if e.Kind == "USES_BACKEND" {
			backendEdgeCount++
			if e.SourceKind != "OpenWebUIInstance" || e.TargetKind != "OllamaInstance" {
				t.Errorf("USES_BACKEND edge kinds = %s -> %s", e.SourceKind, e.TargetKind)
			}
			if e.Properties["evidence_state"] != "configured" {
				t.Errorf("configured edge overclaimed verification: %+v", e.Properties)
			}
		}
	}
	if backendEdgeCount != 1 {
		t.Errorf("USES_BACKEND edge count = %d, want 1", backendEdgeCount)
	}
	urls, _ := res.IngestData.Graph.Nodes[0].Properties["ollama_backend_urls"].([]string)
	if len(urls) != 1 || urls[0] != "http://10.0.0.5:11434" {
		t.Errorf("ollama_backend_urls = %v, want [http://10.0.0.5:11434]", urls)
	}
	if res.Inventory == nil || res.Inventory.State != ingest.OutcomeComplete || res.Inventory.Items != 1 {
		t.Fatalf("backend inventory = %+v, want complete with one Ollama backend", res.Inventory)
	}
}

func TestCollect_OpenWebUI_EnabledQdrantBackendIsTypedAndRedacted(t *testing.T) {
	const key = "admin-jwt"
	srv := openwebuiStub(t, openwebuiStubOptions{
		apiKey:       key,
		ollamaConfig: `{"OLLAMA_BASE_URLS":[]}`,
		externalConnections: `{
			"items":[
				{"id":"q-1","provider":"qdrant","endpoint":"qdrant","enabled":true,"auth_configured":true,"auth_config":{"api_key":"must-not-leak"}},
				{"id":"q-2","provider":"QDRANT","endpoint":"http://QDRANT:6333/","enabled":true,"auth_configured":false},
				{"id":"q-disabled","provider":"qdrant","endpoint":"http://disabled:6333","enabled":false,"auth_configured":false},
				{"id":"milvus","provider":"milvus","endpoint":"http://milvus:19530","enabled":true,"auth_configured":false}
			],
			"total":4
		}`,
	})
	defer srv.Close()

	res, err := (&Collector{}).Collect(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.CollectOptions{Extras: map[string]any{"api-key": key}})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	qdrantID := ingest.ComputeNodeID("QdrantInstance", "http://qdrant:6333")
	var qdrantNodes, backendEdges int
	for _, node := range res.IngestData.Graph.Nodes {
		if node.Kinds[0] != "QdrantInstance" {
			continue
		}
		qdrantNodes++
		if node.ID != qdrantID || node.Properties["endpoint"] != "http://qdrant:6333" {
			t.Errorf("Qdrant identity = %+v", node)
		}
		if node.Properties["configured_auth_method"] != "apiKey" {
			t.Errorf("aggregated auth posture = %+v", node.Properties)
		}
	}
	for _, edge := range res.IngestData.Graph.Edges {
		if edge.Kind == "EXPOSES" {
			t.Fatalf("collector emitted deprecated Open WebUI backend edge: %+v", edge)
		}
		if edge.Kind != "USES_BACKEND" || edge.TargetKind != "QdrantInstance" {
			continue
		}
		backendEdges++
		if edge.SourceKind != "OpenWebUIInstance" || edge.Target != qdrantID ||
			edge.Properties["evidence_state"] != "configured" {
			t.Errorf("Qdrant backend edge = %+v", edge)
		}
	}
	if qdrantNodes != 1 || backendEdges != 1 {
		t.Fatalf("Qdrant topology = nodes:%d edges:%d, want one converged path", qdrantNodes, backendEdges)
	}
	if res.Inventory == nil || res.Inventory.State != ingest.OutcomeComplete || res.Inventory.Items != 1 {
		t.Fatalf("backend inventory = %+v, want complete one-backend surface", res.Inventory)
	}
	encoded, err := json.Marshal(res.IngestData.Graph)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "must-not-leak") || credCount(res) != 0 {
		t.Fatalf("external backend credential leaked into graph: %s", encoded)
	}
}

func TestCollect_OpenWebUI_IncompleteExternalConnectionsStayNonAuthoritative(t *testing.T) {
	const key = "admin-jwt"
	srv := openwebuiStub(t, openwebuiStubOptions{
		apiKey:       key,
		ollamaConfig: `{}`,
		externalConnections: `{
			"items":[{"id":"q-1","provider":"qdrant","endpoint":"http://qdrant:6333","enabled":true}],
			"total":2
		}`,
	})
	defer srv.Close()
	res, err := (&Collector{}).Collect(context.Background(), action.Target{
		Address: addrOf(srv),
	}, action.CollectOptions{Extras: map[string]any{"api-key": key}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Inventory == nil || res.Inventory.State != ingest.OutcomePartial {
		t.Fatalf("incomplete response inventory = %+v, want partial", res.Inventory)
	}
}

func TestCollect_OpenWebUI_ConfigurationFailurePreventsAuthoritativeInventory(t *testing.T) {
	const key = "admin-jwt"
	srv := openwebuiStub(t, openwebuiStubOptions{
		apiKey:       key,
		ollamaConfig: `{"OLLAMA_BASE_URLS":["http://ollama:11434"]}`,
		overrides: map[string]stubRoute{
			"/api/v1/retrieval/config": {status: http.StatusInternalServerError},
		},
	})
	defer srv.Close()
	res, err := (&Collector{}).Collect(context.Background(), action.Target{
		Address: addrOf(srv),
	}, action.CollectOptions{Extras: map[string]any{"api-key": key}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Inventory == nil || res.Inventory.State != ingest.OutcomePartial {
		t.Fatalf("failed configuration read inventory = %+v, want partial", res.Inventory)
	}
}

func TestCollect_OpenWebUI_BackendLimitReportsTruncation(t *testing.T) {
	const key = "admin-jwt"
	srv := openwebuiStub(t, openwebuiStubOptions{
		apiKey:       key,
		ollamaConfig: `{"OLLAMA_BASE_URLS":[]}`,
		externalConnections: `{
			"items":[
				{"id":"q-1","provider":"qdrant","endpoint":"http://qdrant-a:6333","enabled":true},
				{"id":"q-2","provider":"qdrant","endpoint":"http://qdrant-b:6333","enabled":true}
			],
			"total":2
		}`,
	})
	defer srv.Close()
	res, err := (&Collector{}).Collect(context.Background(), action.Target{
		Address: addrOf(srv),
	}, action.CollectOptions{MaxItems: 1, Extras: map[string]any{"api-key": key}})
	if err != nil {
		t.Fatal(err)
	}
	if res.Inventory == nil || res.Inventory.State != ingest.OutcomeTruncated || res.Inventory.Items != 1 {
		t.Fatalf("bounded configuration inventory = %+v, want one emitted item and truncated", res.Inventory)
	}
	var qdrantNodes int
	for _, node := range res.IngestData.Graph.Nodes {
		if node.Kinds[0] == "QdrantInstance" {
			qdrantNodes++
		}
	}
	if qdrantNodes != 1 {
		t.Fatalf("Qdrant nodes = %d, want bounded emission of one", qdrantNodes)
	}
}

// TestCollect_OpenWebUI_OllamaConfig_URLKeyed — same result via URL-keyed
// OLLAMA_API_CONFIGS lookup (the second fallback path in Open WebUI's
// get_api_key).
func TestCollect_OpenWebUI_OllamaConfig_URLKeyed(t *testing.T) {
	const key = "admin-jwt"
	srv := openwebuiStub(t, openwebuiStubOptions{
		apiKey:       key,
		ollamaConfig: `{"OLLAMA_BASE_URLS":["http://10.0.0.5:11434"],"OLLAMA_API_CONFIGS":{"http://10.0.0.5:11434":{"key":"sk-ollama-url"}}}`,
	})
	defer srv.Close()

	l := &Collector{}
	res, err := l.Collect(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.CollectOptions{
		Extras: map[string]any{"api-key": key},
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var found bool
	for _, n := range res.IngestData.Graph.Nodes {
		if n.Kinds[0] != "Credential" {
			continue
		}
		if vh, _ := n.Properties["value_hash"].(string); vh == common.HashCredentialValue("sk-ollama-url") {
			found = true
		}
	}
	if !found {
		t.Error("URL-keyed OLLAMA_API_CONFIGS lookup did not capture key")
	}
}

// TestCollect_OpenWebUI_OllamaConfig_LegacyAPIKey — decoding falls back
// to `api_key` when `key` is absent (older/forked Open WebUI).
func TestCollect_OpenWebUI_OllamaConfig_LegacyAPIKey(t *testing.T) {
	const key = "admin-jwt"
	srv := openwebuiStub(t, openwebuiStubOptions{
		apiKey:       key,
		ollamaConfig: `{"OLLAMA_BASE_URLS":["http://10.0.0.5:11434"],"OLLAMA_API_CONFIGS":{"0":{"api_key":"sk-legacy-abc"}}}`,
	})
	defer srv.Close()

	l := &Collector{}
	res, err := l.Collect(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.CollectOptions{
		Extras: map[string]any{"api-key": key},
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	var found bool
	for _, n := range res.IngestData.Graph.Nodes {
		if n.Kinds[0] != "Credential" {
			continue
		}
		if vh, _ := n.Properties["value_hash"].(string); vh == common.HashCredentialValue("sk-legacy-abc") {
			found = true
		}
	}
	if !found {
		t.Error("legacy api_key fallback did not capture key")
	}
}

// TestCollect_OpenWebUI_RetrievalConfig_FlatKey — three flat UPPER_SNAKE
// fields matching different positive suffixes.
func TestCollect_OpenWebUI_RetrievalConfig_FlatKey(t *testing.T) {
	const key = "admin-jwt"
	srv := openwebuiStub(t, openwebuiStubOptions{
		apiKey:          key,
		retrievalConfig: `{"RAG_EXTERNAL_RERANKER_API_KEY":"sk-rerank-long-secret","PADDLEOCR_VL_TOKEN":"tok-abc-1234567","YACY_PASSWORD":"pw-secret-yacy-1"}`,
	})
	defer srv.Close()

	l := &Collector{}
	res, err := l.Collect(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.CollectOptions{
		Extras: map[string]any{"api-key": key},
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	names := credNames(res)
	sort.Strings(names)
	// Path slugs include the "openwebui-retrieval_config-" prefix.
	wantContains := []string{
		"rag_external_reranker_api_key",
		"paddleocr_vl_token",
		"yacy_password",
	}
	if len(names) != 3 {
		t.Fatalf("Credential count = %d (%v), want 3", len(names), names)
	}
	for _, want := range wantContains {
		found := false
		for _, n := range names {
			if strings.Contains(n, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no Credential name contains %q; names = %v", want, names)
		}
	}
}

// TestCollect_OpenWebUI_RetrievalConfig_SubscriptionKey — SUBSCRIPTION
// suffix must match (BING_SEARCH_V7_SUBSCRIPTION_KEY at retrieval.py:711).
func TestCollect_OpenWebUI_RetrievalConfig_SubscriptionKey(t *testing.T) {
	const key = "admin-jwt"
	srv := openwebuiStub(t, openwebuiStubOptions{
		apiKey:          key,
		retrievalConfig: `{"BING_SEARCH_V7_SUBSCRIPTION_KEY":"sub-abc-1234567"}`,
	})
	defer srv.Close()

	l := &Collector{}
	res, err := l.Collect(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.CollectOptions{
		Extras: map[string]any{"api-key": key},
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := credCount(res); got != 1 {
		t.Errorf("SUBSCRIPTION_KEY captured: got %d, want 1", got)
	}
}

// TestCollect_OpenWebUI_RetrievalConfig_SkSuffix — _SK trailing shorthand
// (SOUGOU_API_SK at retrieval.py:721).
func TestCollect_OpenWebUI_RetrievalConfig_SkSuffix(t *testing.T) {
	const key = "admin-jwt"
	srv := openwebuiStub(t, openwebuiStubOptions{
		apiKey:          key,
		retrievalConfig: `{"SOUGOU_API_SK":"sk-sougou-longish-secret"}`,
	})
	defer srv.Close()

	l := &Collector{}
	res, err := l.Collect(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.CollectOptions{
		Extras: map[string]any{"api-key": key},
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := credCount(res); got != 1 {
		t.Errorf("_SK suffix captured: got %d, want 1", got)
	}
}

// TestCollect_OpenWebUI_RetrievalEmbedding_Nested — recursion must descend
// into openai_config.key / ollama_config.key / azure_openai_config.key
// (retrieval.py:445-457).
func TestCollect_OpenWebUI_RetrievalEmbedding_Nested(t *testing.T) {
	const key = "admin-jwt"
	srv := openwebuiStub(t, openwebuiStubOptions{
		apiKey: key,
		retrievalEmbedding: `{
			"RAG_EMBEDDING_ENGINE":"openai",
			"openai_config":{"url":"https://api.openai.com/v1","key":"sk-nested-openai-1"},
			"ollama_config":{"url":"http://ollama:11434","key":"sk-nested-ollama-1"},
			"azure_openai_config":{"url":"https://azure/","key":"sk-nested-azure-1","version":"2024-02-01"}
		}`,
	})
	defer srv.Close()

	l := &Collector{}
	res, err := l.Collect(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.CollectOptions{
		Extras: map[string]any{"api-key": key},
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	names := credNames(res)
	sort.Strings(names)
	if len(names) != 3 {
		t.Fatalf("nested credential count = %d (%v), want 3", len(names), names)
	}
	for _, want := range []string{
		"openai_config.key", "ollama_config.key", "azure_openai_config.key",
	} {
		found := false
		for _, n := range names {
			if strings.Contains(n, want) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("no Credential name contains %q; names = %v", want, names)
		}
	}
}

// TestCollect_OpenWebUI_Walker_NegativeFilters — MODEL/ENGINE/LANGUAGE
// suffixes must NOT trigger the walker even when they include
// TOKEN/KEY substrings.
func TestCollect_OpenWebUI_Walker_NegativeFilters(t *testing.T) {
	const key = "admin-jwt"
	srv := openwebuiStub(t, openwebuiStubOptions{
		apiKey: key,
		retrievalConfig: `{
			"RAG_TOKENIZER_MODEL":"tiktoken-cl100k",
			"SEARCHAPI_ENGINE":"google",
			"YOUTUBE_LOADER_LANGUAGE":"en",
			"EMPTY_API_KEY":""
		}`,
	})
	defer srv.Close()

	l := &Collector{}
	res, err := l.Collect(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.CollectOptions{
		Extras: map[string]any{"api-key": key},
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := credCount(res); got != 0 {
		t.Errorf("negative-filter walker captures: got %d, want 0 (%v)", got, credNames(res))
	}
}

// TestCollect_OpenWebUI_Walker_ShortValueSkipped — values shorter than 8
// chars are treated as noise (real secrets are always longer).
func TestCollect_OpenWebUI_Walker_ShortValueSkipped(t *testing.T) {
	const key = "admin-jwt"
	srv := openwebuiStub(t, openwebuiStubOptions{
		apiKey:          key,
		retrievalConfig: `{"TEST_API_KEY":"abc"}`,
	})
	defer srv.Close()

	l := &Collector{}
	res, err := l.Collect(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.CollectOptions{
		Extras: map[string]any{"api-key": key},
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if got := credCount(res); got != 0 {
		t.Errorf("short-value skipped: got %d, want 0", got)
	}
}

// TestCollect_OpenWebUI_RetrievalRerankingRouteAbsent — the Collector must
// NOT probe /api/v1/retrieval/reranking. That endpoint does not exist
// on Open WebUI (verified via full route enumeration in retrieval.py).
// Reranking config lives inside /api/v1/retrieval/config.
func TestCollect_OpenWebUI_RetrievalRerankingRouteAbsent(t *testing.T) {
	var tracker sync.Map
	const key = "admin-jwt"
	srv := openwebuiStub(t, openwebuiStubOptions{
		apiKey:  key,
		tracker: &tracker,
	})
	defer srv.Close()

	l := &Collector{}
	_, err := l.Collect(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.CollectOptions{
		Extras: map[string]any{"api-key": key},
	})
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	if _, hit := tracker.Load("GET /api/v1/retrieval/reranking"); hit {
		t.Error("Collector probed /api/v1/retrieval/reranking; that endpoint does not exist on Open WebUI")
	}
}

// TestCanonicalizeBackendURL locks in effective HTTP-port identity.
func TestCanonicalizeBackendURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"http://ollama:11434", "http://ollama:11434"},
		{"https://ollama.example.com", "https://ollama.example.com"},
		{"https://ollama.example.com:443", "https://ollama.example.com:443"},
		{"ollama-backend:11434", "http://ollama-backend:11434"},
		{"ollama-backend", "http://ollama-backend:11434"},
		{"", ""},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := canonicalizeBackendURL(tt.input)
			if got != tt.want {
				t.Errorf("canonicalizeBackendURL(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestCanonicalizeBackendURLMatchesDirectOllamaIdentity(t *testing.T) {
	raw := "https://ollama.example.com:443"
	direct := action.EndpointBaseURL(
		action.Target{Kind: "url", Address: raw}, 11434, "http",
	)
	if configured := canonicalizeBackendURL(raw); configured != direct {
		t.Fatalf("configured identity %q differs from direct identity %q", configured, direct)
	}
}

func TestBackendInventoryRequiresResponseFields(t *testing.T) {
	freshResult := func() *action.CollectResult {
		return &action.CollectResult{IngestData: &ingest.IngestData{
			Graph: ingest.GraphData{Nodes: []ingest.Node{{
				ID: "openwebui", Properties: map[string]any{},
			}}},
		}}
	}
	tests := []struct {
		name                string
		ollamaConfig        string
		externalConnections string
	}{
		{name: "missing", ollamaConfig: `{}`, externalConnections: `{}`},
		{
			name:                "null",
			ollamaConfig:        `{"OLLAMA_BASE_URLS":null}`,
			externalConnections: `{"items":null,"total":0}`,
		},
		{
			name:                "wrong shape",
			ollamaConfig:        `{"OLLAMA_BASE_URLS":{}}`,
			externalConnections: `{"items":{},"total":0}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			srv := openwebuiStub(t, openwebuiStubOptions{
				ollamaConfig:        test.ollamaConfig,
				externalConnections: test.externalConnections,
			})
			defer srv.Close()

			_, ollama := runOllamaConfig(
				context.Background(), srv.Client(), freshResult(), action.CollectOptions{},
				"openwebui", srv.URL, "", 10, 10,
			)
			if ollama.State == ingest.OutcomeComplete {
				t.Fatal("invalid OLLAMA_BASE_URLS was accepted as complete inventory")
			}
			qdrant := runExternalKnowledgeConnections(
				context.Background(), srv.Client(), freshResult(), "openwebui", srv.URL, "", 10,
			)
			if qdrant.State == ingest.OutcomeComplete {
				t.Fatal("invalid items or total was accepted as complete inventory")
			}
		})
	}
}

func TestCanonicalizeQdrantBackendURLUsesEffectivePorts(t *testing.T) {
	tests := []struct {
		left, right string
		equal       bool
	}{
		{left: "qdrant", right: "qdrant:6333", equal: true},
		{left: "http://qdrant", right: "http://qdrant:80", equal: true},
		{left: "https://qdrant", right: "https://qdrant:443", equal: true},
		{left: "http://qdrant", right: "http://qdrant:6333", equal: false},
	}
	for _, tc := range tests {
		left := canonicalizeQdrantBackendURL(tc.left)
		right := canonicalizeQdrantBackendURL(tc.right)
		if (left == right) != tc.equal {
			t.Errorf("canonical endpoints %q and %q equality = %t, want %t", left, right, left == right, tc.equal)
		}
		leftID := ingest.ComputeNodeID("QdrantInstance", left)
		rightID := ingest.ComputeNodeID("QdrantInstance", right)
		if (leftID == rightID) != tc.equal {
			t.Errorf("Qdrant IDs for %q and %q equality = %t, want %t", tc.left, tc.right, leftID == rightID, tc.equal)
		}
	}
}

// credCount counts Credential nodes in a CollectResult.
func credCount(res *action.CollectResult) int {
	if res == nil || res.IngestData == nil {
		return 0
	}
	var n int
	for _, node := range res.IngestData.Graph.Nodes {
		if len(node.Kinds) > 0 && node.Kinds[0] == "Credential" {
			n++
		}
	}
	return n
}

// credNames returns the `name` property of every Credential node.
func credNames(res *action.CollectResult) []string {
	if res == nil || res.IngestData == nil {
		return nil
	}
	var out []string
	for _, node := range res.IngestData.Graph.Nodes {
		if len(node.Kinds) == 0 || node.Kinds[0] != "Credential" {
			continue
		}
		if name, ok := node.Properties["name"].(string); ok {
			out = append(out, name)
		}
	}
	return out
}

// Force json import (used by fixtures indirectly via httptest handlers).
var _ = json.RawMessage{}
