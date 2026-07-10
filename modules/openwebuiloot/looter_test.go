package openwebuiloot

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/common"
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
	apiKey             string
	config             string
	openaiConfig       string
	ollamaConfig       string
	retrievalConfig    string
	retrievalEmbedding string
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
		case "/api/config":
			body := opts.config
			if body == "" {
				body = configBody
			}
			_, _ = w.Write([]byte(body))
		case "/openai/config":
			if opts.openaiConfig == "" {
				w.WriteHeader(404)
				return
			}
			_, _ = w.Write([]byte(opts.openaiConfig))
		case "/ollama/config":
			if opts.ollamaConfig == "" {
				w.WriteHeader(404)
				return
			}
			_, _ = w.Write([]byte(opts.ollamaConfig))
		case "/api/v1/retrieval/config":
			if opts.retrievalConfig == "" {
				w.WriteHeader(404)
				return
			}
			_, _ = w.Write([]byte(opts.retrievalConfig))
		case "/api/v1/retrieval/embedding":
			if opts.retrievalEmbedding == "" {
				w.WriteHeader(404)
				return
			}
			_, _ = w.Write([]byte(opts.retrievalEmbedding))
		default:
			w.WriteHeader(404)
		}
	}))
}

func addrOf(srv *httptest.Server) string {
	return strings.TrimPrefix(srv.URL, "http://")
}

// TestLoot_OpenWebUI_AnonymousPosture — no api-key supplied, only the
// posture props land. Instance node carries signup_enabled +
// auth_required; no ollama_backend_url (that lived in the dead
// $.ollama.base_url capture, now removed in v3).
func TestLoot_OpenWebUI_AnonymousPosture(t *testing.T) {
	srv := openwebuiStub(t, openwebuiStubOptions{})
	defer srv.Close()

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.LootOptions{})
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	if got := len(res.IngestData.Graph.Nodes); got != 1 {
		t.Fatalf("nodes: got %d, want 1 (OpenWebUIInstance)", got)
	}
	node := res.IngestData.Graph.Nodes[0]
	if node.Kinds[0] != "OpenWebUIInstance" {
		t.Errorf("kind = %v, want OpenWebUIInstance", node.Kinds)
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
	if _, ok := node.Properties["ollama_backend_url"]; ok {
		t.Errorf("ollama_backend_url should not be set in anonymous mode (moved to /ollama/config)")
	}
	if res.Summary.CredentialsFound != 0 {
		t.Errorf("CredentialsFound = %d, want 0 in anonymous mode", res.Summary.CredentialsFound)
	}
	if got := len(res.IngestData.Graph.Edges); got != 0 {
		t.Errorf("edges: got %d, want 0 in anonymous mode", got)
	}
}

// TestLoot_OpenWebUI_AuthenticatedCredentials — /openai/config path
// still works end-to-end, emitting 1 Credential and 1 EXPOSES_CREDENTIAL
// edge for the non-empty key.
func TestLoot_OpenWebUI_AuthenticatedCredentials(t *testing.T) {
	const key = "sk-operator-admin-token"
	srv := openwebuiStub(t, openwebuiStubOptions{
		apiKey:       key,
		openaiConfig: openaiConfigBody,
	})
	defer srv.Close()

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.LootOptions{
		Extras: map[string]any{"api-key": key},
	})
	if err != nil {
		t.Fatalf("Loot: %v", err)
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
	if cred.hasValue {
		t.Errorf("raw value present without IncludeCredentialValues")
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

func TestLoot_OpenWebUI_RawValueGated(t *testing.T) {
	const key = "sk-operator-admin-token"
	srv := openwebuiStub(t, openwebuiStubOptions{
		apiKey:       key,
		openaiConfig: openaiConfigBody,
	})
	defer srv.Close()

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.LootOptions{
		Extras:                  map[string]any{"api-key": key},
		IncludeCredentialValues: true,
	})
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	var found bool
	for _, n := range res.IngestData.Graph.Nodes {
		if n.Kinds[0] != "Credential" {
			continue
		}
		found = true
		if v, _ := n.Properties["value"].(string); v != "sk-proj-secret-abc123" {
			t.Errorf("value = %q, want raw key when IncludeCredentialValues=true", v)
		}
		if _, ok := n.Properties["value_hash"]; !ok {
			t.Errorf("value_hash must remain populated even with raw value")
		}
	}
	if !found {
		t.Fatal("no Credential node emitted")
	}
}

// TestLoot_OpenWebUI_ConfigFails — non-2xx on /api/config is a partial
// failure, not a fatal error. Instance node still emitted.
func TestLoot_OpenWebUI_ConfigFails(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer srv.Close()

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.LootOptions{})
	if err != nil {
		t.Fatalf("Loot should not error on partial failures: %v", err)
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

// TestLoot_OpenWebUI_AuthRejected — /openai/config returns 401 (e.g.
// non-admin key). Anonymous posture still lands and the credential
// probe records a partial failure.
func TestLoot_OpenWebUI_AuthRejected(t *testing.T) {
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

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.LootOptions{
		Extras: map[string]any{"api-key": "sk-nonadmin"},
	})
	if err != nil {
		t.Fatalf("Loot should not error on partial failures: %v", err)
	}
	if se, _ := res.IngestData.Graph.Nodes[0].Properties["signup_enabled"].(bool); !se {
		t.Errorf("anonymous posture must land even when auth probes fail")
	}
	if res.Summary.CredentialsFound != 0 {
		t.Errorf("CredentialsFound = %d, want 0 when auth rejected", res.Summary.CredentialsFound)
	}
	// Four authenticated probes all 401 → 4 partial failures.
	if res.Summary.PartialFailures < 1 {
		t.Errorf("PartialFailures = %d, want at least 1", res.Summary.PartialFailures)
	}
}

// TestLoot_OpenWebUI_OllamaConfig_KeyField — the primary shape:
// OLLAMA_API_CONFIGS keyed by string index, per-URL config uses `key`.
// Asserts 1 Credential + 1 :OllamaInstance placeholder + 1 :EXPOSES
// edge + canonicalized ollama_backend_url property.
func TestLoot_OpenWebUI_OllamaConfig_KeyField(t *testing.T) {
	const key = "admin-jwt"
	srv := openwebuiStub(t, openwebuiStubOptions{
		apiKey:       key,
		ollamaConfig: `{"ENABLE_OLLAMA_API":true,"OLLAMA_BASE_URLS":["http://10.0.0.5:11434"],"OLLAMA_API_CONFIGS":{"0":{"key":"sk-ollama-idx","enable":true}}}`,
	})
	defer srv.Close()

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.LootOptions{
		Extras: map[string]any{"api-key": key},
	})
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	var credCount, ollamaCount, exposesCount int
	for _, n := range res.IngestData.Graph.Nodes {
		switch n.Kinds[0] {
		case "Credential":
			credCount++
			if vh, _ := n.Properties["value_hash"].(string); vh != common.HashCredentialValue("sk-ollama-idx") {
				t.Errorf("value_hash mismatch: %v", vh)
			}
		case "OllamaInstance":
			ollamaCount++
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
			exposesCount++
			if e.SourceKind != "OpenWebUIInstance" || e.TargetKind != "OllamaInstance" {
				t.Errorf("EXPOSES edge kinds = %s -> %s", e.SourceKind, e.TargetKind)
			}
		}
	}
	if exposesCount != 1 {
		t.Errorf("EXPOSES edge count = %d, want 1", exposesCount)
	}
	if bu, _ := res.IngestData.Graph.Nodes[0].Properties["ollama_backend_url"].(string); bu != "http://10.0.0.5:11434" {
		t.Errorf("ollama_backend_url = %q, want http://10.0.0.5:11434", bu)
	}
}

// TestLoot_OpenWebUI_OllamaConfig_URLKeyed — same result via URL-keyed
// OLLAMA_API_CONFIGS lookup (the second fallback path in Open WebUI's
// get_api_key).
func TestLoot_OpenWebUI_OllamaConfig_URLKeyed(t *testing.T) {
	const key = "admin-jwt"
	srv := openwebuiStub(t, openwebuiStubOptions{
		apiKey:       key,
		ollamaConfig: `{"OLLAMA_BASE_URLS":["http://10.0.0.5:11434"],"OLLAMA_API_CONFIGS":{"http://10.0.0.5:11434":{"key":"sk-ollama-url"}}}`,
	})
	defer srv.Close()

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.LootOptions{
		Extras: map[string]any{"api-key": key},
	})
	if err != nil {
		t.Fatalf("Loot: %v", err)
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

// TestLoot_OpenWebUI_OllamaConfig_LegacyAPIKey — decoding falls back
// to `api_key` when `key` is absent (older/forked Open WebUI).
func TestLoot_OpenWebUI_OllamaConfig_LegacyAPIKey(t *testing.T) {
	const key = "admin-jwt"
	srv := openwebuiStub(t, openwebuiStubOptions{
		apiKey:       key,
		ollamaConfig: `{"OLLAMA_BASE_URLS":["http://10.0.0.5:11434"],"OLLAMA_API_CONFIGS":{"0":{"api_key":"sk-legacy-abc"}}}`,
	})
	defer srv.Close()

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.LootOptions{
		Extras: map[string]any{"api-key": key},
	})
	if err != nil {
		t.Fatalf("Loot: %v", err)
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

// TestLoot_OpenWebUI_RetrievalConfig_FlatKey — three flat UPPER_SNAKE
// fields matching different positive suffixes.
func TestLoot_OpenWebUI_RetrievalConfig_FlatKey(t *testing.T) {
	const key = "admin-jwt"
	srv := openwebuiStub(t, openwebuiStubOptions{
		apiKey:          key,
		retrievalConfig: `{"RAG_EXTERNAL_RERANKER_API_KEY":"sk-rerank-long-secret","PADDLEOCR_VL_TOKEN":"tok-abc-1234567","YACY_PASSWORD":"pw-secret-yacy-1"}`,
	})
	defer srv.Close()

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.LootOptions{
		Extras: map[string]any{"api-key": key},
	})
	if err != nil {
		t.Fatalf("Loot: %v", err)
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

// TestLoot_OpenWebUI_RetrievalConfig_SubscriptionKey — SUBSCRIPTION
// suffix must match (BING_SEARCH_V7_SUBSCRIPTION_KEY at retrieval.py:711).
func TestLoot_OpenWebUI_RetrievalConfig_SubscriptionKey(t *testing.T) {
	const key = "admin-jwt"
	srv := openwebuiStub(t, openwebuiStubOptions{
		apiKey:          key,
		retrievalConfig: `{"BING_SEARCH_V7_SUBSCRIPTION_KEY":"sub-abc-1234567"}`,
	})
	defer srv.Close()

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.LootOptions{
		Extras: map[string]any{"api-key": key},
	})
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	if got := credCount(res); got != 1 {
		t.Errorf("SUBSCRIPTION_KEY captured: got %d, want 1", got)
	}
}

// TestLoot_OpenWebUI_RetrievalConfig_SkSuffix — _SK trailing shorthand
// (SOUGOU_API_SK at retrieval.py:721).
func TestLoot_OpenWebUI_RetrievalConfig_SkSuffix(t *testing.T) {
	const key = "admin-jwt"
	srv := openwebuiStub(t, openwebuiStubOptions{
		apiKey:          key,
		retrievalConfig: `{"SOUGOU_API_SK":"sk-sougou-longish-secret"}`,
	})
	defer srv.Close()

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.LootOptions{
		Extras: map[string]any{"api-key": key},
	})
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	if got := credCount(res); got != 1 {
		t.Errorf("_SK suffix captured: got %d, want 1", got)
	}
}

// TestLoot_OpenWebUI_RetrievalEmbedding_Nested — recursion must descend
// into openai_config.key / ollama_config.key / azure_openai_config.key
// (retrieval.py:445-457).
func TestLoot_OpenWebUI_RetrievalEmbedding_Nested(t *testing.T) {
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

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.LootOptions{
		Extras: map[string]any{"api-key": key},
	})
	if err != nil {
		t.Fatalf("Loot: %v", err)
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

// TestLoot_OpenWebUI_Walker_NegativeFilters — MODEL/ENGINE/LANGUAGE
// suffixes must NOT trigger the walker even when they include
// TOKEN/KEY substrings.
func TestLoot_OpenWebUI_Walker_NegativeFilters(t *testing.T) {
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

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.LootOptions{
		Extras: map[string]any{"api-key": key},
	})
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	if got := credCount(res); got != 0 {
		t.Errorf("negative-filter walker captures: got %d, want 0 (%v)", got, credNames(res))
	}
}

// TestLoot_OpenWebUI_Walker_ShortValueSkipped — values shorter than 8
// chars are treated as noise (real secrets are always longer).
func TestLoot_OpenWebUI_Walker_ShortValueSkipped(t *testing.T) {
	const key = "admin-jwt"
	srv := openwebuiStub(t, openwebuiStubOptions{
		apiKey:          key,
		retrievalConfig: `{"TEST_API_KEY":"abc"}`,
	})
	defer srv.Close()

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.LootOptions{
		Extras: map[string]any{"api-key": key},
	})
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	if got := credCount(res); got != 0 {
		t.Errorf("short-value skipped: got %d, want 0", got)
	}
}

// TestLoot_OpenWebUI_RetrievalRerankingRouteAbsent — the Looter must
// NOT probe /api/v1/retrieval/reranking. That endpoint does not exist
// on Open WebUI (verified via full route enumeration in retrieval.py).
// Reranking config lives inside /api/v1/retrieval/config.
func TestLoot_OpenWebUI_RetrievalRerankingRouteAbsent(t *testing.T) {
	var tracker sync.Map
	const key = "admin-jwt"
	srv := openwebuiStub(t, openwebuiStubOptions{
		apiKey:  key,
		tracker: &tracker,
	})
	defer srv.Close()

	l := &Looter{}
	_, err := l.Loot(context.Background(), action.Target{
		Kind: "host", Address: addrOf(srv),
	}, action.LootOptions{
		Extras: map[string]any{"api-key": key},
	})
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	if _, hit := tracker.Load("GET /api/v1/retrieval/reranking"); hit {
		t.Error("Looter probed /api/v1/retrieval/reranking; that endpoint does not exist on Open WebUI")
	}
}

// TestCanonicalizeBackendURL exercises the URL normalizer that used to
// live in openwebuifp. Ported verbatim from the fingerprinter test.
func TestCanonicalizeBackendURL(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"http://ollama:11434", "http://ollama:11434"},
		{"https://ollama.example.com", "https://ollama.example.com:11434"},
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

// credCount counts Credential nodes in a LootResult.
func credCount(res *action.LootResult) int {
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
func credNames(res *action.LootResult) []string {
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
