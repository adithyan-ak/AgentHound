package openwebuiloot

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/common"
)

const configBody = `{"status":true,"name":"Open WebUI","version":"0.6.32","features":{"auth":false,"enable_signup":true},"ollama":{"base_url":"http://10.0.0.5:11434"}}`

// openaiConfigBody mirrors the assumed GET /openai/config shape: parallel
// OPENAI_API_KEYS / OPENAI_API_BASE_URLS arrays. The Ollama upstream at
// index 1 has an empty key and must be skipped.
const openaiConfigBody = `{"ENABLE_OPENAI_API":true,"OPENAI_API_BASE_URLS":["https://api.openai.com/v1","http://10.0.0.5:11434/v1"],"OPENAI_API_KEYS":["sk-proj-secret-abc123",""]}`

func openwebuiStub(t *testing.T, apiKey string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/config" && r.Method == "GET":
			_, _ = w.Write([]byte(configBody))
		case r.URL.Path == "/openai/config" && r.Method == "GET":
			if apiKey != "" && r.Header.Get("Authorization") != "Bearer "+apiKey {
				w.WriteHeader(401)
				return
			}
			_, _ = w.Write([]byte(openaiConfigBody))
		default:
			w.WriteHeader(404)
		}
	}))
}

func TestLoot_OpenWebUI_AnonymousPosture(t *testing.T) {
	srv := openwebuiStub(t, "")
	defer srv.Close()

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.LootOptions{})
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	// Anonymous mode: just the OpenWebUIInstance node, no credentials.
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
	// /api/config reported auth:false → wide open → auth_required false.
	if ar, ok := node.Properties["auth_required"].(bool); !ok || ar {
		t.Errorf("auth_required = %v, want false", node.Properties["auth_required"])
	}
	if bu, _ := node.Properties["ollama_backend_url"].(string); bu != "http://10.0.0.5:11434" {
		t.Errorf("ollama_backend_url = %q, want http://10.0.0.5:11434", bu)
	}
	if res.Summary.CredentialsFound != 0 {
		t.Errorf("CredentialsFound = %d, want 0 in anonymous mode", res.Summary.CredentialsFound)
	}
	// No EXPOSES_CREDENTIAL edges in anonymous mode (fingerprinter owns the
	// EXPOSES->Ollama edge; the looter must not duplicate it).
	if got := len(res.IngestData.Graph.Edges); got != 0 {
		t.Errorf("edges: got %d, want 0 in anonymous mode", got)
	}
}

func TestLoot_OpenWebUI_AuthenticatedCredentials(t *testing.T) {
	const key = "sk-operator-admin-token"
	srv := openwebuiStub(t, key)
	defer srv.Close()

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	}, action.LootOptions{
		Extras: map[string]any{"api-key": key},
	})
	if err != nil {
		t.Fatalf("Loot: %v", err)
	}
	// 1 OpenWebUIInstance + 1 Credential (the empty-key Ollama upstream is
	// skipped).
	if got := len(res.IngestData.Graph.Nodes); got != 2 {
		t.Fatalf("nodes: got %d, want 2 (instance + 1 credential)", got)
	}
	var cred *struct {
		valueHash string
		hasValue  bool
	}
	for _, n := range res.IngestData.Graph.Nodes {
		if n.Kinds[0] != "Credential" {
			continue
		}
		vh, _ := n.Properties["value_hash"].(string)
		_, hasVal := n.Properties["value"]
		cred = &struct {
			valueHash string
			hasValue  bool
		}{valueHash: vh, hasValue: hasVal}
	}
	if cred == nil {
		t.Fatal("no Credential node emitted")
	}
	wantHash := common.HashCredentialValue("sk-proj-secret-abc123")
	if cred.valueHash != wantHash {
		t.Errorf("value_hash = %q, want %q", cred.valueHash, wantHash)
	}
	// Raw value gated behind IncludeCredentialValues — must be absent here.
	if cred.hasValue {
		t.Errorf("raw value present without IncludeCredentialValues")
	}
	if res.Summary.CredentialsFound != 1 {
		t.Errorf("CredentialsFound = %d, want 1", res.Summary.CredentialsFound)
	}
	// One EXPOSES_CREDENTIAL edge anchored on the instance.
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
	srv := openwebuiStub(t, key)
	defer srv.Close()

	l := &Looter{}
	res, err := l.Loot(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
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

// Closed/unreachable config endpoint (non-200) must not error — the
// instance node is still emitted and the failure recorded. Authenticated
// path is not attempted (no key), so no credentials.
func TestLoot_OpenWebUI_ConfigFails(t *testing.T) {
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

// When the operator supplies a key but /openai/config rejects it (e.g.
// non-admin key → 401), the anonymous posture must still land and the
// credential probe records a partial failure rather than aborting.
func TestLoot_OpenWebUI_AuthRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/config":
			_, _ = w.Write([]byte(configBody))
		case "/openai/config":
			w.WriteHeader(401)
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
		Extras: map[string]any{"api-key": "sk-nonadmin"},
	})
	if err != nil {
		t.Fatalf("Loot should not error on partial failures: %v", err)
	}
	if se, _ := res.IngestData.Graph.Nodes[0].Properties["signup_enabled"].(bool); !se {
		t.Errorf("anonymous posture must land even when auth probe fails")
	}
	if res.Summary.CredentialsFound != 0 {
		t.Errorf("CredentialsFound = %d, want 0 when auth rejected", res.Summary.CredentialsFound)
	}
	if res.Summary.PartialFailures != 1 {
		t.Errorf("PartialFailures = %d, want 1", res.Summary.PartialFailures)
	}
}
