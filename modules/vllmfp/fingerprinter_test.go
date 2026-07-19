package vllmfp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/action"
)

const vllmVersionBody = `{"version":"0.10.1"}`

func TestFingerprint_VLLMHappy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/version" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(vllmVersionBody))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	f, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := f.Fingerprint(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	})
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if !res.Matched {
		t.Fatal("expected Matched=true")
	}
	if res.ServiceKind != "vllm" {
		t.Errorf("ServiceKind = %q, want vllm", res.ServiceKind)
	}
	if res.AuthMethod != "unknown" {
		t.Errorf("AuthMethod = %q, want unknown", res.AuthMethod)
	}
	if res.Version != "0.10.1" {
		t.Errorf("Version = %q, want 0.10.1", res.Version)
	}
	if res.IngestData == nil || len(res.IngestData.Graph.Nodes) != 1 {
		t.Fatalf("expected 1 ingest node, got %+v", res.IngestData)
	}
	node := res.IngestData.Graph.Nodes[0]
	if len(node.Kinds) != 2 || node.Kinds[0] != "VLLMInstance" || node.Kinds[1] != "AIService" {
		t.Errorf("node.Kinds = %v, want [VLLMInstance AIService]", node.Kinds)
	}
	if got := node.Properties["service_kind"]; got != "vllm" {
		t.Errorf("properties.service_kind = %v, want vllm", got)
	}
	if got := node.Properties["version"]; got != "0.10.1" {
		t.Errorf("properties.version = %v, want 0.10.1", got)
	}
	if _, fabricated := node.Properties["is_anonymous_loot"]; fabricated {
		t.Error("vLLM fingerprint must not claim anonymous lootability")
	}
	if !strings.HasPrefix(node.ID, "sha256:") {
		t.Errorf("node.ID = %q, want sha256: prefix", node.ID)
	}
}

func TestFingerprint_NotVLLM(t *testing.T) {
	// A generic OpenAI-compatible service without vLLM's version endpoint.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/models" {
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"arbitrary-alias"}]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer srv.Close()

	f, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := f.Fingerprint(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	})
	if err != nil {
		t.Fatalf("Fingerprint err = %v", err)
	}
	if res.Matched {
		t.Error("expected no match for a generic OpenAI-compatible service")
	}
}

func TestFingerprint_LiteLLMNearMiss(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/health/liveliness":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"healthy"}`))
		case "/v1/models":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"object":"list","data":[{"id":"agenthound-litellm-fixture"}]}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	f, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := f.Fingerprint(context.Background(), action.Target{Kind: "host", Address: strings.TrimPrefix(srv.URL, "http://")})
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if res.Matched {
		t.Fatal("LiteLLM-compatible OpenAI routes were misclassified as vLLM")
	}
}

func TestFingerprint_NetworkError(t *testing.T) {
	f, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	_, err = f.Fingerprint(context.Background(), action.Target{
		Kind:    "host",
		Address: "127.0.0.1:1",
	})
	if err == nil {
		t.Fatal("closed-port transport failure must be operationally indeterminate")
	}
}

func TestFingerprint_SchemeOverride(t *testing.T) {
	// Verify that Meta["scheme"] = "https" produces an https:// URL.
	// We use an HTTPS test server; the fingerprinter should connect via TLS.
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/version" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(vllmVersionBody))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	f, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// httptest.NewTLSServer uses a self-signed cert; the fingerprinter's
	// DefaultFingerprintHTTPClient blocks redirects but doesn't skip TLS
	// verification by default. We pass scheme=https and use the test
	// server's address; this exercises the scheme-override branch even
	// though the actual TLS handshake will fail (self-signed).
	addr := strings.TrimPrefix(srv.URL, "https://")
	_, err = f.Fingerprint(context.Background(), action.Target{
		Kind:    "host",
		Address: addr,
		Meta:    map[string]string{"scheme": "https"},
	})
	if err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("expected strict-TLS certificate failure, got %v", err)
	}
}
