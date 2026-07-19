package ollamafp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/action"
)

// TestFingerprint_OllamaHappy verifies the end-to-end happy path — a
// stub HTTP server returns the canonical Ollama version JSON, and the
// fingerprinter emits the multi-label node with version captured.
func TestFingerprint_OllamaHappy(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" && r.URL.Path == "/api/version" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"version":"0.5.1"}`))
			return
		}
		if r.Method == "GET" && r.URL.Path == "/api/tags" {
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"models":[]}`))
			return
		}
		w.WriteHeader(404)
	}))
	defer srv.Close()

	f, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	addr := strings.TrimPrefix(srv.URL, "http://")
	res, err := f.Fingerprint(context.Background(), action.Target{
		Kind:    "host",
		Address: addr, // host:port
	})
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if !res.Matched {
		t.Fatal("expected Matched=true")
	}
	if res.ServiceKind != "ollama" {
		t.Errorf("ServiceKind = %q, want ollama", res.ServiceKind)
	}
	if res.Version != "0.5.1" {
		t.Errorf("Version = %q, want 0.5.1", res.Version)
	}
	if res.AuthMethod != "none" {
		t.Errorf("AuthMethod = %q, want none", res.AuthMethod)
	}
	if res.IngestData == nil || len(res.IngestData.Graph.Nodes) != 1 {
		t.Fatalf("expected 1 ingest node, got %+v", res.IngestData)
	}
	node := res.IngestData.Graph.Nodes[0]
	if len(node.Kinds) != 2 || node.Kinds[0] != "OllamaInstance" || node.Kinds[1] != "AIService" {
		t.Errorf("node.Kinds = %v, want [OllamaInstance AIService]", node.Kinds)
	}
	if got := node.Properties["version"]; got != "0.5.1" {
		t.Errorf("properties.version = %v, want 0.5.1", got)
	}
	if got := node.Properties["service_kind"]; got != "ollama" {
		t.Errorf("properties.service_kind = %v, want ollama", got)
	}
	if got := node.Properties["discovered_via"]; got != "network_scan" {
		t.Errorf("properties.discovered_via = %v, want network_scan", got)
	}
	if !strings.HasPrefix(node.ID, "sha256:") {
		t.Errorf("node.ID = %q, want sha256: prefix", node.ID)
	}
}

func TestFingerprint_NotOllama(t *testing.T) {
	// Server returns an empty 200 — no version JSON.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{}`))
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
		t.Error("expected no match")
	}
}

func TestFingerprint_OpenWebUINearMiss(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/version":
			_, _ = w.Write([]byte(`{"version":"0.6.5"}`))
		case "/api/tags":
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(`<!doctype html><title>Open WebUI</title>`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	f, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	res, err := f.Fingerprint(context.Background(), action.Target{
		Kind: "host", Address: strings.TrimPrefix(srv.URL, "http://"),
	})
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if res.Matched {
		t.Fatal("Open WebUI's generic version endpoint must not identify it as Ollama")
	}
}

func TestFingerprint_NetworkError(t *testing.T) {
	f, err := New()
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// Use a port that's surely closed on loopback.
	_, err = f.Fingerprint(context.Background(), action.Target{
		Kind:    "host",
		Address: "127.0.0.1:1",
	})
	if err == nil {
		t.Fatal("closed-port transport failure must be operationally indeterminate")
	}
}

func TestSplitHostPort(t *testing.T) {
	tests := []struct {
		input    string
		wantHost string
		wantPort int
	}{
		{"10.0.0.5:11434", "10.0.0.5", 11434},
		{"10.0.0.5", "10.0.0.5", 11434},
		{"localhost:8080", "localhost", 8080},
		{"localhost", "localhost", 11434},
		{"http://10.0.0.5:11434/api", "10.0.0.5", 11434},
		{"[::1]:11434", "::1", 11434},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			h, p := splitHostPort(tt.input, 11434)
			if h != tt.wantHost || p != tt.wantPort {
				t.Errorf("got (%q, %d), want (%q, %d)", h, p, tt.wantHost, tt.wantPort)
			}
		})
	}
}
