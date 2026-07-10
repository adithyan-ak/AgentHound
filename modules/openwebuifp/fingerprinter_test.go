package openwebuifp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/action"
)

const owuiVersionBody = `{"version":"0.6.5"}`

// owuiConfigBody matches Open WebUI's real /api/config shape (verified
// across v0.1.111..v0.9.6 + main). {"name": "Open WebUI", ...} is
// stable across every tag; $.ollama.base_url was NEVER present and
// the fingerprint no longer captures it.
const owuiConfigBody = `{"name":"Open WebUI","status":true,"features":{"auth":false,"enable_signup":true}}`

// TestFingerprint_OpenWebUI_HappyPath — the v3 rule matches on
// /api/version + /api/config's {"name": "Open WebUI"} shape. Emits
// exactly 1 OpenWebUIInstance node, 0 edges (the old EXPOSES edge on
// $.ollama.base_url is gone — Ollama backend URLs are surfaced by the
// authenticated Looter via /ollama/config).
func TestFingerprint_OpenWebUI_HappyPath(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/version":
			_, _ = w.Write([]byte(owuiVersionBody))
		case "/api/config":
			_, _ = w.Write([]byte(owuiConfigBody))
		default:
			w.WriteHeader(404)
		}
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
	if res.ServiceKind != "openwebui" {
		t.Errorf("ServiceKind = %q, want openwebui", res.ServiceKind)
	}
	if res.IngestData == nil {
		t.Fatal("IngestData nil")
	}
	if len(res.IngestData.Graph.Nodes) != 1 {
		t.Fatalf("expected 1 node (OpenWebUIInstance only), got %d", len(res.IngestData.Graph.Nodes))
	}
	if len(res.IngestData.Graph.Edges) != 0 {
		t.Fatalf("expected 0 EXPOSES edges (dead capture removed in v3), got %d", len(res.IngestData.Graph.Edges))
	}
}

// TestFingerprint_OpenWebUI_ConfigMissingNameField — response with a
// different name field is not Open WebUI, so the conjunctive match
// fails on probe 2. The single-probe fallback on /api/version alone
// still fires because /api/version returned a valid version.
func TestFingerprint_OpenWebUI_ConfigMissingNameField(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/version":
			_, _ = w.Write([]byte(owuiVersionBody))
		case "/api/config":
			_, _ = w.Write([]byte(`{"name":"Something Else","status":true}`))
		default:
			w.WriteHeader(404)
		}
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
		t.Fatal("expected Matched=true via /api/version fallback")
	}
	if len(res.IngestData.Graph.Nodes) != 1 {
		t.Errorf("expected 1 node, got %d", len(res.IngestData.Graph.Nodes))
	}
	if len(res.IngestData.Graph.Edges) != 0 {
		t.Errorf("expected 0 edges, got %d", len(res.IngestData.Graph.Edges))
	}
}

func TestFingerprint_OpenWebUI_ConfigLockedFallback(t *testing.T) {
	// /api/config 401 — fingerprinter must still match on /api/version alone.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/version":
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(owuiVersionBody))
		case "/api/config":
			w.WriteHeader(401)
		default:
			w.WriteHeader(404)
		}
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
		t.Fatal("expected Matched=true even when /api/config is locked")
	}
	if len(res.IngestData.Graph.Edges) != 0 {
		t.Errorf("expected 0 EXPOSES edges when config locked, got %d", len(res.IngestData.Graph.Edges))
	}
}

func TestFingerprint_NotOpenWebUI(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		_, _ = w.Write([]byte(`{"object":"list","data":[]}`))
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
		t.Error("expected no match on non-OpenWebUI body")
	}
}
