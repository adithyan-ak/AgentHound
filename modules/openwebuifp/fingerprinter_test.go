package openwebuifp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/sdk/action"
	"github.com/adithyan-ak/agenthound/sdk/common"
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
	props := res.IngestData.Graph.Nodes[0].Properties
	if got := props["version"]; got != "0.6.5" {
		t.Errorf("version = %v, want 0.6.5", got)
	}
	for _, key := range []string{"auth_method", "auth_assurance", "auth_evidence", "is_anonymous_loot"} {
		if _, exists := props[key]; exists {
			t.Errorf("public identity probe emitted %s: %+v", key, props)
		}
	}
}

// TestFingerprint_OpenWebUI_PublicIdentityDoesNotImplyAnonymousAccess covers
// the production posture where WEBUI_AUTH=true still leaves the identity
// endpoints public while privileged endpoints reject anonymous callers.
func TestFingerprint_OpenWebUI_PublicIdentityDoesNotImplyAnonymousAccess(t *testing.T) {
	protectedRequests := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/version":
			_, _ = w.Write([]byte(owuiVersionBody))
		case "/api/config":
			_, _ = w.Write([]byte(`{"name":"Open WebUI","status":true,"features":{"auth":true,"enable_signup":false}}`))
		case "/ollama/config":
			protectedRequests++
			w.WriteHeader(http.StatusUnauthorized)
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
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	})
	if err != nil {
		t.Fatalf("Fingerprint: %v", err)
	}
	if !res.Matched {
		t.Fatal("expected public Open WebUI identity probes to match")
	}
	props := res.IngestData.Graph.Nodes[0].Properties
	if got := props["version"]; got != "0.6.5" {
		t.Errorf("version = %v, want 0.6.5", got)
	}
	for _, key := range []string{"auth_method", "auth_assurance", "auth_evidence", "is_anonymous_loot"} {
		if _, exists := props[key]; exists {
			t.Errorf("public identity probe emitted %s: %+v", key, props)
		}
	}
	if res.AuthMethod != string(common.AuthUnknown) {
		t.Errorf("AuthMethod = %q, want unknown", res.AuthMethod)
	}
	if protectedRequests != 0 {
		t.Errorf("fingerprinter unexpectedly probed protected endpoint %d times", protectedRequests)
	}
	protected, err := http.Get(srv.URL + "/ollama/config")
	if err != nil {
		t.Fatalf("GET protected endpoint: %v", err)
	}
	defer protected.Body.Close()
	if protected.StatusCode != http.StatusUnauthorized {
		t.Errorf("protected endpoint status = %d, want %d", protected.StatusCode, http.StatusUnauthorized)
	}
}

// TestFingerprint_OpenWebUI_ConfigMissingNameField — /api/version is not
// implementation-specific (Ollama exposes the same shape), so both canonical
// probes are required.
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
	if res.Matched {
		t.Fatal("generic /api/version response must not bypass the Open WebUI shape guard")
	}
}

func TestFingerprint_OpenWebUI_ConfigLockedFallback(t *testing.T) {
	// A locked required probe is not a definitive mismatch. The dispatcher must
	// retain prior observations rather than reconciling the service away.
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
	_, err = f.Fingerprint(context.Background(), action.Target{
		Kind:    "host",
		Address: strings.TrimPrefix(srv.URL, "http://"),
	})
	if err == nil {
		t.Fatal("authentication challenge must be operationally indeterminate")
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
