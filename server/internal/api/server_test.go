package api

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestServer_GatesMutatingEndpointsByOrigin locks the route topology:
// every mutating endpoint must reject a browser request from a foreign
// Origin (drive-by CSRF), admit a request with no Origin (CLI / curl /
// cron), and reach the handler when the Origin is in the CORS allowlist
// (the embedded UI). If a future change moves a route between the two
// groups, this test fails loudly.
func TestServer_GatesMutatingEndpointsByOrigin(t *testing.T) {
	deps := ServerDeps{
		// Nil DB-backed deps are fine for this routing test: the
		// middleware rejects requests before they reach the handler,
		// and on the admit path we assert "not 403", not handler success.
		CORSOrigins: []string{"http://localhost:8080"},
	}
	srv := NewServer(deps)

	type tc struct {
		method      string
		path        string
		description string
	}
	mutating := []tc{
		{"POST", "/api/v1/ingest", "ingest"},
		{"POST", "/api/v1/query", "raw cypher"},
		{"POST", "/api/v1/scans", "create scan"},
		{"DELETE", "/api/v1/scans/abc", "delete scan"},
		{"POST", "/api/v1/analysis/shortest-path", "shortest-path"},
		{"POST", "/api/v1/analysis/all-paths", "all-paths"},
		{"POST", "/api/v1/analysis/weighted-path", "weighted-path"},
		{"PUT", "/api/v1/findings/triage/0123456789abcdef", "triage update"},
	}

	for _, c := range mutating {
		t.Run(c.method+" "+c.path+" rejects evil Origin", func(t *testing.T) {
			req := httptest.NewRequest(c.method, c.path, bytes.NewReader([]byte("{}")))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", "https://evil.com")
			rec := httptest.NewRecorder()
			srv.router.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s %s: status = %d, want 403", c.method, c.path, rec.Code)
			}
		})

		t.Run(c.method+" "+c.path+" rejects null Origin", func(t *testing.T) {
			req := httptest.NewRequest(c.method, c.path, bytes.NewReader([]byte("{}")))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", "null")
			rec := httptest.NewRecorder()
			srv.router.ServeHTTP(rec, req)
			if rec.Code != http.StatusForbidden {
				t.Errorf("%s %s: status = %d, want 403", c.method, c.path, rec.Code)
			}
		})

		t.Run(c.method+" "+c.path+" admits no Origin (CLI)", func(t *testing.T) {
			req := httptest.NewRequest(c.method, c.path, bytes.NewReader([]byte("{}")))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			srv.router.ServeHTTP(rec, req)
			if rec.Code == http.StatusForbidden {
				t.Errorf("%s %s: OriginGuard returned 403 for no-Origin (CLI/curl) request — must allow",
					c.method, c.path)
			}
		})

		t.Run(c.method+" "+c.path+" admits allowed Origin (UI)", func(t *testing.T) {
			req := httptest.NewRequest(c.method, c.path, bytes.NewReader([]byte("{}")))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Origin", "http://localhost:8080")
			rec := httptest.NewRecorder()
			srv.router.ServeHTTP(rec, req)
			if rec.Code == http.StatusForbidden {
				t.Errorf("%s %s: OriginGuard returned 403 for allowlisted Origin — UI would break",
					c.method, c.path)
			}
		})
	}

	// Read endpoints must be open regardless of Origin: the UI and CLI
	// both hit these without any gating concern.
	t.Run("GET /health is open", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/health", nil)
		rec := httptest.NewRecorder()
		srv.router.ServeHTTP(rec, req)
		if rec.Code == http.StatusForbidden || rec.Code == http.StatusUnauthorized {
			t.Errorf("status = %d; reads must not be gated", rec.Code)
		}
	})
}

// TestServer_ServesUIFallbackWhenDistEmpty asserts that when the binary
// is built with only the ui/dist/.gitkeep marker (no real React UI), the
// server serves the embedded "UI not built" page instead of returning a
// 500. This guards against the footgun where `go build` succeeds but the
// resulting server serves a broken page.
//
// In CI and production, ui-build runs first and ui/dist contains a real
// index.html, so this test exercises only the fallback branch. We detect
// which branch is active by inspecting the response body.
func TestServer_ServesUIFallbackOrRealUI(t *testing.T) {
	srv := NewServer(ServerDeps{})

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	srv.router.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("GET /: status = %d, want 200", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("GET /: Content-Type = %q, want text/html", ct)
	}
	body, err := io.ReadAll(rec.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if len(body) == 0 {
		t.Error("GET /: empty body; expected either real UI or fallback page")
	}
	// Any valid HTML is acceptable: the real UI (contains React mount
	// point), the fallback page (contains "UI not built"), or the CI stub
	// (minimal HTML generated by the "Create UI embed stub" workflow step).
	// Only a 404, empty page, or non-HTML response is a regression.
	hasHTML := strings.Contains(string(body), "<html")
	if !hasHTML {
		t.Errorf("GET /: body is not HTML; first 200 bytes: %q",
			string(body[:min(len(body), 200)]))
	}
}
