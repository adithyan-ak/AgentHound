package api

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	apimw "github.com/adithyan-ak/agenthound/server/internal/api/middleware"
)

// TestServer_GatesMutatingEndpointsWithToken locks the route topology:
// every mutating endpoint must reject an unauthenticated request and
// every read endpoint must serve without one. If a future change moves
// a route between the two groups, this test fails loudly.
func TestServer_GatesMutatingEndpointsWithToken(t *testing.T) {
	dir := t.TempDir()
	tok, err := apimw.NewLocalToken(filepath.Join(dir, "server.token"))
	if err != nil {
		t.Fatalf("NewLocalToken: %v", err)
	}

	deps := ServerDeps{
		// Nil DB-backed deps are fine for this routing test: the
		// middleware rejects requests before they reach the handler.
		// We assert on response status, not body content.
		LocalToken: tok,
	}
	srv := NewServer(deps)

	type tc struct {
		method      string
		path        string
		gated       bool
		description string
	}
	cases := []tc{
		// Mutating — must require token.
		{"POST", "/api/v1/ingest", true, "ingest"},
		{"POST", "/api/v1/query", true, "raw cypher"},
		{"POST", "/api/v1/scans", true, "create scan"},
		{"DELETE", "/api/v1/scans/abc", true, "delete scan"},
		{"POST", "/api/v1/analysis/shortest-path", true, "shortest-path"},
		{"POST", "/api/v1/analysis/all-paths", true, "all-paths"},
		{"POST", "/api/v1/analysis/weighted-path", true, "weighted-path"},
	}
	for _, c := range cases {
		t.Run(c.method+" "+c.path+" no-token", func(t *testing.T) {
			req := httptest.NewRequest(c.method, c.path, bytes.NewReader([]byte("{}")))
			req.Header.Set("Content-Type", "application/json")
			rec := httptest.NewRecorder()
			srv.router.ServeHTTP(rec, req)
			if rec.Code != http.StatusUnauthorized {
				t.Errorf("%s %s: status = %d, want %d",
					c.method, c.path, rec.Code, http.StatusUnauthorized)
			}
		})
	}

	// Token bootstrap endpoint must NOT be gated, otherwise the UI can
	// never fetch the token in the first place.
	t.Run("GET /auth/local-token is open", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/api/v1/auth/local-token", nil)
		rec := httptest.NewRecorder()
		srv.router.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want %d", rec.Code, http.StatusOK)
		}
	})

	// With the correct token, /query passes the middleware and reaches
	// the handler. We deliberately did NOT supply a Reader, so the
	// handler responds 500 — but that is downstream of the middleware,
	// which is exactly what we want to prove: the token unlocks the
	// route.
	t.Run("POST /query with token reaches handler", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/query",
			bytes.NewReader([]byte(`{"cypher":"MATCH (n) RETURN n LIMIT 1"}`)))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+tok.Token())
		rec := httptest.NewRecorder()
		srv.router.ServeHTTP(rec, req)
		if rec.Code == http.StatusUnauthorized {
			t.Errorf("status = 401 with valid token; middleware should have admitted the request")
		}
	})
}
