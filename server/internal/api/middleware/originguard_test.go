package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// allowedOrigins is the default allowlist for these tests — mirrors the
// production default (localhost:8080 and 127.0.0.1:8080 both shipped).
var allowedOrigins = []string{"http://localhost:8080", "http://127.0.0.1:8080"}

func newGuardedHandler() http.Handler {
	return OriginGuard(allowedOrigins)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent) // distinguishable from 403
	}))
}

func TestOriginGuard_AllowsMissingOrigin(t *testing.T) {
	// curl from cron / CI / agenthound CLI — no Origin header at all.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", strings.NewReader("{}"))
	rec := httptest.NewRecorder()
	newGuardedHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("missing Origin: status = %d, want 204 (admitted as non-browser)", rec.Code)
	}
}

func TestOriginGuard_AllowsEmptyOrigin(t *testing.T) {
	// Some proxies blank the header rather than remove it. Treat as missing.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", strings.NewReader("{}"))
	req.Header.Set("Origin", "")
	rec := httptest.NewRecorder()
	newGuardedHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("empty Origin: status = %d, want 204", rec.Code)
	}
}

func TestOriginGuard_AllowsConfiguredOrigin(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", strings.NewReader("{}"))
	req.Header.Set("Origin", "http://localhost:8080")
	rec := httptest.NewRecorder()
	newGuardedHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("allowed Origin: status = %d, want 204", rec.Code)
	}
}

func TestOriginGuard_AllowsLoopbackIPVariant(t *testing.T) {
	// http://127.0.0.1:8080 is a distinct origin from http://localhost:8080
	// (RFC 6454 §4). Both ship by default so the operator can use either URL.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", strings.NewReader("{}"))
	req.Header.Set("Origin", "http://127.0.0.1:8080")
	rec := httptest.NewRecorder()
	newGuardedHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Errorf("127.0.0.1 Origin: status = %d, want 204", rec.Code)
	}
}

func TestOriginGuard_RejectsEvilOrigin(t *testing.T) {
	// Drive-by CSRF: tab on evil.com auto-submits a form to the local server.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", strings.NewReader("{}"))
	req.Header.Set("Origin", "https://evil.com")
	rec := httptest.NewRecorder()
	newGuardedHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("evil Origin: status = %d, want 403", rec.Code)
	}
}

func TestOriginGuard_RejectsNullOrigin(t *testing.T) {
	// Sandboxed iframe / data: / file: URLs serialize to "null".
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", strings.NewReader("{}"))
	req.Header.Set("Origin", "null")
	rec := httptest.NewRecorder()
	newGuardedHandler().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Errorf("null Origin: status = %d, want 403", rec.Code)
	}
}

func TestOriginGuard_NormalizesCaseAndTrailingSlash(t *testing.T) {
	// Operators routinely paste mixed-case URLs or include a trailing
	// slash in env config. RFC 6454: scheme/host are case-insensitive.
	cases := []string{
		"HTTP://LOCALHOST:8080",
		"http://localhost:8080/",
		"  http://localhost:8080  ", // whitespace
	}
	for _, o := range cases {
		t.Run(o, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", strings.NewReader("{}"))
			req.Header.Set("Origin", o)
			rec := httptest.NewRecorder()
			newGuardedHandler().ServeHTTP(rec, req)
			if rec.Code != http.StatusNoContent {
				t.Errorf("Origin %q: status = %d, want 204", o, rec.Code)
			}
		})
	}
}

func TestOriginGuard_EmptyAllowlist(t *testing.T) {
	// Defensive: with an empty allowlist, any browser Origin is rejected
	// but non-browser callers still pass. This is the "operator wiped CORS
	// config" failure mode; we keep CLI working and lock down the UI.
	guard := OriginGuard(nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))

	t.Run("no Origin still passes", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", strings.NewReader("{}"))
		rec := httptest.NewRecorder()
		guard.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Errorf("status = %d, want 204", rec.Code)
		}
	})

	t.Run("any Origin rejected", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", strings.NewReader("{}"))
		req.Header.Set("Origin", "http://localhost:8080")
		rec := httptest.NewRecorder()
		guard.ServeHTTP(rec, req)
		if rec.Code != http.StatusForbidden {
			t.Errorf("status = %d, want 403", rec.Code)
		}
	})
}
