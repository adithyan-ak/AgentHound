package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
)

func TestCORSRejectsUnknownOrigin(t *testing.T) {
	r := chi.NewRouter()
	r.Use(CORS([]string{"http://localhost:8080"}))
	r.Get("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "http://evil.com")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	got := rec.Header().Get("Access-Control-Allow-Origin")
	if got == "http://evil.com" {
		t.Errorf("CORS should not allow origin http://evil.com, but Access-Control-Allow-Origin = %q", got)
	}
}

func TestCORSAllowsConfiguredOrigin(t *testing.T) {
	r := chi.NewRouter()
	r.Use(CORS([]string{"http://localhost:8080"}))
	r.Get("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "http://localhost:8080")
	req.Header.Set("Access-Control-Request-Method", "GET")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	got := rec.Header().Get("Access-Control-Allow-Origin")
	if got != "http://localhost:8080" {
		t.Errorf("Access-Control-Allow-Origin = %q, want %q", got, "http://localhost:8080")
	}
}

// TestCORSDoesNotAllowCredentials locks down the no-credentials posture.
// AllowCredentials: true would let a hostile tab ride ambient cookies on
// the operator's browser. The server has no credentials to send anyway,
// so this header must NEVER appear in responses.
func TestCORSDoesNotAllowCredentials(t *testing.T) {
	r := chi.NewRouter()
	r.Use(CORS([]string{"http://localhost:8080"}))
	r.Get("/", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	req := httptest.NewRequest(http.MethodOptions, "/", nil)
	req.Header.Set("Origin", "http://localhost:8080")
	req.Header.Set("Access-Control-Request-Method", "POST")
	rec := httptest.NewRecorder()

	r.ServeHTTP(rec, req)

	if got := rec.Header().Get("Access-Control-Allow-Credentials"); got == "true" {
		t.Errorf("Access-Control-Allow-Credentials = %q, must NOT be %q", got, "true")
	}
}
