package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandleOpenAPIDocs(t *testing.T) {
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/docs/openapi.yaml", nil)
	HandleOpenAPIDocs(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	ct := w.Header().Get("Content-Type")
	if ct != "application/yaml" {
		t.Fatalf("expected Content-Type application/yaml, got %q", ct)
	}
	body := w.Body.String()
	if body == "" {
		t.Fatal("expected non-empty body")
	}
	if !strings.Contains(body, "openapi:") {
		t.Fatal("body does not contain 'openapi:' marker")
	}
}
