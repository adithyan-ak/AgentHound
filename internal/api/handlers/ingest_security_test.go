package handlers

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestMaxIngestBodySizeValue(t *testing.T) {
	const want = 100 << 20 // 100 MB
	if maxIngestBodySize != want {
		t.Errorf("maxIngestBodySize = %d, want %d (100 MB)", maxIngestBodySize, want)
	}
}

func TestIngestRejectsInvalidJSON(t *testing.T) {
	h := NewIngestHandler(nil, nil)

	body := strings.NewReader(`{"bad json`)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/ingest", body)
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	h.Handle(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Errorf("status = %d, want %d", rec.Code, http.StatusBadRequest)
	}
	if !strings.Contains(rec.Body.String(), "VALIDATION_ERROR") {
		t.Errorf("body should contain VALIDATION_ERROR, got %s", rec.Body.String())
	}
}
