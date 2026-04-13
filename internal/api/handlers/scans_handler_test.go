package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleCreateScan_MissingCollector(t *testing.T) {
	h := NewScanHandler(nil, nil, nil)
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodPost, "/api/v1/scans", []byte(`{}`))
	h.HandleCreate(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	var resp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error.Code != "VALIDATION_ERROR" {
		t.Fatalf("expected VALIDATION_ERROR, got %s", resp.Error.Code)
	}
}

func TestHandleGetScan_EmptyID(t *testing.T) {
	h := NewScanHandler(nil, nil, nil)
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodGet, "/api/v1/scans/", nil)
	r = withChiURLParam(r, "id", "")
	h.HandleGet(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	var resp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error.Code != "VALIDATION_ERROR" {
		t.Fatalf("expected VALIDATION_ERROR, got %s", resp.Error.Code)
	}
}
