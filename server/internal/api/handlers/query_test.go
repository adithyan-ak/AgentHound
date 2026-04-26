package handlers

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleQuery_EmptyBody(t *testing.T) {
	h := NewQueryHandler(nil)
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodPost, "/api/v1/query", []byte(""))
	h.Handle(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	var resp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error.Message != "invalid JSON payload" {
		t.Fatalf("expected 'invalid JSON payload', got %q", resp.Error.Message)
	}
}

func TestHandleQuery_EmptyCypher(t *testing.T) {
	h := NewQueryHandler(nil)
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodPost, "/api/v1/query", []byte(`{"cypher":""}`))
	h.Handle(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
	var resp ErrorResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatal(err)
	}
	if resp.Error.Message != "cypher query is required" {
		t.Fatalf("expected 'cypher query is required', got %q", resp.Error.Message)
	}
}

func TestHandleQuery_InvalidJSON(t *testing.T) {
	h := NewQueryHandler(nil)
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodPost, "/api/v1/query", []byte(`{invalid`))
	h.Handle(w, r)

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
