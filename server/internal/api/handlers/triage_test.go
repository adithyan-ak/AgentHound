package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/adithyan-ak/agenthound/server/model"
)

type mockTriageStore struct {
	getResult *model.TriageState
	getErr    error
	upsertErr error

	gotGetFP    string
	gotUpsertFP string
	gotStatus   string
	gotNote     string
	upsertCalls int
	statusCalls int
}

func (m *mockTriageStore) GetTriage(_ context.Context, fp string) (*model.TriageState, error) {
	m.gotGetFP = fp
	return m.getResult, m.getErr
}

func (m *mockTriageStore) UpsertTriage(_ context.Context, fp, status, note string) (*model.TriageState, error) {
	m.upsertCalls++
	m.gotUpsertFP, m.gotStatus, m.gotNote = fp, status, note
	if m.upsertErr != nil {
		return nil, m.upsertErr
	}
	return &model.TriageState{Status: status, Note: note}, nil
}

func (m *mockTriageStore) UpdateTriageStatus(_ context.Context, fp, status string) (*model.TriageState, error) {
	m.statusCalls++
	m.gotUpsertFP, m.gotStatus = fp, status
	if m.upsertErr != nil {
		return nil, m.upsertErr
	}
	// Simulate a preserved note from a prior decision.
	return &model.TriageState{Status: status, Note: "preserved"}, nil
}

const validFP = "aaaaaaaaaaaaaaaa"

func TestTriageHandler_Get_InvalidFingerprint(t *testing.T) {
	h := &TriageHandler{store: &mockTriageStore{}}
	w := httptest.NewRecorder()
	r := withChiURLParam(newTestRequest(http.MethodGet, "/x", nil), "fingerprint", "not-hex")
	h.HandleGet(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestTriageHandler_Get_NilStore(t *testing.T) {
	h := &TriageHandler{} // store nil
	w := httptest.NewRecorder()
	r := withChiURLParam(newTestRequest(http.MethodGet, "/x", nil), "fingerprint", validFP)
	h.HandleGet(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
}

func TestTriageHandler_Get_DefaultsToNewWhenAbsent(t *testing.T) {
	h := &TriageHandler{store: &mockTriageStore{getResult: nil}}
	w := httptest.NewRecorder()
	r := withChiURLParam(newTestRequest(http.MethodGet, "/x", nil), "fingerprint", validFP)
	h.HandleGet(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var ts model.TriageState
	if err := json.NewDecoder(w.Body).Decode(&ts); err != nil {
		t.Fatal(err)
	}
	if ts.Status != "new" {
		t.Errorf("absent triage should default to 'new', got %q", ts.Status)
	}
}

func TestTriageHandler_Get_Success(t *testing.T) {
	h := &TriageHandler{store: &mockTriageStore{getResult: &model.TriageState{Status: "confirmed", Note: "verified"}}}
	w := httptest.NewRecorder()
	r := withChiURLParam(newTestRequest(http.MethodGet, "/x", nil), "fingerprint", validFP)
	h.HandleGet(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var ts model.TriageState
	if err := json.NewDecoder(w.Body).Decode(&ts); err != nil {
		t.Fatal(err)
	}
	if ts.Status != "confirmed" || ts.Note != "verified" {
		t.Errorf("got %+v", ts)
	}
}

func TestTriageHandler_Get_StoreError(t *testing.T) {
	h := &TriageHandler{store: &mockTriageStore{getErr: errors.New("pg down")}}
	w := httptest.NewRecorder()
	r := withChiURLParam(newTestRequest(http.MethodGet, "/x", nil), "fingerprint", validFP)
	h.HandleGet(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}

func TestTriageHandler_Set_InvalidFingerprint(t *testing.T) {
	h := &TriageHandler{store: &mockTriageStore{}}
	w := httptest.NewRecorder()
	r := withChiURLParam(newTestRequest(http.MethodPut, "/x", []byte(`{"status":"confirmed"}`)), "fingerprint", "zzz")
	h.HandleSet(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestTriageHandler_Set_DecodeError(t *testing.T) {
	h := &TriageHandler{store: &mockTriageStore{}}
	w := httptest.NewRecorder()
	r := withChiURLParam(newTestRequest(http.MethodPut, "/x", []byte(`{not json`)), "fingerprint", validFP)
	h.HandleSet(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestTriageHandler_Set_InvalidStatus(t *testing.T) {
	h := &TriageHandler{store: &mockTriageStore{}}
	w := httptest.NewRecorder()
	r := withChiURLParam(newTestRequest(http.MethodPut, "/x", []byte(`{"status":"bogus"}`)), "fingerprint", validFP)
	h.HandleSet(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}

func TestTriageHandler_Set_NoteTooLong(t *testing.T) {
	h := &TriageHandler{store: &mockTriageStore{}}
	longNote := strings.Repeat("x", maxTriageNoteLen+1)
	body, _ := json.Marshal(triageUpdateRequest{Status: "confirmed", Note: &longNote})
	w := httptest.NewRecorder()
	r := withChiURLParam(newTestRequest(http.MethodPut, "/x", body), "fingerprint", validFP)
	h.HandleSet(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized note, got %d", w.Code)
	}
}

func TestTriageHandler_Set_StatusOnlyPreservesNote(t *testing.T) {
	// AH-UI-34: a PATCH with no note field must NOT overwrite the note. The
	// handler routes to UpdateTriageStatus (note-preserving), not UpsertTriage.
	store := &mockTriageStore{}
	h := &TriageHandler{store: store}
	w := httptest.NewRecorder()
	r := withChiURLParam(newTestRequest(http.MethodPut, "/x", []byte(`{"status":"confirmed"}`)), "fingerprint", validFP)
	h.HandleSet(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if store.statusCalls != 1 || store.upsertCalls != 0 {
		t.Errorf("status-only change should call UpdateTriageStatus once, not UpsertTriage: status=%d upsert=%d", store.statusCalls, store.upsertCalls)
	}
	var ts model.TriageState
	if err := json.NewDecoder(w.Body).Decode(&ts); err != nil {
		t.Fatal(err)
	}
	if ts.Note != "preserved" {
		t.Errorf("note should be preserved, got %q", ts.Note)
	}
}

func TestTriageHandler_Set_ExplicitNoteOverwrites(t *testing.T) {
	// An explicitly provided note (even empty) uses UpsertTriage.
	store := &mockTriageStore{}
	h := &TriageHandler{store: store}
	w := httptest.NewRecorder()
	r := withChiURLParam(newTestRequest(http.MethodPut, "/x", []byte(`{"status":"confirmed","note":""}`)), "fingerprint", validFP)
	h.HandleSet(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if store.upsertCalls != 1 || store.statusCalls != 0 {
		t.Errorf("explicit note should call UpsertTriage once: status=%d upsert=%d", store.statusCalls, store.upsertCalls)
	}
}

func TestTriageHandler_Set_NilStore(t *testing.T) {
	h := &TriageHandler{} // store nil
	w := httptest.NewRecorder()
	r := withChiURLParam(newTestRequest(http.MethodPut, "/x", []byte(`{"status":"confirmed"}`)), "fingerprint", validFP)
	h.HandleSet(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", w.Code)
	}
}

func TestTriageHandler_Set_Success(t *testing.T) {
	store := &mockTriageStore{}
	h := &TriageHandler{store: store}
	w := httptest.NewRecorder()
	r := withChiURLParam(newTestRequest(http.MethodPut, "/x", []byte(`{"status":"accepted-risk","note":"ok"}`)), "fingerprint", validFP)
	h.HandleSet(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if store.gotUpsertFP != validFP || store.gotStatus != "accepted-risk" || store.gotNote != "ok" {
		t.Errorf("upsert got fp=%q status=%q note=%q", store.gotUpsertFP, store.gotStatus, store.gotNote)
	}
}

func TestTriageHandler_Set_StoreError(t *testing.T) {
	h := &TriageHandler{store: &mockTriageStore{upsertErr: errors.New("pg down")}}
	w := httptest.NewRecorder()
	r := withChiURLParam(newTestRequest(http.MethodPut, "/x", []byte(`{"status":"confirmed"}`)), "fingerprint", validFP)
	h.HandleSet(w, r)
	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
}
