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
	patchErr  error

	gotGetFP    string
	gotUpsertFP string
	gotStatus   string
	gotNote     string

	gotPatchFP     string
	gotPatchStatus *string
	gotPatchNote   *string
}

func (m *mockTriageStore) GetTriage(_ context.Context, fp string) (*model.TriageState, error) {
	m.gotGetFP = fp
	return m.getResult, m.getErr
}

func (m *mockTriageStore) UpsertTriage(_ context.Context, fp, status, note string) (*model.TriageState, error) {
	m.gotUpsertFP, m.gotStatus, m.gotNote = fp, status, note
	if m.upsertErr != nil {
		return nil, m.upsertErr
	}
	return &model.TriageState{Status: status, Note: note}, nil
}

func (m *mockTriageStore) PatchTriage(_ context.Context, fp string, status, note *string) (*model.TriageState, error) {
	m.gotPatchFP, m.gotPatchStatus, m.gotPatchNote = fp, status, note
	if m.patchErr != nil {
		return nil, m.patchErr
	}
	ts := &model.TriageState{Status: "new"}
	if status != nil {
		ts.Status = *status
	}
	if note != nil {
		ts.Note = *note
	}
	return ts, nil
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
	body, _ := json.Marshal(triageUpdateRequest{Status: "confirmed", Note: strings.Repeat("x", maxTriageNoteLen+1)})
	w := httptest.NewRecorder()
	r := withChiURLParam(newTestRequest(http.MethodPut, "/x", body), "fingerprint", validFP)
	h.HandleSet(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for oversized note, got %d", w.Code)
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

func TestTriageHandler_Patch_OmittedFieldsPreserve(t *testing.T) {
	store := &mockTriageStore{}
	h := &TriageHandler{store: store}
	w := httptest.NewRecorder()
	// Only status provided; note omitted → note pointer must be nil (preserve).
	r := withChiURLParam(newTestRequest(http.MethodPatch, "/x", []byte(`{"status":"confirmed"}`)), "fingerprint", validFP)
	h.HandlePatch(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if store.gotPatchStatus == nil || *store.gotPatchStatus != "confirmed" {
		t.Errorf("status pointer should be set to confirmed, got %v", store.gotPatchStatus)
	}
	if store.gotPatchNote != nil {
		t.Error("omitted note must be a nil pointer (preserve), not an empty string")
	}
}

func TestTriageHandler_Patch_ExplicitEmptyClears(t *testing.T) {
	store := &mockTriageStore{}
	h := &TriageHandler{store: store}
	w := httptest.NewRecorder()
	// Explicit empty note → non-nil pointer to "" (clear).
	r := withChiURLParam(newTestRequest(http.MethodPatch, "/x", []byte(`{"note":""}`)), "fingerprint", validFP)
	h.HandlePatch(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	if store.gotPatchNote == nil || *store.gotPatchNote != "" {
		t.Errorf("explicit empty note must be a non-nil empty pointer (clear), got %v", store.gotPatchNote)
	}
	if store.gotPatchStatus != nil {
		t.Error("omitted status must be a nil pointer (preserve)")
	}
}

func TestTriageHandler_Patch_InvalidStatus(t *testing.T) {
	h := &TriageHandler{store: &mockTriageStore{}}
	w := httptest.NewRecorder()
	r := withChiURLParam(newTestRequest(http.MethodPatch, "/x", []byte(`{"status":"bogus"}`)), "fingerprint", validFP)
	h.HandlePatch(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", w.Code)
	}
}
