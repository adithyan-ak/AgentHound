package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/adithyan-ak/agenthound/server/model"
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

func TestHandleDeleteScan_GraphCleanupFailureDoesNotDeleteScan(t *testing.T) {
	store := &fakeScanStoreForHandler{scan: &model.Scan{ID: "scan-1", Collector: "mcp", Status: model.ScanStatusCompleted}}
	h := &ScanHandler{
		scanStore: store,
		graphDB:   &mockGraphDB{writeErr: errors.New("neo4j down")},
	}
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodDelete, "/api/v1/scans/scan-1", nil)
	r = withChiURLParam(r, "id", "scan-1")

	h.HandleDelete(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500, got %d", w.Code)
	}
	if store.deleted {
		t.Fatal("scan store DeleteScan should not be called when graph cleanup fails")
	}
}

func TestHandleDeleteScan_NonTerminalRejected(t *testing.T) {
	store := &fakeScanStoreForHandler{scan: &model.Scan{ID: "scan-1", Collector: "mcp", Status: model.ScanStatusRunning}}
	h := &ScanHandler{scanStore: store, graphDB: &mockGraphDB{}}
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodDelete, "/api/v1/scans/scan-1", nil)
	r = withChiURLParam(r, "id", "scan-1")

	h.HandleDelete(w, r)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d", w.Code)
	}
	if store.deleted {
		t.Fatal("a non-terminal scan must not be deleted")
	}
}

func TestHandleDeleteScan_RematerializesPriorGeneration(t *testing.T) {
	store := &fakeScanStoreForHandler{
		scan:  &model.Scan{ID: "scan-cur", Collector: "mcp", Status: model.ScanStatusCompleted, IsCurrent: true, GenerationID: "gen-cur"},
		prior: &model.Scan{ID: "scan-old", Collector: "mcp", GenerationID: "gen-old"},
	}
	fd := &fakeFindingDeleter{}
	h := &ScanHandler{scanStore: store, findingStore: fd, graphDB: &mockGraphDB{}}
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodDelete, "/api/v1/scans/scan-cur", nil)
	r = withChiURLParam(r, "id", "scan-cur")

	h.HandleDelete(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
	if len(store.promoted) != 1 || store.promoted[0] != "scan-old" {
		t.Errorf("expected prior generation scan-old rematerialized, got %v", store.promoted)
	}
	if !fd.deleted {
		t.Error("expected finding snapshot deletion")
	}
	if !store.deleted {
		t.Error("expected scan row deletion")
	}
}

func TestHandleDeleteScan_PreviewReportsBlastRadius(t *testing.T) {
	store := &fakeScanStoreForHandler{
		scan:  &model.Scan{ID: "scan-cur", Collector: "mcp", Status: model.ScanStatusCompleted, IsCurrent: true, GenerationID: "gen-cur"},
		prior: &model.Scan{ID: "scan-old", Collector: "mcp", GenerationID: "gen-old"},
	}
	h := &ScanHandler{scanStore: store, graphDB: &mockGraphDB{queryResult: []map[string]any{{"c": int64(5)}}}}
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodDelete, "/api/v1/scans/scan-cur?preview=true", nil)
	r = withChiURLParam(r, "id", "scan-cur")

	h.HandleDelete(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", w.Code)
	}
	var pv deletePreview
	if err := json.NewDecoder(w.Body).Decode(&pv); err != nil {
		t.Fatal(err)
	}
	if pv.NodesAffected != 5 || pv.EdgesAffected != 5 {
		t.Errorf("expected 5/5 affected, got %d/%d", pv.NodesAffected, pv.EdgesAffected)
	}
	if pv.RematerializeScanID != "scan-old" || pv.RematerializeGeneration != "gen-old" {
		t.Errorf("expected rematerialize prior scan-old/gen-old, got %s/%s", pv.RematerializeScanID, pv.RematerializeGeneration)
	}
	// Preview must not mutate anything.
	if store.deleted || len(store.promoted) != 0 {
		t.Error("preview must be side-effect free")
	}
}

type fakeFindingDeleter struct{ deleted bool }

func (f *fakeFindingDeleter) DeleteFindingsForScan(_ context.Context, _ string) error {
	f.deleted = true
	return nil
}

type fakeScanStoreForHandler struct {
	scan         *model.Scan
	prior        *model.Scan
	deleted      bool
	promoted     []string
	promoteErr   error
	deleteStates []string
}

func (s *fakeScanStoreForHandler) ListScans(_ context.Context, _, _ int) ([]model.Scan, error) {
	if s.scan == nil {
		return nil, nil
	}
	return []model.Scan{*s.scan}, nil
}

func (s *fakeScanStoreForHandler) GetScan(_ context.Context, _ string) (*model.Scan, error) {
	if s.scan == nil {
		return nil, errors.New("not found")
	}
	return s.scan, nil
}

func (s *fakeScanStoreForHandler) CreateScan(_ context.Context, scan *model.Scan) error {
	s.scan = scan
	return nil
}

func (s *fakeScanStoreForHandler) DeleteScan(_ context.Context, _ string) error {
	s.deleted = true
	return nil
}

func (s *fakeScanStoreForHandler) CurrentScanForScope(_ context.Context, _ string) (*model.Scan, error) {
	return nil, nil
}

func (s *fakeScanStoreForHandler) PriorValidScanForScope(_ context.Context, _, _ string) (*model.Scan, error) {
	return s.prior, nil
}

func (s *fakeScanStoreForHandler) PromoteGeneration(_ context.Context, id, _ string) error {
	if s.promoteErr != nil {
		return s.promoteErr
	}
	s.promoted = append(s.promoted, id)
	return nil
}

func (s *fakeScanStoreForHandler) MarkDeleting(_ context.Context, _ string) error {
	s.deleteStates = append(s.deleteStates, model.DeleteStateDeleting)
	return nil
}

func (s *fakeScanStoreForHandler) MarkDeleteFailed(_ context.Context, _ string) error {
	s.deleteStates = append(s.deleteStates, model.DeleteStateFailed)
	return nil
}

func (s *fakeScanStoreForHandler) ScansInDeleteState(_ context.Context) ([]model.Scan, error) {
	return nil, nil
}
