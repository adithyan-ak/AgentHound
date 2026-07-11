package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/adithyan-ak/agenthound/server/internal/appdb"
	"github.com/adithyan-ak/agenthound/server/model"
)

func TestHandleCreateScan_MissingCollector(t *testing.T) {
	h := NewScanHandler(nil, nil)
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
	h := NewScanHandler(nil, nil)
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

func TestHandleListScans_WritesStablePageHeaders(t *testing.T) {
	store := &fakeScanStoreForHandler{
		scan: &model.Scan{ID: "scan-1", Collector: "mcp", Status: model.ScanStatusCompleted},
	}
	h := &ScanHandler{scanStore: store}
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodGet, "/api/v1/scans?limit=50&offset=0", nil)

	h.HandleList(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if got := w.Header().Get(headerTotalCount); got != "1" {
		t.Fatalf("%s = %q, want 1", headerTotalCount, got)
	}
	if got := w.Header().Get(headerRevision); got != "scan-rev" {
		t.Fatalf("%s = %q, want scan-rev", headerRevision, got)
	}
	if got := w.Header().Get(headerCollectionComplete); got != "true" {
		t.Fatalf("%s = %q, want true", headerCollectionComplete, got)
	}
	if store.order != appdb.ScanListOrderStarted {
		t.Fatalf("order = %q, want started", store.order)
	}
}

func TestHandleListScans_UsesRequestedFreshnessOrder(t *testing.T) {
	store := &fakeScanStoreForHandler{
		scan: &model.Scan{ID: "scan-1", Collector: "mcp", Status: model.ScanStatusCompleted},
	}
	h := &ScanHandler{scanStore: store}
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodGet, "/api/v1/scans?limit=1&order=completed", nil)

	h.HandleList(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", w.Code)
	}
	if store.order != appdb.ScanListOrderCompleted {
		t.Fatalf("order = %q, want completed", store.order)
	}
}

func TestHandleListScans_RejectsUnknownOrder(t *testing.T) {
	store := &fakeScanStoreForHandler{}
	h := &ScanHandler{scanStore: store}
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodGet, "/api/v1/scans?order=unknown", nil)

	h.HandleList(w, r)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", w.Code)
	}
}

func TestHandleDeleteScan_IsHistoryOnly(t *testing.T) {
	store := &fakeScanStoreForHandler{scan: &model.Scan{ID: "scan-1", Collector: "mcp", Status: model.ScanStatusCompleted}}
	h := &ScanHandler{scanStore: store}
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodDelete, "/api/v1/scans/scan-1", nil)
	r = withChiURLParam(r, "id", "scan-1")

	h.HandleDelete(w, r)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", w.Code)
	}
	if !store.deleted {
		t.Fatal("scan history row was not deleted")
	}
}

func TestHandleDeleteScan_ConflictIs409(t *testing.T) {
	store := &fakeScanStoreForHandler{
		scan:      &model.Scan{ID: "scan-1", Status: model.ScanStatusRunning},
		deleteErr: &appdb.ScanDeleteConflictError{Reason: "pending or running scans are active"},
	}
	h := &ScanHandler{scanStore: store}
	w := httptest.NewRecorder()
	r := newTestRequest(http.MethodDelete, "/api/v1/scans/scan-1", nil)
	r = withChiURLParam(r, "id", "scan-1")

	h.HandleDelete(w, r)

	if w.Code != http.StatusConflict {
		t.Fatalf("expected 409, got %d body=%s", w.Code, w.Body.String())
	}
	if store.deleted {
		t.Fatal("conflicted scan was marked deleted")
	}
}

type fakeScanStoreForHandler struct {
	scan      *model.Scan
	deleted   bool
	deleteErr error
	order     appdb.ScanListOrder
}

func (s *fakeScanStoreForHandler) ListScans(_ context.Context, _, _ int) ([]model.Scan, error) {
	if s.scan == nil {
		return nil, nil
	}
	return []model.Scan{*s.scan}, nil
}

func (s *fakeScanStoreForHandler) ListScansPage(_ context.Context, limit, offset int, _ string, order appdb.ScanListOrder) ([]model.Scan, appdb.ScanPageInfo, error) {
	s.order = order
	scans, err := s.ListScans(context.Background(), limit, offset)
	return scans, appdb.ScanPageInfo{
		Offset: offset, Limit: limit, Total: int64(len(scans)),
		Complete: true, Revision: "scan-rev",
	}, err
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
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.deleted = true
	return nil
}
