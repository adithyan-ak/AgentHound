package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/adithyan-ak/agenthound/server/model"
)

type fakePostureReader struct {
	export *model.PostureExport
	state  *model.ProjectionState
}

func (f *fakePostureReader) GetPublishedExport(context.Context) (*model.PostureExport, error) {
	return f.export, nil
}

func (f *fakePostureReader) GetProjectionState(context.Context) (*model.ProjectionState, error) {
	return f.state, nil
}

func TestPostureExportServesPersistedRevision(t *testing.T) {
	handler := &PostureHandler{store: &fakePostureReader{
		export: &model.PostureExport{
			SchemaVersion: 1,
			Scope: model.PostureScope{
				ScanID:   "scan-published",
				Revision: 42,
			},
			Findings: []model.Finding{},
		},
	}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/posture/export", nil)

	handler.HandleExport(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var export model.PostureExport
	if err := json.NewDecoder(w.Body).Decode(&export); err != nil {
		t.Fatal(err)
	}
	if export.Scope.Revision != 42 || export.Scope.ScanID != "scan-published" {
		t.Fatalf("export scope = %+v", export.Scope)
	}
	if got := w.Header().Get("Content-Disposition"); got == "" {
		t.Fatal("missing download content disposition")
	}
}

func TestPostureStateReportsPublishedFallbackDuringIncompleteProjection(t *testing.T) {
	revision := int64(42)
	publishedAt := time.Now().UTC()
	handler := &PostureHandler{store: &fakePostureReader{
		state: &model.ProjectionState{
			Status:            model.ProjectionIncomplete,
			ScanID:            "scan-partial",
			DirtyCoverage:     []string{"mcp"},
			PublishedScanID:   "scan-published",
			PublishedRevision: &revision,
			PublishedAt:       &publishedAt,
		},
	}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/posture", nil)

	handler.HandleState(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var state model.ProjectionState
	if err := json.NewDecoder(w.Body).Decode(&state); err != nil {
		t.Fatal(err)
	}
	if state.Status != model.ProjectionIncomplete ||
		state.PublishedScanID != "scan-published" ||
		state.ScanID != "scan-partial" {
		t.Fatalf("state = %+v", state)
	}
}
