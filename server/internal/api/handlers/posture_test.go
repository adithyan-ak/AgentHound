package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
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

func validPostureExport() *model.PostureExport {
	return &model.PostureExport{
		SchemaVersion: model.PostureExportSchemaVersion,
		Scope: model.PostureScope{
			CoverageKeys:              []string{},
			ActiveCoverageKeys:        []string{},
			ActiveCoverageRoots:       []model.PostureCoverageRoot{},
			ActiveCoverageLimitations: []model.PostureCoverageLimitation{},
			DirtyCoverage:             []string{},
		},
		Completeness: model.PostureCompleteness{
			Warnings: []sdkingest.NormalizationWarning{},
			Stages:   []sdkingest.StageResult{},
		},
		GraphAfter: model.GraphSnapshot{
			NodeCounts: map[string]int64{},
			EdgeCounts: map[string]int64{},
		},
		Findings: []model.Finding{},
	}
}

func TestPostureExportServesPersistedRevision(t *testing.T) {
	export := validPostureExport()
	export.Scope.ScanID = "scan-published"
	export.Scope.Revision = 42
	handler := &PostureHandler{store: &fakePostureReader{
		export: export,
	}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/posture/export", nil)

	handler.HandleExport(w, r)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var decoded model.PostureExport
	if err := json.NewDecoder(w.Body).Decode(&decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Scope.Revision != 42 || decoded.Scope.ScanID != "scan-published" {
		t.Fatalf("export scope = %+v", decoded.Scope)
	}
	if decoded.Scope.ActiveCoverageRoots == nil {
		t.Fatal("current export emitted null active_coverage_roots")
	}
	if decoded.Scope.ActiveCoverageLimitations == nil {
		t.Fatal("current export emitted null active_coverage_limitations")
	}
	if got := w.Header().Get("Content-Disposition"); got == "" {
		t.Fatal("missing download content disposition")
	}
}

func TestPostureExportRejectsNullRequiredCoverage(t *testing.T) {
	export := validPostureExport()
	export.Scope.ActiveCoverageLimitations = nil
	handler := &PostureHandler{store: &fakePostureReader{
		export: export,
	}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/posture/export", nil)

	handler.HandleExport(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Disposition"); got != "" {
		t.Fatalf("invalid export received download header %q", got)
	}
}

func TestPostureExportRejectsUnsupportedPersistedSchema(t *testing.T) {
	export := validPostureExport()
	export.SchemaVersion = model.PostureExportSchemaVersion + 1
	handler := &PostureHandler{store: &fakePostureReader{
		export: export,
	}}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/api/v1/posture/export", nil)

	handler.HandleExport(w, r)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	if got := w.Header().Get("Content-Disposition"); got != "" {
		t.Fatalf("unsupported export received download header %q", got)
	}
}

func TestPostureStateReportsPublishedFallbackDuringIncompleteProjection(t *testing.T) {
	revision := int64(42)
	publishedAt := time.Now().UTC()
	handler := &PostureHandler{store: &fakePostureReader{
		state: &model.ProjectionState{
			Status:                    model.ProjectionIncomplete,
			ScanID:                    "scan-partial",
			DirtyCoverage:             []string{"mcp"},
			ActiveCoverageRoots:       []model.PostureCoverageRoot{},
			ActiveCoverageLimitations: []model.PostureCoverageLimitation{},
			PublishedScanID:           "scan-published",
			PublishedRevision:         &revision,
			PublishedAt:               &publishedAt,
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
