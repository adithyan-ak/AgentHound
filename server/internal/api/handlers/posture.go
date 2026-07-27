package handlers

import (
	"context"
	"fmt"
	"net/http"

	"github.com/adithyan-ak/agenthound/server/internal/appdb"
	"github.com/adithyan-ak/agenthound/server/model"
)

type postureReader interface {
	GetPublishedExport(ctx context.Context) (*model.PostureExport, error)
	GetProjectionState(ctx context.Context) (*model.ProjectionState, error)
}

type PostureHandler struct {
	store postureReader
}

func NewPostureHandler(store *appdb.FindingStore) *PostureHandler {
	handler := &PostureHandler{}
	if store != nil {
		handler.store = store
	}
	return handler
}

func (h *PostureHandler) HandleState(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		WriteServiceError(w, "posture store")
		return
	}
	state, err := h.store.GetProjectionState(r.Context())
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("get posture state: %w", err))
		return
	}
	if err := validateProjectionStateV1(state); err != nil {
		WriteInternalError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, state)
}

func (h *PostureHandler) HandleExport(w http.ResponseWriter, r *http.Request) {
	if h.store == nil {
		WriteServiceError(w, "posture store")
		return
	}
	export, err := h.store.GetPublishedExport(r.Context())
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("get published posture export: %w", err))
		return
	}
	if export == nil {
		WriteNotFound(w, "no posture revision has been published")
		return
	}
	if export.SchemaVersion != model.PostureExportSchemaVersion {
		WriteInternalError(
			w,
			r,
			fmt.Errorf(
				"published posture export schema %d is unsupported; expected %d",
				export.SchemaVersion,
				model.PostureExportSchemaVersion,
			),
		)
		return
	}
	if err := validatePostureExportV1(export); err != nil {
		WriteInternalError(w, r, err)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="agenthound-posture.json"`)
	WriteJSON(w, http.StatusOK, export)
}

func validatePostureExportV1(export *model.PostureExport) error {
	switch {
	case export.Scope.CoverageKeys == nil:
		return fmt.Errorf("published posture export is invalid: scope.coverage_keys is null")
	case export.Scope.ActiveCoverageKeys == nil:
		return fmt.Errorf("published posture export is invalid: scope.active_coverage_keys is null")
	case export.Scope.ActiveCoverageRoots == nil:
		return fmt.Errorf("published posture export is invalid: scope.active_coverage_roots is null")
	case export.Scope.ActiveCoverageLimitations == nil:
		return fmt.Errorf("published posture export is invalid: scope.active_coverage_limitations is null")
	case export.Scope.DirtyCoverage == nil:
		return fmt.Errorf("published posture export is invalid: scope.dirty_coverage is null")
	case export.Completeness.Warnings == nil:
		return fmt.Errorf("published posture export is invalid: completeness.warnings is null")
	case export.Completeness.Stages == nil:
		return fmt.Errorf("published posture export is invalid: completeness.stages is null")
	case export.GraphAfter.NodeCounts == nil:
		return fmt.Errorf("published posture export is invalid: graph_after.node_counts is null")
	case export.GraphAfter.EdgeCounts == nil:
		return fmt.Errorf("published posture export is invalid: graph_after.edge_counts is null")
	case export.Findings == nil:
		return fmt.Errorf("published posture export is invalid: findings is null")
	default:
		return nil
	}
}

func validateProjectionStateV1(state *model.ProjectionState) error {
	switch {
	case state == nil:
		return fmt.Errorf("posture state is missing")
	case state.DirtyCoverage == nil:
		return fmt.Errorf("posture state is invalid: dirty_coverage is null")
	case state.ActiveCoverageRoots == nil:
		return fmt.Errorf("posture state is invalid: active_coverage_roots is null")
	case state.ActiveCoverageLimitations == nil:
		return fmt.Errorf("posture state is invalid: active_coverage_limitations is null")
	default:
		return nil
	}
}
