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
	w.Header().Set("Content-Disposition", `attachment; filename="agenthound-posture.json"`)
	WriteJSON(w, http.StatusOK, export)
}
