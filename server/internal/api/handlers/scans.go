package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/adithyan-ak/agenthound/server/internal/appdb"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/adithyan-ak/agenthound/server/model"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type ScanHandler struct {
	scanStore scanStore
}

type scanStore interface {
	ListScans(ctx context.Context, limit, offset int) ([]model.Scan, error)
	ListScansPage(ctx context.Context, limit, offset int, revision string, order appdb.ScanListOrder) ([]model.Scan, appdb.ScanPageInfo, error)
	GetScan(ctx context.Context, id string) (*model.Scan, error)
	CreateScan(ctx context.Context, scan *model.Scan) error
	DeleteScan(ctx context.Context, id string) error
}

func NewScanHandler(store *appdb.ScanStore, graphDB graph.GraphDB) *ScanHandler {
	_ = graphDB // retained in the constructor for additive call-site compatibility
	return &ScanHandler{scanStore: store}
}

func (h *ScanHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	limit := parseIntParam(r, "limit", 50)
	offset := parseOffsetParam(r, "offset")
	revision := r.URL.Query().Get("revision")
	order := appdb.ScanListOrder(r.URL.Query().Get("order"))
	if order == "" {
		order = appdb.ScanListOrderStarted
	}
	switch order {
	case appdb.ScanListOrderStarted, appdb.ScanListOrderCompleted, appdb.ScanListOrderPublished:
	default:
		WriteValidationError(w, "order must be one of: started, completed, published")
		return
	}

	scans, page, err := h.scanStore.ListScansPage(r.Context(), limit, offset, revision, order)
	if err != nil {
		var mismatch *appdb.ScanRevisionMismatchError
		if errors.As(err, &mismatch) {
			w.Header().Set(headerRevision, mismatch.Actual)
			WriteError(w, http.StatusConflict, "REVISION_CONFLICT", "scan history changed during pagination; restart from offset 0")
			return
		}
		WriteInternalError(w, r, fmt.Errorf("list scans: %w", err))
		return
	}
	if scans == nil {
		scans = []model.Scan{}
	}
	writePaginationHeaders(w, graph.PageInfo{
		Offset: page.Offset, Limit: page.Limit, Total: page.Total,
		HasMore: page.HasMore, Complete: page.Complete, Revision: page.Revision,
	})
	WriteJSON(w, http.StatusOK, scans)
}

func (h *ScanHandler) HandleGet(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		WriteValidationError(w, "scan id is required")
		return
	}

	scan, err := h.scanStore.GetScan(r.Context(), id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			WriteNotFound(w, "scan not found")
			return
		}
		WriteInternalError(w, r, fmt.Errorf("get scan: %w", err))
		return
	}
	WriteJSON(w, http.StatusOK, scan)
}

type createScanRequest struct {
	Collector string         `json:"collector"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

func (h *ScanHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	var req createScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteValidationError(w, "invalid request body")
		return
	}
	if req.Collector == "" {
		WriteValidationError(w, "collector is required")
		return
	}
	validCollectors := map[string]bool{"mcp": true, "a2a": true, "config": true}
	if !validCollectors[req.Collector] {
		WriteValidationError(w, "collector must be one of: mcp, a2a, config")
		return
	}

	scan := model.Scan{
		ID:        uuid.New().String(),
		Collector: req.Collector,
		Status:    model.ScanStatusPending,
		StartedAt: time.Now().UTC(),
		Metadata:  req.Metadata,
	}

	if err := h.scanStore.CreateScan(r.Context(), &scan); err != nil {
		WriteInternalError(w, r, fmt.Errorf("create scan: %w", err))
		return
	}

	WriteJSON(w, http.StatusCreated, scan)
}

func (h *ScanHandler) HandleDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		WriteValidationError(w, "scan id is required")
		return
	}

	if err := h.scanStore.DeleteScan(r.Context(), id); err != nil {
		var conflict *appdb.ScanDeleteConflictError
		if errors.As(err, &conflict) {
			WriteError(w, http.StatusConflict, "SCAN_DELETE_CONFLICT", conflict.Reason)
			return
		}
		if errors.Is(err, pgx.ErrNoRows) {
			WriteNotFound(w, "scan not found")
			return
		}
		WriteInternalError(w, r, fmt.Errorf("delete scan: %w", err))
		return
	}

	w.WriteHeader(http.StatusNoContent)
}
