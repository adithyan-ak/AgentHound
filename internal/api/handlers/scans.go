package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/adithyan-ak/agenthound/internal/appdb"
	"github.com/adithyan-ak/agenthound/internal/audit"
	"github.com/adithyan-ak/agenthound/internal/model"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type ScanHandler struct {
	scanStore *appdb.ScanStore
	audit     *audit.Logger
}

func NewScanHandler(store *appdb.ScanStore, auditLog *audit.Logger) *ScanHandler {
	return &ScanHandler{scanStore: store, audit: auditLog}
}

func (h *ScanHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	limit := parseIntParam(r, "limit", 50)
	offset := parseIntParam(r, "offset", 0)

	scans, err := h.scanStore.ListScans(r.Context(), limit, offset)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("list scans: %w", err))
		return
	}
	if scans == nil {
		scans = []model.Scan{}
	}
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

	h.auditLog(r, "scan.start", map[string]any{"scan_id": scan.ID, "collector": scan.Collector})
	WriteJSON(w, http.StatusCreated, scan)
}

func (h *ScanHandler) auditLog(r *http.Request, action string, details map[string]any) {
	if h.audit == nil {
		return
	}
	if err := h.audit.Log(r.Context(), action, details); err != nil {
		slog.Warn("audit log failed", "action", action, "error", err)
	}
}
