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
	"github.com/adithyan-ak/agenthound/internal/graph"
	"github.com/adithyan-ak/agenthound/internal/model"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type ScanHandler struct {
	scanStore *appdb.ScanStore
	graphDB   graph.GraphDB
	audit     *audit.Logger
}

func NewScanHandler(store *appdb.ScanStore, graphDB graph.GraphDB, auditLog *audit.Logger) *ScanHandler {
	return &ScanHandler{scanStore: store, graphDB: graphDB, audit: auditLog}
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

	h.auditLog(r, "scan.start", map[string]any{"scan_id": scan.ID, "collector": scan.Collector})
	WriteJSON(w, http.StatusCreated, scan)
}

func (h *ScanHandler) HandleDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		WriteValidationError(w, "scan id is required")
		return
	}

	// Verify the scan exists before doing graph cleanup.
	if _, err := h.scanStore.GetScan(r.Context(), id); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			WriteNotFound(w, "scan not found")
			return
		}
		WriteInternalError(w, r, fmt.Errorf("get scan: %w", err))
		return
	}

	// Delete edges owned by this scan from Neo4j.
	edgesDeleted, err := h.graphDB.ExecuteWrite(r.Context(),
		`MATCH ()-[r]->() WHERE r.scan_id = $scan_id DELETE r RETURN count(r) AS deleted`,
		map[string]any{"scan_id": id})
	if err != nil {
		slog.Error("neo4j edge cleanup failed", "scan_id", id, "error", err)
	}

	// Delete orphaned nodes: nodes from this scan with no remaining edges.
	nodesDeleted, err := h.graphDB.ExecuteWrite(r.Context(),
		`MATCH (n) WHERE n.scan_id = $scan_id
		 AND NOT EXISTS { MATCH (n)-[]-() }
		 DELETE n RETURN count(n) AS deleted`,
		map[string]any{"scan_id": id})
	if err != nil {
		slog.Error("neo4j node cleanup failed", "scan_id", id, "error", err)
	}

	// Delete PG scan record.
	if err := h.scanStore.DeleteScan(r.Context(), id); err != nil {
		WriteInternalError(w, r, fmt.Errorf("delete scan: %w", err))
		return
	}

	h.auditLog(r, "scan.delete", map[string]any{
		"scan_id":       id,
		"edges_deleted": edgesDeleted,
		"nodes_deleted": nodesDeleted,
	})
	w.WriteHeader(http.StatusNoContent)
}

func (h *ScanHandler) auditLog(r *http.Request, action string, details map[string]any) {
	if h.audit == nil {
		return
	}
	if err := h.audit.Log(r.Context(), action, details); err != nil {
		slog.Warn("audit log failed", "action", action, "error", err)
	}
}
