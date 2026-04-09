package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	"github.com/adithyan-ak/agenthound/internal/audit"
	"github.com/adithyan-ak/agenthound/internal/ingest"
	"github.com/adithyan-ak/agenthound/internal/model"
)

type IngestHandler struct {
	pipeline *ingest.Pipeline
	audit    *audit.Logger
}

func NewIngestHandler(pipeline *ingest.Pipeline, auditLog *audit.Logger) *IngestHandler {
	return &IngestHandler{pipeline: pipeline, audit: auditLog}
}

const maxIngestBodySize = 100 << 20 // 100 MB

func (h *IngestHandler) Handle(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxIngestBodySize)

	var data model.IngestData
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		WriteValidationError(w, "invalid JSON payload")
		return
	}

	result, err := h.pipeline.Ingest(r.Context(), &data)
	if err != nil {
		var ve *ingest.ValidationError
		if errors.As(err, &ve) {
			WriteJSON(w, http.StatusBadRequest, ErrorResponse{
				Error: ErrorDetail{
					Code:    "VALIDATION_ERROR",
					Message: "validation failed",
					Details: ve.Errors,
				},
			})
			return
		}
		WriteInternalError(w, r, err)
		return
	}

	if h.audit != nil {
		if err := h.audit.Log(r.Context(), "ingest.upload", map[string]any{
			"scan_id":    result.ScanID,
			"node_count": result.NodesWritten,
			"edge_count": result.EdgesWritten,
		}); err != nil {
			slog.Warn("audit log failed", "error", err)
		}
		if err := h.audit.Log(r.Context(), "scan.complete", map[string]any{
			"scan_id":    result.ScanID,
			"node_count": result.NodesWritten,
			"edge_count": result.EdgesWritten,
		}); err != nil {
			slog.Warn("audit log failed", "error", err)
		}
	}

	WriteJSON(w, http.StatusOK, result)
}
