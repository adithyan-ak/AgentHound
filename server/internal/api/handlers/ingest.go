package handlers

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/ingest"
)

type IngestHandler struct {
	pipeline *ingest.Pipeline
}

func NewIngestHandler(pipeline *ingest.Pipeline) *IngestHandler {
	return &IngestHandler{pipeline: pipeline}
}

const maxIngestBodySize = 100 << 20 // 100 MB

func (h *IngestHandler) Handle(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxIngestBodySize)

	var data sdkingest.IngestData
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
		if result != nil {
			slog.Error("ingest failed after graph mutation",
				"error", err,
				"scan_id", result.ScanID,
				"nodes_written", result.NodesWritten,
				"edges_written", result.EdgesWritten,
			)
			WriteJSON(w, http.StatusInternalServerError, ErrorResponse{
				Error: ErrorDetail{
					Code:    "INGEST_FAILED",
					Message: "Ingest failed after partial graph mutation.",
					Details: result,
				},
			})
			return
		}
		WriteInternalError(w, r, err)
		return
	}

	WriteJSON(w, http.StatusOK, result)
}
