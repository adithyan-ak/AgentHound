package handlers

import (
	"encoding/json"
	"errors"
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
		WriteInternalError(w, r, err)
		return
	}

	WriteJSON(w, http.StatusOK, result)
}
