package handlers

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/adithyan-ak/agenthound/internal/ingest"
	"github.com/adithyan-ak/agenthound/internal/model"
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

	var data model.IngestData
	if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}

	result, err := h.pipeline.Ingest(r.Context(), &data)
	if err != nil {
		var ve *ingest.ValidationError
		if errors.As(err, &ve) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(map[string]any{
				"error":   "validation failed",
				"details": ve.Errors,
			})
			return
		}
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, result)
}
