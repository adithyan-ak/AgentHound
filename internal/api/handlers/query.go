package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/adithyan-ak/agenthound/internal/graph"
)

type QueryHandler struct {
	reader *graph.Reader
}

func NewQueryHandler(reader *graph.Reader) *QueryHandler {
	return &QueryHandler{reader: reader}
}

type queryRequest struct {
	Cypher string         `json:"cypher"`
	Params map[string]any `json:"params"`
}

func (h *QueryHandler) Handle(w http.ResponseWriter, r *http.Request) {
	var req queryRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON: "+err.Error())
		return
	}
	if req.Cypher == "" {
		writeError(w, http.StatusBadRequest, "cypher query is required")
		return
	}

	rows, err := h.reader.Query(r.Context(), req.Cypher, req.Params)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{"rows": rows})
}
