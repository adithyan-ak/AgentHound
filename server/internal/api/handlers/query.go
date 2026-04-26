package handlers

import (
	"encoding/json"
	"net/http"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
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
		WriteValidationError(w, "invalid JSON payload")
		return
	}
	if req.Cypher == "" {
		WriteValidationError(w, "cypher query is required")
		return
	}

	rows, err := h.reader.Query(r.Context(), req.Cypher, req.Params)
	if err != nil {
		WriteInternalError(w, r, err)
		return
	}

	WriteJSON(w, http.StatusOK, map[string]any{"rows": rows})
}
