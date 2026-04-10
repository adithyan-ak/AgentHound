package handlers

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/adithyan-ak/agenthound/internal/graph"
	"github.com/go-chi/chi/v5"
)

type GraphHandler struct {
	reader *graph.Reader
}

func NewGraphHandler(reader *graph.Reader) *GraphHandler {
	return &GraphHandler{reader: reader}
}

func (h *GraphHandler) HandleStats(w http.ResponseWriter, r *http.Request) {
	stats, err := h.reader.GetStats(r.Context())
	if err != nil {
		WriteInternalError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, stats)
}

func (h *GraphHandler) HandleListNodes(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	limit := parseIntParam(r, "limit", 100)

	nodes, err := h.reader.ListNodes(r.Context(), kind, limit)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("list nodes: %w", err))
		return
	}
	WriteJSON(w, http.StatusOK, nodes)
}

func (h *GraphHandler) HandleGetNode(w http.ResponseWriter, r *http.Request) {
	raw := chi.URLParam(r, "id")
	id, err := url.PathUnescape(raw)
	if err != nil {
		WriteValidationError(w, "invalid node id")
		return
	}
	node, edges, err := h.reader.GetNode(r.Context(), id)
	if err != nil {
		WriteInternalError(w, r, err)
		return
	}
	if node == nil {
		WriteNotFound(w, "node not found")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"node":  node,
		"edges": edges,
	})
}

func (h *GraphHandler) HandleListEdges(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	source := r.URL.Query().Get("source")
	target := r.URL.Query().Get("target")
	limit := parseIntParam(r, "limit", 100)

	edges, err := h.reader.ListEdges(r.Context(), kind, source, target, limit)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("list edges: %w", err))
		return
	}
	WriteJSON(w, http.StatusOK, edges)
}

const maxQueryLimit = 10000

func parseIntParam(r *http.Request, key string, defaultVal int) int {
	s := r.URL.Query().Get(key)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(s)
	if err != nil || v <= 0 {
		return defaultVal
	}
	if v > maxQueryLimit {
		return maxQueryLimit
	}
	return v
}
