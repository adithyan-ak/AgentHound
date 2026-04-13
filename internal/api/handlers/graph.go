package handlers

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/adithyan-ak/agenthound/internal/graph"
	"github.com/adithyan-ak/agenthound/internal/model"
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
	if nodes == nil {
		nodes = []model.Node{}
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
	limit := parseIntParamWithMax(r, "limit", 100, maxEdgeQueryLimit)

	edges, err := h.reader.ListEdges(r.Context(), kind, source, target, limit)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("list edges: %w", err))
		return
	}
	if edges == nil {
		edges = []model.Edge{}
	}
	if len(edges) >= limit {
		w.Header().Set("X-Truncated", "true")
	}
	WriteJSON(w, http.StatusOK, edges)
}

func (h *GraphHandler) HandleSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if len(q) < 2 {
		WriteValidationError(w, "q must be at least 2 characters")
		return
	}
	limit := parseIntParamWithMax(r, "limit", 20, 100)

	results, err := h.reader.SearchNodes(r.Context(), q, limit)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("search nodes: %w", err))
		return
	}
	if results == nil {
		results = []graph.SearchResult{}
	}
	WriteJSON(w, http.StatusOK, results)
}

func (h *GraphHandler) HandleNeighborhood(w http.ResponseWriter, r *http.Request) {
	raw := chi.URLParam(r, "id")
	id, err := url.PathUnescape(raw)
	if err != nil {
		WriteValidationError(w, "invalid node id")
		return
	}
	depth := parseIntParamWithMax(r, "depth", 1, 3)

	nodes, edges, err := h.reader.GetNeighborhood(r.Context(), id, depth)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("get neighborhood: %w", err))
		return
	}
	if nodes == nil {
		WriteNotFound(w, "node not found")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"nodes": nodes,
		"edges": edges,
	})
}

func (h *GraphHandler) HandleBlastRadius(w http.ResponseWriter, r *http.Request) {
	raw := chi.URLParam(r, "id")
	id, err := url.PathUnescape(raw)
	if err != nil {
		WriteValidationError(w, "invalid node id")
		return
	}

	direction := r.URL.Query().Get("direction")
	if direction == "" {
		direction = "out"
	}
	switch direction {
	case "out", "in", "both":
	default:
		WriteValidationError(w, "direction must be one of: out, in, both")
		return
	}

	maxHops := parseIntParamWithMax(r, "max_hops", 6, 10)

	result, err := h.reader.GetBlastRadius(r.Context(), id, direction, maxHops)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("get blast radius: %w", err))
		return
	}
	if result == nil {
		WriteNotFound(w, "node not found")
		return
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"nodes":     result.Nodes,
		"edges":     result.Edges,
		"rings":     result.Rings,
		"direction": direction,
		"max_hops":  maxHops,
	})
}

const (
	maxQueryLimit     = 10000
	maxEdgeQueryLimit = 100000
)

func parseIntParam(r *http.Request, key string, defaultVal int) int {
	return parseIntParamWithMax(r, key, defaultVal, maxQueryLimit)
}

func parseIntParamWithMax(r *http.Request, key string, defaultVal, maxVal int) int {
	s := r.URL.Query().Get(key)
	if s == "" {
		return defaultVal
	}
	v, err := strconv.Atoi(s)
	if err != nil || v <= 0 {
		return defaultVal
	}
	if v > maxVal {
		return maxVal
	}
	return v
}
