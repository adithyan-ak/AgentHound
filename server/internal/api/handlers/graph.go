package handlers

import (
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/appdb"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/go-chi/chi/v5"
)

type GraphHandler struct {
	reader *graph.Reader
	gens   generationLister
}

func NewGraphHandler(reader *graph.Reader, scanStore *appdb.ScanStore) *GraphHandler {
	h := &GraphHandler{reader: reader}
	if scanStore != nil {
		h.gens = scanStore
	}
	return h
}

// graphStatsResponse wraps the raw counts with completeness so a client never
// treats totals over a partial/staged view as authoritative.
type graphStatsResponse struct {
	Stats        *graph.GraphStats `json:"stats"`
	Completeness Completeness      `json:"completeness"`
}

func (h *GraphHandler) HandleStats(w http.ResponseWriter, r *http.Request) {
	scope, err := resolveGenerationScope(r.Context(), h.gens)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("resolve generation scope: %w", err))
		return
	}
	// No promoted generation → do not surface staged facts; return zeroed
	// stats with an explicit incomplete disclosure.
	if h.gens != nil && len(scope.GenerationIDs) == 0 {
		WriteJSON(w, http.StatusOK, graphStatsResponse{
			Stats:        &graph.GraphStats{NodeCounts: map[string]int64{}, EdgeCounts: map[string]int64{}},
			Completeness: scope.Completeness,
		})
		return
	}
	stats, err := h.reader.GetStatsScoped(r.Context(), scope.GenerationIDs)
	if err != nil {
		WriteInternalError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, graphStatsResponse{Stats: stats, Completeness: scope.Completeness})
}

func (h *GraphHandler) HandleListNodes(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	limit := parseIntParam(r, "limit", 100)
	offset := parseIntParam(r, "offset", 0)

	scope, err := resolveGenerationScope(r.Context(), h.gens)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("resolve generation scope: %w", err))
		return
	}
	if h.gens != nil && len(scope.GenerationIDs) == 0 {
		WriteJSON(w, http.StatusOK, newPage([]ingest.Node{}, 0, limit, offset, scope.Completeness))
		return
	}

	nodes, err := h.reader.ListNodesPage(r.Context(), kind, limit, offset, scope.GenerationIDs)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("list nodes: %w", err))
		return
	}
	if nodes == nil {
		nodes = []ingest.Node{}
	}
	c := scope.Completeness
	if len(nodes) >= limit {
		c.Truncated = true
	}
	// A page-level read cannot know the scoped grand total without a count
	// query, so total is reported as offset+len when a short page proves
	// exhaustion, else suppressed via incomplete truncation disclosure.
	total := offset + len(nodes)
	WriteJSON(w, http.StatusOK, newGraphPage(nodes, total, limit, offset, c))
}

func (h *GraphHandler) HandleGetNode(w http.ResponseWriter, r *http.Request) {
	raw := chi.URLParam(r, "id")
	id, err := url.PathUnescape(raw)
	if err != nil {
		WriteValidationError(w, "invalid node id")
		return
	}
	scope, err := resolveGenerationScope(r.Context(), h.gens)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("resolve generation scope: %w", err))
		return
	}
	// No promoted generation → nothing is current, so a detail read must not
	// surface a staged/retained node.
	if h.gens != nil && len(scope.GenerationIDs) == 0 {
		WriteNotFound(w, "node not found")
		return
	}

	node, edges, err := h.reader.GetNode(r.Context(), id, scope.GenerationIDs)
	if err != nil {
		WriteInternalError(w, r, err)
		return
	}
	if node == nil {
		WriteNotFound(w, "node not found")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"node":         node,
		"edges":        edges,
		"completeness": scope.Completeness,
	})
}

func (h *GraphHandler) HandleListEdges(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	source := r.URL.Query().Get("source")
	target := r.URL.Query().Get("target")
	limit := parseIntParamWithMax(r, "limit", 100, maxEdgeQueryLimit)
	offset := parseIntParam(r, "offset", 0)

	scope, err := resolveGenerationScope(r.Context(), h.gens)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("resolve generation scope: %w", err))
		return
	}
	if h.gens != nil && len(scope.GenerationIDs) == 0 {
		WriteJSON(w, http.StatusOK, newGraphPage([]ingest.Edge{}, 0, limit, offset, scope.Completeness))
		return
	}

	edges, err := h.reader.ListEdgesPage(r.Context(), kind, source, target, limit, offset, scope.GenerationIDs)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("list edges: %w", err))
		return
	}
	if edges == nil {
		edges = []ingest.Edge{}
	}
	c := scope.Completeness
	if len(edges) >= limit {
		c.Truncated = true
		w.Header().Set("X-Truncated", "true")
	}
	WriteJSON(w, http.StatusOK, newGraphPage(edges, offset+len(edges), limit, offset, c))
}

func (h *GraphHandler) HandleSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if len(q) < 2 {
		WriteValidationError(w, "q must be at least 2 characters")
		return
	}
	limit := parseIntParamWithMax(r, "limit", 20, 100)

	scope, err := resolveGenerationScope(r.Context(), h.gens)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("resolve generation scope: %w", err))
		return
	}
	if h.gens != nil && len(scope.GenerationIDs) == 0 {
		WriteJSON(w, http.StatusOK, []graph.SearchResult{})
		return
	}

	results, err := h.reader.SearchNodes(r.Context(), q, limit, scope.GenerationIDs)
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

	scope, err := resolveGenerationScope(r.Context(), h.gens)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("resolve generation scope: %w", err))
		return
	}
	if h.gens != nil && len(scope.GenerationIDs) == 0 {
		WriteNotFound(w, "node not found")
		return
	}

	nodes, edges, err := h.reader.GetNeighborhood(r.Context(), id, depth, scope.GenerationIDs)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("get neighborhood: %w", err))
		return
	}
	if nodes == nil {
		WriteNotFound(w, "node not found")
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"nodes":        nodes,
		"edges":        edges,
		"completeness": scope.Completeness,
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

	scope, err := resolveGenerationScope(r.Context(), h.gens)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("resolve generation scope: %w", err))
		return
	}
	if h.gens != nil && len(scope.GenerationIDs) == 0 {
		WriteNotFound(w, "node not found")
		return
	}

	result, err := h.reader.GetBlastRadius(r.Context(), id, direction, maxHops, scope.GenerationIDs)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("get blast radius: %w", err))
		return
	}
	if result == nil {
		WriteNotFound(w, "node not found")
		return
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"nodes":        result.Nodes,
		"edges":        result.Edges,
		"rings":        result.Rings,
		"direction":    direction,
		"max_hops":     maxHops,
		"completeness": scope.Completeness,
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
