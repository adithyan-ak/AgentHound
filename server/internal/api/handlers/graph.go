package handlers

import (
	"context"
	"errors"
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
	reader           graphReader
	projectionReader projectionStateReader
}

type graphReader interface {
	GetStats(ctx context.Context) (*graph.GraphStats, error)
	ListNodesPage(ctx context.Context, kind string, limit, offset int, revision string) ([]ingest.Node, graph.PageInfo, error)
	GetNode(ctx context.Context, objectID string) (*ingest.Node, []ingest.Edge, error)
	ListEdgesPage(ctx context.Context, kind, sourceID, targetID string, limit, offset int, revision string) ([]ingest.Edge, graph.PageInfo, error)
	SearchNodes(ctx context.Context, query string, limit int) ([]graph.SearchResult, error)
	GetNeighborhood(ctx context.Context, objectID string, depth int) ([]ingest.Node, []ingest.Edge, error)
	GetBlastRadius(ctx context.Context, objectID, direction string, maxHops int) (*graph.BlastRadiusResult, error)
}

type pageMetadata struct {
	Offset     int                 `json:"offset"`
	Limit      int                 `json:"limit"`
	Total      int64               `json:"total"`
	HasMore    bool                `json:"has_more"`
	Complete   bool                `json:"complete"`
	Revision   string              `json:"revision"`
	Projection *projectionIdentity `json:"projection,omitempty"`
}

type nodeListResponse struct {
	Nodes []ingest.Node `json:"nodes"`
	Page  pageMetadata  `json:"page"`
}

type edgeListResponse struct {
	Edges []ingest.Edge `json:"edges"`
	Page  pageMetadata  `json:"page"`
}

func NewGraphHandler(reader *graph.Reader, store *appdb.FindingStore) *GraphHandler {
	handler := &GraphHandler{reader: reader}
	if store != nil {
		handler.projectionReader = store
	}
	return handler
}

func (h *GraphHandler) HandleStats(w http.ResponseWriter, r *http.Request) {
	stats, projection, err := guardedProjectionRead(
		r.Context(),
		h.projectionReader,
		func() (*graph.GraphStats, error) {
			return h.reader.GetStats(r.Context())
		},
	)
	if err != nil {
		if writeProjectionConflict(w, err) {
			return
		}
		WriteInternalError(w, r, err)
		return
	}
	WriteJSON(w, http.StatusOK, struct {
		*graph.GraphStats
		Projection projectionIdentity `json:"projection"`
	}{
		GraphStats: stats,
		Projection: projection,
	})
}

func (h *GraphHandler) HandleListNodes(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	limit := parseIntParam(r, "limit", 100)
	offset := parseOffsetParam(r, "offset")
	revision := r.URL.Query().Get("revision")

	type nodePageRead struct {
		nodes []ingest.Node
		page  graph.PageInfo
	}
	result, projection, err := guardedProjectionRead(
		r.Context(),
		h.projectionReader,
		func() (nodePageRead, error) {
			nodes, page, err := h.reader.ListNodesPage(
				r.Context(), kind, limit, offset, revision,
			)
			return nodePageRead{nodes: nodes, page: page}, err
		},
	)
	if err != nil {
		if writeProjectionConflict(w, err) {
			return
		}
		if writeRevisionConflict(w, err) {
			return
		}
		WriteInternalError(w, r, fmt.Errorf("list nodes: %w", err))
		return
	}
	if result.nodes == nil {
		result.nodes = []ingest.Node{}
	}
	WriteJSON(w, http.StatusOK, nodeListResponse{
		Nodes: result.nodes,
		Page:  graphPageMetadata(result.page, projection),
	})
}

func (h *GraphHandler) HandleGetNode(w http.ResponseWriter, r *http.Request) {
	raw := chi.URLParam(r, "id")
	id, err := url.PathUnescape(raw)
	if err != nil {
		WriteValidationError(w, "invalid node id")
		return
	}
	type nodeRead struct {
		node  *ingest.Node
		edges []ingest.Edge
	}
	result, _, err := guardedProjectionRead(
		r.Context(),
		h.projectionReader,
		func() (nodeRead, error) {
			node, edges, err := h.reader.GetNode(r.Context(), id)
			return nodeRead{node: node, edges: edges}, err
		},
	)
	if err != nil {
		if writeProjectionConflict(w, err) {
			return
		}
		WriteInternalError(w, r, err)
		return
	}
	if result.node == nil {
		WriteNotFound(w, "node not found")
		return
	}
	if result.edges == nil {
		result.edges = []ingest.Edge{}
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"node":  result.node,
		"edges": result.edges,
	})
}

func (h *GraphHandler) HandleListEdges(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	source := r.URL.Query().Get("source")
	target := r.URL.Query().Get("target")
	limit := parseIntParamWithMax(r, "limit", 100, maxEdgeQueryLimit)
	offset := parseOffsetParam(r, "offset")
	revision := r.URL.Query().Get("revision")

	type edgePageRead struct {
		edges []ingest.Edge
		page  graph.PageInfo
	}
	result, projection, err := guardedProjectionRead(
		r.Context(),
		h.projectionReader,
		func() (edgePageRead, error) {
			edges, page, err := h.reader.ListEdgesPage(
				r.Context(), kind, source, target, limit, offset, revision,
			)
			return edgePageRead{edges: edges, page: page}, err
		},
	)
	if err != nil {
		if writeProjectionConflict(w, err) {
			return
		}
		if writeRevisionConflict(w, err) {
			return
		}
		WriteInternalError(w, r, fmt.Errorf("list edges: %w", err))
		return
	}
	if result.edges == nil {
		result.edges = []ingest.Edge{}
	}
	WriteJSON(w, http.StatusOK, edgeListResponse{
		Edges: result.edges,
		Page:  graphPageMetadata(result.page, projection),
	})
}

func (h *GraphHandler) HandleSearch(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	if len(q) < 2 {
		WriteValidationError(w, "q must be at least 2 characters")
		return
	}
	limit := parseIntParamWithMax(r, "limit", defaultGraphSearchLimit, maxGraphSearchLimit)

	results, _, err := guardedProjectionRead(
		r.Context(),
		h.projectionReader,
		func() ([]graph.SearchResult, error) {
			return h.reader.SearchNodes(r.Context(), q, limit)
		},
	)
	if err != nil {
		if writeProjectionConflict(w, err) {
			return
		}
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

	type neighborhoodRead struct {
		nodes []ingest.Node
		edges []ingest.Edge
	}
	result, _, err := guardedProjectionRead(
		r.Context(),
		h.projectionReader,
		func() (neighborhoodRead, error) {
			nodes, edges, err := h.reader.GetNeighborhood(r.Context(), id, depth)
			return neighborhoodRead{nodes: nodes, edges: edges}, err
		},
	)
	if err != nil {
		if writeProjectionConflict(w, err) {
			return
		}
		WriteInternalError(w, r, fmt.Errorf("get neighborhood: %w", err))
		return
	}
	if result.nodes == nil {
		WriteNotFound(w, "node not found")
		return
	}
	if result.edges == nil {
		result.edges = []ingest.Edge{}
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"nodes": result.nodes,
		"edges": result.edges,
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

	maxHops := parseIntParamWithMax(r, "max_hops", defaultBlastRadiusMaxHops, maxBlastRadiusMaxHops)

	result, _, err := guardedProjectionRead(
		r.Context(),
		h.projectionReader,
		func() (*graph.BlastRadiusResult, error) {
			return h.reader.GetBlastRadius(r.Context(), id, direction, maxHops)
		},
	)
	if err != nil {
		if writeProjectionConflict(w, err) {
			return
		}
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
	maxQueryLimit             = 10000
	maxEdgeQueryLimit         = 100000
	defaultGraphSearchLimit   = 20
	maxGraphSearchLimit       = 100
	defaultBlastRadiusMaxHops = 6
	maxBlastRadiusMaxHops     = 10
)

func graphPageMetadata(page graph.PageInfo, projection projectionIdentity) pageMetadata {
	return pageMetadata{
		Offset:     page.Offset,
		Limit:      page.Limit,
		Total:      page.Total,
		HasMore:    page.HasMore,
		Complete:   page.Complete,
		Revision:   page.Revision,
		Projection: &projection,
	}
}

func writeRevisionConflict(w http.ResponseWriter, err error) bool {
	var mismatch *graph.RevisionMismatchError
	if !errors.As(err, &mismatch) {
		return false
	}
	WriteJSON(w, http.StatusConflict, ErrorResponse{
		Error: ErrorDetail{
			Code:    "REVISION_CONFLICT",
			Message: "collection changed during pagination; restart from offset 0",
			Details: revisionConflictDetails{
				ExpectedRevision: mismatch.Expected,
				ActualRevision:   mismatch.Actual,
			},
		},
	})
	return true
}

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

func parseOffsetParam(r *http.Request, key string) int {
	s := r.URL.Query().Get(key)
	if s == "" {
		return 0
	}
	v, err := strconv.Atoi(s)
	if err != nil || v < 0 {
		return 0
	}
	return v
}
