package handlers

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/adithyan-ak/agenthound/server/internal/appdb"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/adithyan-ak/agenthound/server/model"
	"github.com/jackc/pgx/v5/pgxpool"
)

// pinger abstracts a component health check so the export/freshness handlers
// can report degraded components without importing driver types directly.
type pinger interface {
	Ping(ctx context.Context) error
}

// DashboardHandler serves the lightweight generation-freshness poll and the
// server-side dashboard export. Both read from one promoted generation so the
// client never assembles a verdict from independently-fetched, possibly
// inconsistent parts.
type DashboardHandler struct {
	reader       *graph.Reader
	findingStore findingSource
	gens         generationLister
	pgPool       *pgxpool.Pool
}

func NewDashboardHandler(reader *graph.Reader, findingStore *appdb.FindingStore, scanStore *appdb.ScanStore, pgPool *pgxpool.Pool) *DashboardHandler {
	h := &DashboardHandler{reader: reader, pgPool: pgPool}
	if findingStore != nil {
		h.findingStore = findingStore
	}
	if scanStore != nil {
		h.gens = scanStore
	}
	return h
}

// freshnessResponse is the cheap poll payload: current generation identity and
// completeness derived from Postgres only, so the UI can detect a new promoted
// generation without re-fetching the whole graph.
type freshnessResponse struct {
	Completeness Completeness        `json:"completeness"`
	Generations  []generationSummary `json:"generations"`
}

type generationSummary struct {
	ScanID         string     `json:"scan_id"`
	Collector      string     `json:"collector"`
	GenerationID   string     `json:"generation_id"`
	CoverageStatus string     `json:"coverage_status"`
	NodeCount      int        `json:"node_count"`
	EdgeCount      int        `json:"edge_count"`
	CapturedAt     *time.Time `json:"captured_at,omitempty"`
	CompletedAt    *time.Time `json:"completed_at,omitempty"`
}

// HandleFreshness returns the current promoted generations and completeness
// without touching Neo4j — a cheap endpoint for polling instead of re-reading
// the full graph.
func (h *DashboardHandler) HandleFreshness(w http.ResponseWriter, r *http.Request) {
	if h.gens == nil {
		WriteServiceError(w, "scan store")
		return
	}
	scanStore, ok := h.gens.(*appdb.ScanStore)
	if !ok {
		WriteServiceError(w, "scan store")
		return
	}
	scans, err := scanStore.CurrentGenerations(r.Context())
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("current generations: %w", err))
		return
	}
	deleting, err := scanStore.CurrentDeletingGenerations(r.Context())
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("current deleting generations: %w", err))
		return
	}
	// Fold delete-lifecycle scopes into completeness so a scope stuck
	// mid-delete is disclosed as a blocker rather than silently dropped
	// (which could report a false all-clear).
	scope := applyDeleteBlockers(scopeFromScans(scans), deleting)
	resp := freshnessResponse{Completeness: scope.Completeness, Generations: []generationSummary{}}
	for i := range scans {
		s := scans[i]
		resp.Generations = append(resp.Generations, generationSummary{
			ScanID:         s.ID,
			Collector:      s.Collector,
			GenerationID:   s.GenerationID,
			CoverageStatus: string(s.CoverageStatus),
			NodeCount:      s.NodeCount,
			EdgeCount:      s.EdgeCount,
			CapturedAt:     s.CapturedAt,
			CompletedAt:    s.CompletedAt,
		})
	}
	WriteJSON(w, http.StatusOK, resp)
}

// suppressionPolicy documents which triage statuses hide a finding from the
// export's default view and whether this export included them.
type suppressionPolicy struct {
	SuppressedStatuses []string `json:"suppressed_statuses"`
	IncludeSuppressed  bool     `json:"include_suppressed"`
}

// exportResponse is the server-side dashboard export. It is generated from one
// promoted generation and carries scope + completeness, the suppression
// policy, component health, the generated time, the scoped graph stats, and
// every finding with its full ATLAS/OWASP metadata.
type exportResponse struct {
	GeneratedAt       time.Time         `json:"generated_at"`
	Scope             Completeness      `json:"scope"`
	SuppressionPolicy suppressionPolicy `json:"suppression_policy"`
	Health            map[string]string `json:"health"`
	Stats             *graph.GraphStats `json:"stats"`
	Findings          []model.Finding   `json:"findings"`
}

// HandleExport builds the dashboard export server-side from the current
// promoted generation.
func (h *DashboardHandler) HandleExport(w http.ResponseWriter, r *http.Request) {
	includeSuppressed := r.URL.Query().Get("include_suppressed") == "true"

	scope, err := resolveGenerationScope(r.Context(), h.gens)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("resolve generation scope: %w", err))
		return
	}

	resp := exportResponse{
		GeneratedAt: time.Now().UTC(),
		Scope:       scope.Completeness,
		SuppressionPolicy: suppressionPolicy{
			SuppressedStatuses: []string{"accepted-risk", "false-positive"},
			IncludeSuppressed:  includeSuppressed,
		},
		Health:   h.componentHealth(r.Context()),
		Findings: []model.Finding{},
	}

	// Stats + findings are scoped to the promoted generations; when nothing is
	// promoted the export is explicitly incomplete with an empty finding set.
	if len(scope.GenerationIDs) > 0 && h.reader != nil {
		stats, err := h.reader.GetStatsScoped(r.Context(), scope.GenerationIDs)
		if err != nil {
			WriteInternalError(w, r, fmt.Errorf("export stats: %w", err))
			return
		}
		resp.Stats = stats
	}
	if h.findingStore != nil {
		items, _, err := h.findingStore.ListCurrentFindings(r.Context(), appdb.FindingQuery{
			GenerationIDs:     scope.GenerationIDs,
			IncludeSuppressed: includeSuppressed,
			Limit:             100000,
		})
		if err != nil {
			WriteInternalError(w, r, fmt.Errorf("export findings: %w", err))
			return
		}
		if items != nil {
			resp.Findings = items
		}
	}

	WriteJSON(w, http.StatusOK, resp)
}

// componentHealth pings Neo4j and Postgres, surfacing per-component degraded
// truth in the export rather than a single collapsed boolean.
func (h *DashboardHandler) componentHealth(ctx context.Context) map[string]string {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	health := map[string]string{}
	if h.reader != nil {
		if err := h.reader.Ping(ctx); err != nil {
			health["neo4j"] = "unavailable"
		} else {
			health["neo4j"] = "ok"
		}
	}
	if h.pgPool != nil {
		if err := h.pgPool.Ping(ctx); err != nil {
			health["postgres"] = "unavailable"
		} else {
			health["postgres"] = "ok"
		}
	}
	return health
}

var _ pinger = (*graph.Reader)(nil)
