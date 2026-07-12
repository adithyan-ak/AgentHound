package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/adithyan-ak/agenthound/server/internal/appdb"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/adithyan-ak/agenthound/server/internal/ingest"
	"github.com/adithyan-ak/agenthound/server/model"
	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

type ScanHandler struct {
	scanStore    scanStore
	findingStore findingDeleter
	graphDB      graph.GraphDB
	// coord serializes the delete's graph mutation against ingest through the
	// shared pipeline coordinator, so a delete's generation-GC never races an
	// in-flight ingest's untagged writes. Nil disables coordination (tests /
	// no-pipeline deployments) — the delete then runs unserialized.
	coord *ingest.Coordinator
}

// SetCoordinator wires the shared ingest/delete coordinator (from the
// Pipeline) so scan deletion and ingest are mutually exclusive.
func (h *ScanHandler) SetCoordinator(c *ingest.Coordinator) { h.coord = c }

type scanStore interface {
	ListScans(ctx context.Context, limit, offset int) ([]model.Scan, error)
	GetScan(ctx context.Context, id string) (*model.Scan, error)
	CreateScan(ctx context.Context, scan *model.Scan) error
	DeleteScan(ctx context.Context, id string) error
	// CurrentScanForScope / PriorValidScanForScope / PromoteGeneration back
	// the generation-aware, rematerializing delete path.
	CurrentScanForScope(ctx context.Context, collector string) (*model.Scan, error)
	PriorValidScanForScope(ctx context.Context, collector, excludeID string) (*model.Scan, error)
	PromoteGeneration(ctx context.Context, scanID, collector string) error
	// MarkDeleting / MarkDeleteFailed persist the deletion lifecycle so an
	// interrupted delete is durably recoverable by an idempotent retry.
	MarkDeleting(ctx context.Context, id string) error
	MarkDeleteFailed(ctx context.Context, id string) error
	// ScansInDeleteState lists scans left in a non-terminal delete lifecycle,
	// used by RecoverPendingDeletes to finish interrupted deletes at startup.
	ScansInDeleteState(ctx context.Context) ([]model.Scan, error)
}

// findingDeleter removes a scan's persisted finding snapshot during a
// coordinated delete. Optional: a nil store skips finding cleanup (the scans
// FK cascade still removes rows on scan-row delete).
type findingDeleter interface {
	DeleteFindingsForScan(ctx context.Context, scanID string) error
}

func NewScanHandler(store *appdb.ScanStore, findingStore *appdb.FindingStore, graphDB graph.GraphDB) *ScanHandler {
	h := &ScanHandler{graphDB: graphDB}
	// Guard against typed-nil-in-interface so `h.scanStore != nil` etc. behave.
	if store != nil {
		h.scanStore = store
	}
	if findingStore != nil {
		h.findingStore = findingStore
	}
	return h
}

func (h *ScanHandler) HandleList(w http.ResponseWriter, r *http.Request) {
	limit := parseIntParam(r, "limit", 50)
	offset := parseIntParam(r, "offset", 0)

	scans, err := h.scanStore.ListScans(r.Context(), limit, offset)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("list scans: %w", err))
		return
	}
	if scans == nil {
		scans = []model.Scan{}
	}
	WriteJSON(w, http.StatusOK, scans)
}

func (h *ScanHandler) HandleGet(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		WriteValidationError(w, "scan id is required")
		return
	}
	scan, err := h.scanStore.GetScan(r.Context(), id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			WriteNotFound(w, "scan not found")
			return
		}
		WriteInternalError(w, r, fmt.Errorf("get scan: %w", err))
		return
	}
	WriteJSON(w, http.StatusOK, scan)
}

type createScanRequest struct {
	Collector string         `json:"collector"`
	Metadata  map[string]any `json:"metadata,omitempty"`
}

func (h *ScanHandler) HandleCreate(w http.ResponseWriter, r *http.Request) {
	var req createScanRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		WriteValidationError(w, "invalid request body")
		return
	}
	if req.Collector == "" {
		WriteValidationError(w, "collector is required")
		return
	}
	validCollectors := map[string]bool{"mcp": true, "a2a": true, "config": true}
	if !validCollectors[req.Collector] {
		WriteValidationError(w, "collector must be one of: mcp, a2a, config")
		return
	}

	scan := model.Scan{
		ID:        uuid.New().String(),
		Collector: req.Collector,
		Status:    model.ScanStatusPending,
		StartedAt: time.Now().UTC(),
		Metadata:  req.Metadata,
	}

	if err := h.scanStore.CreateScan(r.Context(), &scan); err != nil {
		WriteInternalError(w, r, fmt.Errorf("create scan: %w", err))
		return
	}

	WriteJSON(w, http.StatusCreated, scan)
}

// deletePreview describes the generation and observations a delete would
// affect, and the generation it would rematerialize as current. Returned by a
// GET-style `?preview=true` delete so an operator can see the blast radius
// before committing.
type deletePreview struct {
	ScanID                   string `json:"scan_id"`
	GenerationID             string `json:"generation_id"`
	IsCurrent                bool   `json:"is_current"`
	NodesAffected            int    `json:"nodes_affected"`
	EdgesAffected            int    `json:"edges_affected"`
	RematerializeScanID      string `json:"rematerialize_scan_id,omitempty"`
	RematerializeGeneration  string `json:"rematerialize_generation_id,omitempty"`
	RematerializeUnavailable bool   `json:"rematerialize_unavailable,omitempty"`
}

func (h *ScanHandler) HandleDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if id == "" {
		WriteValidationError(w, "scan id is required")
		return
	}
	preview := r.URL.Query().Get("preview") == "true"
	// Serialize the entire mutating delete, including scan/predecessor
	// resolution, against ingest. Resolving the predecessor before taking the
	// lock permits an ingest to promote a newer generation between lookup and
	// deletion, causing the wrong generation to be rematerialized.
	if !preview && h.coord != nil {
		h.coord.Lock()
		defer h.coord.Unlock()
	}

	scan, err := h.scanStore.GetScan(r.Context(), id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			WriteNotFound(w, "scan not found")
			return
		}
		WriteInternalError(w, r, fmt.Errorf("get scan: %w", err))
		return
	}

	// Compute the predecessor to rematerialize (same generation scope). Scope
	// (not collector) so a local bundle and a network sweep — both collector
	// "scan" — resolve to independent predecessors.
	prior, err := h.scanStore.PriorValidScanForScope(r.Context(), scanScopeKey(scan), scan.ID)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("resolve prior generation: %w", err))
		return
	}

	// Preview mode: report the affected generation/observations without
	// mutating anything.
	if preview {
		nodes, edges, err := h.countGenerationFacts(r.Context(), scan)
		if err != nil {
			WriteInternalError(w, r, err)
			return
		}
		pv := deletePreview{
			ScanID:        scan.ID,
			GenerationID:  scan.GenerationID,
			IsCurrent:     scan.IsCurrent,
			NodesAffected: nodes,
			EdgesAffected: edges,
		}
		if prior != nil {
			pv.RematerializeScanID = prior.ID
			pv.RematerializeGeneration = prior.GenerationID
		} else if scan.IsCurrent {
			// Deleting the only/current generation for this scope leaves no
			// prior to fall back to — disclose that a re-ingest is required.
			pv.RematerializeUnavailable = true
		}
		WriteJSON(w, http.StatusOK, pv)
		return
	}

	// Reject deletion of a non-terminal scan whose delete has not already
	// begun: its writes may still be in flight, so tearing down its generation
	// would race the ingest. A scan already in a delete lifecycle
	// (deleting/delete_failed) is always retryable regardless of status.
	inDeleteLifecycle := scan.DeleteState == model.DeleteStateDeleting || scan.DeleteState == model.DeleteStateFailed
	if !isTerminalScanStatus(scan.Status) && !inDeleteLifecycle {
		WriteError(w, http.StatusConflict, "SCAN_NOT_TERMINAL",
			"cannot delete a scan that is still "+scan.Status)
		return
	}

	if err := h.runDurableDelete(r.Context(), scan, prior); err != nil {
		WriteInternalError(w, r, err)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// runDurableDelete executes the recoverable, idempotent scan-delete sequence.
// Ordering is chosen so an interruption at ANY point is recoverable by a retry:
//
//  1. Persist the 'deleting' lifecycle BEFORE mutating the graph, so a crash
//     leaves a durable marker that the startup recovery sweep (or a re-issued
//     delete) resumes.
//  2. Remove this generation's graph contribution in ONE Neo4j transaction
//     (atomic + idempotent decrement/GC), scoped to its generation_id so facts
//     a later generation re-observed survive.
//  3. Drop the finding snapshot (idempotent).
//  4. Expose the prior valid generation as current (idempotent promotion). This
//     current-pointer exposure happens only AFTER the recoverable graph +
//     finding delete has completed.
//  5. Remove the scan row (idempotent).
//
// Any error marks the scan 'delete_failed' and returns, so a later retry
// resumes from the durable marker.
func (h *ScanHandler) runDurableDelete(ctx context.Context, scan, prior *model.Scan) error {
	if err := h.scanStore.MarkDeleting(ctx, scan.ID); err != nil {
		return fmt.Errorf("mark scan deleting: %w", err)
	}

	if err := h.deleteGenerationGraphData(ctx, scan); err != nil {
		h.markDeleteFailed(ctx, scan.ID)
		return err
	}

	if h.findingStore != nil {
		if err := h.findingStore.DeleteFindingsForScan(ctx, scan.ID); err != nil {
			h.markDeleteFailed(ctx, scan.ID)
			return fmt.Errorf("delete scan findings: %w", err)
		}
	}

	// Rematerialize the prior valid generation as current for this scope when
	// we just removed the current one. This is a true restore: the prior
	// generation's facts survived this generation's ingest (non-destructive
	// retention) and survive its deletion (the decrement only removed this
	// generation from shared facts' sets), so promoting the prior generation
	// brings back exactly its observed posture.
	if scan.IsCurrent && prior != nil {
		if err := h.scanStore.PromoteGeneration(ctx, prior.ID, scanScopeKey(prior)); err != nil {
			h.markDeleteFailed(ctx, scan.ID)
			return fmt.Errorf("rematerialize prior generation: %w", err)
		}
	}

	if err := h.scanStore.DeleteScan(ctx, scan.ID); err != nil {
		h.markDeleteFailed(ctx, scan.ID)
		return fmt.Errorf("delete scan: %w", err)
	}
	return nil
}

// markDeleteFailed records the failed lifecycle best-effort; a failure to record
// it is logged but not surfaced (the primary delete error is what matters).
func (h *ScanHandler) markDeleteFailed(ctx context.Context, id string) {
	if err := h.scanStore.MarkDeleteFailed(ctx, id); err != nil {
		slog.Warn("failed to record scan delete_failed state", "scan_id", id, "error", err)
	}
}

// RecoverPendingDeletes resumes any scan left in a non-terminal delete
// lifecycle ('deleting'/'delete_failed') — e.g. after a crash between the Neo4j
// graph mutation and the Postgres row removal. Each resume runs the same
// idempotent durable-delete sequence, serialized against ingest through the
// shared coordinator, so the current-generation pointer is only exposed once
// each interrupted delete is durably complete. Errors on individual scans are
// logged and do not abort the sweep (they stay marked for the next attempt).
func (h *ScanHandler) RecoverPendingDeletes(ctx context.Context) error {
	if h.scanStore == nil {
		return nil
	}
	pending, err := h.scanStore.ScansInDeleteState(ctx)
	if err != nil {
		return fmt.Errorf("recover pending deletes: %w", err)
	}
	for i := range pending {
		scan := pending[i]
		if h.coord != nil {
			h.coord.Lock()
		}
		prior, perr := h.scanStore.PriorValidScanForScope(ctx, scanScopeKey(&scan), scan.ID)
		if perr != nil {
			slog.Warn("recover pending delete: prior lookup failed", "scan_id", scan.ID, "error", perr)
		} else if derr := h.runDurableDelete(ctx, &scan, prior); derr != nil {
			slog.Warn("recover pending delete failed; will retry next sweep", "scan_id", scan.ID, "error", derr)
		} else {
			slog.Info("recovered interrupted scan delete", "scan_id", scan.ID)
		}
		if h.coord != nil {
			h.coord.Unlock()
		}
	}
	return nil
}

// isTerminalScanStatus reports whether a scan has reached a state where its
// generation is fully materialized (or definitively failed) and thus safe to
// delete.
func isTerminalScanStatus(status string) bool {
	switch status {
	case model.ScanStatusCompleted, model.ScanStatusCompletedWithErrors, model.ScanStatusFailed:
		return true
	default:
		return false
	}
}

// scanScopeKey returns the generation-scope key for a scan, preferring the
// explicit scope column and falling back to the collector for rows that
// predate it.
func scanScopeKey(scan *model.Scan) string {
	if scan.Scope != "" {
		return scan.Scope
	}
	return scan.Collector
}

// deleteGenerationGraphData removes ONE generation's contribution from the
// graph without destroying facts other generations still own. It is
// decremental, not a blunt scan_id / generation_id sweep:
//
//  1. Remove this generation from every fact's generations set. A fact shared
//     with another (e.g. prior, retained) generation keeps that attribution
//     and survives.
//  2. Delete edges whose generations set is now empty (owned by no generation).
//  3. Delete nodes whose generations set is now empty AND are edgeless, so a
//     node still referenced by a surviving generation's edges is kept.
//
// This is what makes the rematerializing delete a real restore: deleting the
// current generation leaves the prior generation's facts intact and current
// once it is re-promoted.
func (h *ScanHandler) deleteGenerationGraphData(ctx context.Context, scan *model.Scan) error {
	if h.graphDB == nil {
		return fmt.Errorf("delete scan graph data: graph database unavailable")
	}
	gen := scan.GenerationID
	if gen == "" {
		// A generationless (legacy) row cannot be decremented safely; fall
		// back to the scan_id sweep (also one transaction) so its facts are
		// still removed atomically.
		if err := h.graphDB.DeleteByScanIDTx(ctx, scan.ID); err != nil {
			return fmt.Errorf("delete generation graph data (legacy scan_id): %w", err)
		}
		return nil
	}
	// One transaction: decrement + GC edges then nodes atomically. Only facts
	// that carried $gen are touched (an in-flight ingest's untagged facts are
	// never matched), and a fact shared with another generation keeps its other
	// attribution and survives. Running both statements in one transaction
	// means an interruption rolls the whole decrement back, so a retry starts
	// from a consistent state.
	if err := h.graphDB.DeleteGenerationTx(ctx, gen); err != nil {
		return fmt.Errorf("decrement+gc generation graph data: %w", err)
	}
	return nil
}

// countGenerationFacts counts the facts a generation observed (membership),
// used by the delete preview to disclose the blast radius. Counts by
// generations-set membership so a shared fact is reported for this generation
// even though the delete will only decrement (not destroy) it.
func (h *ScanHandler) countGenerationFacts(ctx context.Context, scan *model.Scan) (nodes, edges int, err error) {
	if h.graphDB == nil {
		return 0, 0, fmt.Errorf("count generation facts: graph database unavailable")
	}
	if scan.GenerationID == "" {
		edgeRows, qerr := h.graphDB.Query(ctx,
			`MATCH ()-[r]->() WHERE r.scan_id = $value RETURN count(r) AS c`, map[string]any{"value": scan.ID})
		if qerr != nil {
			return 0, 0, fmt.Errorf("count generation edges: %w", qerr)
		}
		nodeRows, qerr := h.graphDB.Query(ctx,
			`MATCH (n) WHERE n.scan_id = $value RETURN count(n) AS c`, map[string]any{"value": scan.ID})
		if qerr != nil {
			return 0, 0, fmt.Errorf("count generation nodes: %w", qerr)
		}
		return firstIntColumn(nodeRows), firstIntColumn(edgeRows), nil
	}
	params := map[string]any{"gen": scan.GenerationID}
	edgeRows, err := h.graphDB.Query(ctx,
		`MATCH ()-[r]->() WHERE $gen IN coalesce(r.generations, []) RETURN count(r) AS c`, params)
	if err != nil {
		return 0, 0, fmt.Errorf("count generation edges: %w", err)
	}
	nodeRows, err := h.graphDB.Query(ctx,
		`MATCH (n) WHERE $gen IN coalesce(n.generations, []) RETURN count(n) AS c`, params)
	if err != nil {
		return 0, 0, fmt.Errorf("count generation nodes: %w", err)
	}
	return firstIntColumn(nodeRows), firstIntColumn(edgeRows), nil
}

// firstIntColumn reads the first integer-ish value from the first row of a
// count query result (0 when empty).
func firstIntColumn(rows []map[string]any) int {
	for _, row := range rows {
		for _, v := range row {
			switch n := v.(type) {
			case int64:
				return int(n)
			case int:
				return n
			case float64:
				return int(n)
			}
		}
	}
	return 0
}
