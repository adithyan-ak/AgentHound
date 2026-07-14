package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	"github.com/adithyan-ak/agenthound/sdk/campaign"
	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/analysis"
	"github.com/adithyan-ak/agenthound/server/internal/analysis/prebuilt"
	"github.com/adithyan-ak/agenthound/server/internal/appdb"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/adithyan-ak/agenthound/server/model"
	"github.com/go-chi/chi/v5"
)

type publishedFindingStore interface {
	ListPublished(ctx context.Context, severity string, includeSuppressed bool) ([]model.Finding, appdb.FindingScope, error)
	GetPublished(ctx context.Context, fingerprint string) (*model.Finding, appdb.FindingScope, error)
}

type AnalysisHandler struct {
	graphDB          graph.GraphDB
	findingStore     publishedFindingStore
	projectionReader projectionStateReader
}

func NewAnalysisHandler(db graph.GraphDB, findingStore *appdb.FindingStore) *AnalysisHandler {
	h := &AnalysisHandler{graphDB: db}
	if findingStore != nil {
		h.findingStore = findingStore
		h.projectionReader = findingStore
	}
	return h
}

var allowedNodeLabels = func() map[string]bool {
	m := make(map[string]bool, len(ingest.AllowedNodeKinds))
	for label := range ingest.AllowedNodeKinds {
		m[label] = true
	}
	return m
}()

func validNodeKind(kind string) bool {
	return allowedNodeLabels[kind]
}

type pathRequest struct {
	Source     string `json:"source"`
	Target     string `json:"target"`
	SourceKind string `json:"source_kind"`
	TargetKind string `json:"target_kind"`
	MaxHops    int    `json:"max_hops"`
	Limit      int    `json:"limit"`
}

func (h *AnalysisHandler) HandleShortestPath(w http.ResponseWriter, r *http.Request) {
	h.handleShortestPath(w, r, analysis.TraversalScopeSecurity)
}

func (h *AnalysisHandler) HandleTopologyShortestPath(w http.ResponseWriter, r *http.Request) {
	h.handleShortestPath(w, r, analysis.TraversalScopeTopology)
}

func (h *AnalysisHandler) handleShortestPath(
	w http.ResponseWriter,
	r *http.Request,
	scope analysis.TraversalScope,
) {
	var req pathRequest
	if err := DecodeStrictJSON(r.Body, &req); err != nil {
		WriteValidationError(w, "invalid JSON: "+err.Error())
		return
	}
	if req.Source == "" || req.SourceKind == "" {
		WriteValidationError(w, "source and source_kind are required")
		return
	}
	if !validNodeKind(req.SourceKind) {
		WriteValidationError(w, "invalid source_kind: "+req.SourceKind)
		return
	}

	targetKind, targetName := parseTarget(req.Target, req.TargetKind)
	if targetKind != "" && !validNodeKind(targetKind) {
		WriteValidationError(w, "invalid target_kind: "+targetKind)
		return
	}

	result, projection, err := guardedProjectionRead(
		r.Context(),
		h.projectionReader,
		func() (analysis.TraversalResult, error) {
			sources, targets, err := h.resolveTraversalEndpoints(
				r.Context(), req, targetKind, targetName,
			)
			if err != nil {
				return analysis.TraversalResult{}, fmt.Errorf("resolve shortest path endpoints: %w", err)
			}
			return analysis.FindBoundedTraversalPaths(
				r.Context(),
				h.graphDB,
				sources,
				targets,
				analysis.TraversalOptions{
					Scope: scope, Cost: analysis.TraversalCostHops,
					MaxHops: clamp(req.MaxHops, 1, 20, 10),
					Limit:   10, MaxExpansions: 100000,
				},
			)
		},
	)
	if err != nil {
		if writeProjectionConflict(w, err) {
			return
		}
		WriteInternalError(w, r, fmt.Errorf("shortest path query: %w", err))
		return
	}
	writeTraversalResult(w, result, projection)
}

func (h *AnalysisHandler) HandleAllPaths(w http.ResponseWriter, r *http.Request) {
	h.handleAllPaths(w, r, analysis.TraversalScopeSecurity)
}

func (h *AnalysisHandler) HandleTopologyAllPaths(w http.ResponseWriter, r *http.Request) {
	h.handleAllPaths(w, r, analysis.TraversalScopeTopology)
}

func (h *AnalysisHandler) handleAllPaths(
	w http.ResponseWriter,
	r *http.Request,
	scope analysis.TraversalScope,
) {
	var req pathRequest
	if err := DecodeStrictJSON(r.Body, &req); err != nil {
		WriteValidationError(w, "invalid JSON: "+err.Error())
		return
	}
	if req.Source == "" || req.SourceKind == "" {
		WriteValidationError(w, "source and source_kind are required")
		return
	}
	if !validNodeKind(req.SourceKind) {
		WriteValidationError(w, "invalid source_kind: "+req.SourceKind)
		return
	}

	targetKind, targetName := parseTarget(req.Target, req.TargetKind)
	if targetKind != "" && !validNodeKind(targetKind) {
		WriteValidationError(w, "invalid target_kind: "+targetKind)
		return
	}

	result, projection, err := guardedProjectionRead(
		r.Context(),
		h.projectionReader,
		func() (analysis.TraversalResult, error) {
			sources, targets, err := h.resolveTraversalEndpoints(
				r.Context(), req, targetKind, targetName,
			)
			if err != nil {
				return analysis.TraversalResult{}, fmt.Errorf("resolve all path endpoints: %w", err)
			}
			return analysis.FindBoundedTraversalPaths(
				r.Context(),
				h.graphDB,
				sources,
				targets,
				analysis.TraversalOptions{
					Scope: scope, Cost: analysis.TraversalCostHops,
					MaxHops:       clamp(req.MaxHops, 1, 20, 10),
					Limit:         clamp(req.Limit, 1, 100, 10),
					MaxExpansions: 100000, AllPaths: true,
				},
			)
		},
	)
	if err != nil {
		if writeProjectionConflict(w, err) {
			return
		}
		WriteInternalError(w, r, fmt.Errorf("all paths query: %w", err))
		return
	}
	writeTraversalResult(w, result, projection)
}

func (h *AnalysisHandler) HandleWeightedPath(w http.ResponseWriter, r *http.Request) {
	h.handleWeightedPath(w, r, analysis.TraversalScopeSecurity)
}

func (h *AnalysisHandler) HandleTopologyWeightedPath(w http.ResponseWriter, r *http.Request) {
	h.handleWeightedPath(w, r, analysis.TraversalScopeTopology)
}

func (h *AnalysisHandler) handleWeightedPath(
	w http.ResponseWriter,
	r *http.Request,
	scope analysis.TraversalScope,
) {
	var req pathRequest
	if err := DecodeStrictJSON(r.Body, &req); err != nil {
		WriteValidationError(w, "invalid JSON: "+err.Error())
		return
	}
	if req.Source == "" || req.Target == "" || req.SourceKind == "" {
		WriteValidationError(w, "source, target, and source_kind are required")
		return
	}
	if !validNodeKind(req.SourceKind) {
		WriteValidationError(w, "invalid source_kind: "+req.SourceKind)
		return
	}

	targetKind, targetName := parseTarget(req.Target, req.TargetKind)
	if targetKind != "" && !validNodeKind(targetKind) {
		WriteValidationError(w, "invalid target_kind: "+targetKind)
		return
	}
	if targetName == "" {
		WriteValidationError(w, "target name is required")
		return
	}

	result, projection, err := guardedProjectionRead(
		r.Context(),
		h.projectionReader,
		func() (analysis.TraversalResult, error) {
			sources, targets, err := h.resolveTraversalEndpoints(
				r.Context(), req, targetKind, targetName,
			)
			if err != nil {
				return analysis.TraversalResult{}, fmt.Errorf("resolve weighted path endpoints: %w", err)
			}
			return analysis.FindBoundedTraversalPaths(
				r.Context(),
				h.graphDB,
				sources,
				targets,
				analysis.TraversalOptions{
					Scope: scope, Cost: analysis.TraversalCostRisk,
					MaxHops:       clamp(req.MaxHops, 1, 20, 10),
					Limit:         clamp(req.Limit, 1, 100, 10),
					MaxExpansions: 100000,
				},
			)
		},
	)
	if err != nil {
		if writeProjectionConflict(w, err) {
			return
		}
		WriteInternalError(w, r, fmt.Errorf("weighted path query: %w", err))
		return
	}
	writeTraversalResult(w, result, projection)
}

func (h *AnalysisHandler) resolveTraversalEndpoints(
	ctx context.Context,
	req pathRequest,
	targetKind, targetName string,
) ([]analysis.TraversalNode, []analysis.TraversalNode, error) {
	sourceValue := req.Source
	sources, err := analysis.ResolveTraversalNodes(ctx, h.graphDB, analysis.TraversalSelector{
		Kind:     req.SourceKind,
		Property: nodeMatchProp(req.Source),
		Value:    &sourceValue,
	})
	if err != nil {
		return nil, nil, err
	}

	targetSelector := analysis.TraversalSelector{Kind: targetKind}
	if targetName != "" {
		targetValue := targetName
		targetSelector.Property = nodeMatchProp(targetName)
		targetSelector.Value = &targetValue
	}
	targets, err := analysis.ResolveTraversalNodes(ctx, h.graphDB, targetSelector)
	if err != nil {
		return nil, nil, err
	}
	return sources, targets, nil
}

func writeTraversalResult(
	w http.ResponseWriter,
	result analysis.TraversalResult,
	projection projectionIdentity,
) {
	if result.Paths == nil {
		result.Paths = []analysis.TraversalPath{}
	}
	WriteJSON(w, http.StatusOK, struct {
		Paths      []analysis.TraversalPath   `json:"paths"`
		Metadata   analysis.TraversalMetadata `json:"metadata"`
		Projection projectionIdentity         `json:"projection"`
	}{
		Paths:      result.Paths,
		Metadata:   result.Metadata,
		Projection: projection,
	})
}

func (h *AnalysisHandler) HandleFindings(w http.ResponseWriter, r *http.Request) {
	severity := r.URL.Query().Get("severity")
	switch severity {
	case "", "critical", "high", "medium", "low":
	default:
		WriteValidationError(w, "severity must be one of: critical, high, medium, low")
		return
	}
	includeSuppressedValue := r.URL.Query().Get("include_suppressed")
	if includeSuppressedValue != "" &&
		includeSuppressedValue != "true" &&
		includeSuppressedValue != "false" {
		WriteValidationError(w, "include_suppressed must be true or false")
		return
	}
	includeSuppressed := includeSuppressedValue == "true"
	if r.URL.Query().Has("scope") {
		WriteValidationError(w, "scope is not supported; findings are always read from the published snapshot")
		return
	}
	if h.findingStore == nil {
		WriteServiceError(w, "published finding store")
		return
	}
	findings, scope, err := h.findingStore.ListPublished(
		r.Context(), severity, includeSuppressed,
	)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("findings query: %w", err))
		return
	}
	if findings == nil {
		findings = []model.Finding{}
	}
	WriteJSON(w, http.StatusOK, struct {
		Findings []model.Finding    `json:"findings"`
		Scope    appdb.FindingScope `json:"scope"`
	}{
		Findings: findings,
		Scope:    scope,
	})
}

func (h *AnalysisHandler) HandleFindingDetail(w http.ResponseWriter, r *http.Request) {
	findingID := chi.URLParam(r, "id")
	if len(findingID) != 16 {
		WriteValidationError(w, "finding ID must be a 16-character hex string")
		return
	}
	for _, c := range findingID {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			WriteValidationError(w, "finding ID must be a 16-character hex string")
			return
		}
	}

	if r.URL.Query().Has("scope") {
		WriteValidationError(w, "scope is not supported; finding detail is always read from the published snapshot")
		return
	}
	if h.findingStore == nil {
		WriteServiceError(w, "published finding store")
		return
	}
	finding, scope, err := h.findingStore.GetPublished(r.Context(), findingID)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("get published finding: %w", err))
		return
	}
	if finding == nil {
		WriteNotFound(w, "finding not found in the published snapshot: "+findingID)
		return
	}

	attackPath := analysis.AttackPathFromExactEvidence(finding)
	evidenceState := analysis.FindingDetailEvidenceUnavailable
	if finding.ExactEvidence != nil {
		evidenceState = analysis.FindingDetailEvidencePersistedExact
	}

	WriteJSON(w, http.StatusOK, analysis.FindingDetail{
		Finding:     *finding,
		AttackPath:  attackPath,
		Remediation: analysis.BuildRemediation(attackPath, finding),
		Impact:      analysis.BuildImpact(finding, attackPath),
		Snapshot: &analysis.FindingSnapshot{
			Scope:            "published",
			ScanID:           scope.ScanID,
			Revision:         scope.Revision,
			PublishedAt:      scope.PublishedAt,
			ProjectionStatus: scope.ProjectionStatus,
			SnapshotStatus:   scope.SnapshotStatus,
			Available:        scope.Available,
			Stale:            scope.Stale,
			EvidenceState:    evidenceState,
		},
	})
}

// HandleWitness exports a stable, sanitized witness for a predicted CAN_REACH
// finding so the collector-side campaign runner can verify it. The witness is
// built under a guarded read of the published projection and stamped with that
// projection's revision, so it reflects a stable, published prediction.
func (h *AnalysisHandler) HandleWitness(w http.ResponseWriter, r *http.Request) {
	findingID := chi.URLParam(r, "id")
	if len(findingID) != 16 {
		WriteValidationError(w, "finding ID must be a 16-character hex string")
		return
	}
	for _, c := range findingID {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			WriteValidationError(w, "finding ID must be a 16-character hex string")
			return
		}
	}

	witness, projection, err := guardedProjectionRead(
		r.Context(),
		h.projectionReader,
		func() (*campaign.Witness, error) {
			return analysis.BuildWitness(r.Context(), h.graphDB, findingID)
		},
	)
	if err != nil {
		if writeProjectionConflict(w, err) {
			return
		}
		WriteNotFound(w, "witness export: "+err.Error())
		return
	}
	witness.PublicationRevision = int(projection.Revision)
	if err := witness.Validate(); err != nil {
		WriteInternalError(w, r, fmt.Errorf("witness export: %w", err))
		return
	}
	WriteJSON(w, http.StatusOK, struct {
		Witness    *campaign.Witness  `json:"witness"`
		Projection projectionIdentity `json:"projection"`
	}{
		Witness:    witness,
		Projection: projection,
	})
}

func (h *AnalysisHandler) HandleListPreBuilt(w http.ResponseWriter, _ *http.Request) {
	WriteJSON(w, http.StatusOK, prebuilt.List())
}

func (h *AnalysisHandler) HandlePreBuilt(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	q, ok := prebuilt.Get(id)
	if !ok {
		WriteNotFound(w, "pre-built query not found: "+id)
		return
	}
	if id == "shortest-to-database" {
		h.handleShortestToDatabase(w, r, q)
		return
	}

	rows, projection, err := guardedProjectionRead(
		r.Context(),
		h.projectionReader,
		func() ([]map[string]any, error) {
			return h.graphDB.Query(r.Context(), q.Cypher, nil)
		},
	)
	if err != nil {
		if writeProjectionConflict(w, err) {
			return
		}
		WriteInternalError(w, r, fmt.Errorf("prebuilt query %s: %w", id, err))
		return
	}
	if rows == nil {
		rows = []map[string]any{}
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"query":      q,
		"rows":       rows,
		"projection": projection,
	})
}

func (h *AnalysisHandler) handleShortestToDatabase(
	w http.ResponseWriter,
	r *http.Request,
	query prebuilt.PreBuiltQuery,
) {
	result, projection, err := guardedProjectionRead(
		r.Context(),
		h.projectionReader,
		func() (analysis.TraversalResult, error) {
			return analysis.FindShortestDatabasePaths(r.Context(), h.graphDB)
		},
	)
	if err != nil {
		if writeProjectionConflict(w, err) {
			return
		}
		WriteInternalError(w, r, fmt.Errorf("shortest database paths: %w", err))
		return
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"query":      query,
		"rows":       analysis.DatabasePathRows(result),
		"metadata":   result.Metadata,
		"projection": projection,
	})
}

// parseTarget splits "Kind:name" or uses the provided targetKind.
func parseTarget(target, targetKind string) (string, string) {
	if target == "" {
		return targetKind, ""
	}
	if parts := strings.SplitN(target, ":", 2); len(parts) == 2 && targetKind == "" {
		return parts[0], parts[1]
	}
	return targetKind, target
}

// isObjectID returns true if value looks like a SHA-256 objectid (hex string
// with optional "sha256:" prefix) rather than a human-readable name.
func isObjectID(value string) bool {
	v := strings.TrimPrefix(value, "sha256:")
	if len(v) != 64 {
		return false
	}
	for _, c := range v {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// nodeMatchProp returns the property key to use for matching: "objectid" for
// SHA-256 IDs, "name" for human-readable values.
func nodeMatchProp(value string) string {
	if isObjectID(value) {
		return "objectid"
	}
	return "name"
}

func clamp(val, min, max, defaultVal int) int {
	if val <= 0 {
		return defaultVal
	}
	if val < min {
		return min
	}
	if val > max {
		return max
	}
	return val
}
