package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/analysis"
	"github.com/adithyan-ak/agenthound/server/internal/analysis/prebuilt"
	"github.com/adithyan-ak/agenthound/server/internal/appdb"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/adithyan-ak/agenthound/server/model"
	"github.com/go-chi/chi/v5"
)

// findingLister is the subset of *appdb.FindingStore that the findings
// endpoint reads from. When nil (e.g. in unit tests without Postgres),
// HandleFindings falls back to live composite edges in the graph.
type findingLister interface {
	ListLatestPerFingerprint(ctx context.Context, severity string, includeSuppressed bool) ([]model.Finding, error)
}

type publishedFindingLister interface {
	ListPublished(ctx context.Context, severity string, includeSuppressed bool) ([]model.Finding, appdb.FindingScope, error)
	GetPublished(ctx context.Context, fingerprint string) (*model.Finding, appdb.FindingScope, error)
}

type AnalysisHandler struct {
	graphDB      graph.GraphDB
	findingStore findingLister
}

func NewAnalysisHandler(db graph.GraphDB, findingStore *appdb.FindingStore) *AnalysisHandler {
	h := &AnalysisHandler{graphDB: db}
	// Avoid the typed-nil-into-interface trap: only populate the
	// interface field when the concrete pointer is non-nil so the
	// `h.findingStore != nil` fallback check stays correct.
	if findingStore != nil {
		h.findingStore = findingStore
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
	Scope      string `json:"scope,omitempty"`
	MaxHops    int    `json:"max_hops"`
	Limit      int    `json:"limit"`
}

func (h *AnalysisHandler) HandleShortestPath(w http.ResponseWriter, r *http.Request) {
	var req pathRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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

	scope, err := analysis.ParseTraversalScope(req.Scope)
	if err != nil {
		WriteValidationError(w, err.Error())
		return
	}
	sources, targets, err := h.resolveTraversalEndpoints(
		r.Context(), req, targetKind, targetName,
	)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("resolve shortest path endpoints: %w", err))
		return
	}
	result, err := analysis.FindBoundedTraversalPaths(
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
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("shortest path query: %w", err))
		return
	}
	writeTraversalResult(w, result)
}

func (h *AnalysisHandler) HandleAllPaths(w http.ResponseWriter, r *http.Request) {
	var req pathRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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

	scope, err := analysis.ParseTraversalScope(req.Scope)
	if err != nil {
		WriteValidationError(w, err.Error())
		return
	}
	sources, targets, err := h.resolveTraversalEndpoints(
		r.Context(), req, targetKind, targetName,
	)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("resolve all path endpoints: %w", err))
		return
	}
	result, err := analysis.FindBoundedTraversalPaths(
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
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("all paths query: %w", err))
		return
	}
	writeTraversalResult(w, result)
}

func (h *AnalysisHandler) HandleWeightedPath(w http.ResponseWriter, r *http.Request) {
	var req pathRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
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

	scope, err := analysis.ParseTraversalScope(req.Scope)
	if err != nil {
		WriteValidationError(w, err.Error())
		return
	}
	sources, targets, err := h.resolveTraversalEndpoints(
		r.Context(), req, targetKind, targetName,
	)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("resolve weighted path endpoints: %w", err))
		return
	}
	result, err := analysis.FindBoundedTraversalPaths(
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
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("weighted path query: %w", err))
		return
	}
	writeTraversalResult(w, result)
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

func writeTraversalResult(w http.ResponseWriter, result analysis.TraversalResult) {
	if result.Paths == nil {
		result.Paths = []analysis.TraversalPath{}
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"paths":     result.Paths,
		"algorithm": result.Metadata.Algorithm,
		"metadata":  result.Metadata,
	})
}

func (h *AnalysisHandler) HandleFindings(w http.ResponseWriter, r *http.Request) {
	severity := r.URL.Query().Get("severity")
	includeSuppressed := r.URL.Query().Get("include_suppressed") == "true"
	scopeMode := r.URL.Query().Get("scope")
	if scopeMode == "" {
		scopeMode = "history"
	}
	if scopeMode != "history" && scopeMode != "published" {
		WriteValidationError(w, "scope must be history or published")
		return
	}

	var findings []model.Finding
	var err error
	if scopeMode == "published" {
		store, ok := h.findingStore.(publishedFindingLister)
		if !ok {
			WriteInternalError(w, r, fmt.Errorf("published finding scope is unavailable"))
			return
		}
		var scope appdb.FindingScope
		findings, scope, err = store.ListPublished(r.Context(), severity, includeSuppressed)
		writeFindingScopeHeaders(w, scope)
	} else if h.findingStore != nil {
		// Default data source: the persisted per-scan snapshot, with
		// triage state joined in and suppressed findings hidden unless
		// include_suppressed=true.
		findings, err = h.findingStore.ListLatestPerFingerprint(r.Context(), severity, includeSuppressed)
	} else {
		// Fallback for setups without a Postgres snapshot (unit tests):
		// read live composite edges directly from the graph.
		findings, err = analysis.QueryFindings(r.Context(), h.graphDB, severity)
	}
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("findings query: %w", err))
		return
	}
	if findings == nil {
		findings = []model.Finding{}
	}
	WriteJSON(w, http.StatusOK, findings)
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

	scopeMode := r.URL.Query().Get("scope")
	if scopeMode == "published" {
		h.handlePublishedFindingDetail(w, r, findingID)
		return
	}
	if scopeMode != "" && scopeMode != "history" {
		WriteValidationError(w, "scope must be history or published")
		return
	}

	finding, err := analysis.GetFindingByID(r.Context(), h.graphDB, findingID)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("get finding: %w", err))
		return
	}
	if finding == nil {
		WriteNotFound(w, "finding not found: "+findingID)
		return
	}

	attackPath := analysis.AttackPathFromExactEvidence(finding)
	remediation := analysis.BuildRemediation(attackPath, finding)
	impact := analysis.BuildImpact(finding, attackPath, nil)

	WriteJSON(w, http.StatusOK, analysis.FindingDetail{
		Finding:     *finding,
		AttackPath:  attackPath,
		Remediation: remediation,
		Impact:      impact,
	})
}

func (h *AnalysisHandler) handlePublishedFindingDetail(
	w http.ResponseWriter,
	r *http.Request,
	findingID string,
) {
	store, ok := h.findingStore.(publishedFindingLister)
	if !ok {
		WriteInternalError(w, r, fmt.Errorf("published finding scope is unavailable"))
		return
	}
	finding, scope, err := store.GetPublished(r.Context(), findingID)
	writeFindingScopeHeaders(w, scope)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("get published finding: %w", err))
		return
	}
	if finding == nil {
		WriteNotFound(w, "finding not found in the published snapshot: "+findingID)
		return
	}

	attackPath := analysis.AttackPathFromExactEvidence(finding)
	liveEvidenceState := analysis.LiveEvidenceUnavailable
	if finding.ExactEvidence != nil {
		liveEvidenceState = analysis.LiveEvidencePersistedExact
	}

	WriteJSON(w, http.StatusOK, analysis.FindingDetail{
		Finding:     *finding,
		AttackPath:  attackPath,
		Remediation: analysis.BuildRemediation(attackPath, finding),
		Impact:      analysis.BuildImpact(finding, attackPath, nil),
		Snapshot: &analysis.FindingSnapshot{
			Scope:             "published",
			ScanID:            scope.ScanID,
			ProjectionStatus:  scope.ProjectionStatus,
			Stale:             scope.Stale,
			LiveEvidenceState: liveEvidenceState,
		},
	})
}

func writeFindingScopeHeaders(w http.ResponseWriter, scope appdb.FindingScope) {
	w.Header().Set("X-Finding-Scope", scope.Mode)
	w.Header().Set("X-Projection-Status", scope.ProjectionStatus)
	w.Header().Set("X-Snapshot-Status", scope.SnapshotStatus)
	w.Header().Set("X-Snapshot-Available", strconv.FormatBool(scope.Available))
	w.Header().Set("X-Snapshot-Stale", strconv.FormatBool(scope.Stale))
	if scope.ScanID != "" {
		w.Header().Set("X-Snapshot-Scan-ID", scope.ScanID)
	}
	if scope.Revision != nil {
		w.Header().Set("X-Published-Revision", strconv.FormatInt(*scope.Revision, 10))
	}
	if scope.PublishedAt != nil {
		w.Header().Set("X-Published-At", scope.PublishedAt.UTC().Format(time.RFC3339))
	}
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

	rows, err := h.graphDB.Query(r.Context(), q.Cypher, nil)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("prebuilt query %s: %w", id, err))
		return
	}
	if rows == nil {
		rows = []map[string]any{}
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"query": q,
		"rows":  rows,
	})
}

func (h *AnalysisHandler) handleShortestToDatabase(
	w http.ResponseWriter,
	r *http.Request,
	query prebuilt.PreBuiltQuery,
) {
	result, err := analysis.FindShortestDatabasePaths(r.Context(), h.graphDB)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("shortest database paths: %w", err))
		return
	}

	WriteJSON(w, http.StatusOK, map[string]any{
		"query":    query,
		"rows":     analysis.DatabasePathRows(result),
		"metadata": result.Metadata,
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
