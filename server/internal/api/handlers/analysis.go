package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/analysis"
	"github.com/adithyan-ak/agenthound/server/internal/analysis/prebuilt"
	"github.com/adithyan-ak/agenthound/server/internal/appdb"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/adithyan-ak/agenthound/server/model"
	"github.com/go-chi/chi/v5"
)

// findingSource is the subset of *appdb.FindingStore that the findings
// endpoints read from. Both list and detail read the SAME persisted
// occurrences through this seam, so their finding shapes are identical
// (parity). When nil (e.g. unit tests without Postgres), the handlers fall
// back to live composite edges in the graph.
type findingSource interface {
	ListCurrentFindings(ctx context.Context, q appdb.FindingQuery) ([]model.Finding, int, error)
	GetCurrentFinding(ctx context.Context, generationIDs []string, fingerprint string) (*model.Finding, error)
}

type AnalysisHandler struct {
	graphDB  graph.GraphDB
	findings findingSource
	gens     generationLister
}

func NewAnalysisHandler(db graph.GraphDB, findingStore *appdb.FindingStore, scanStore *appdb.ScanStore) *AnalysisHandler {
	h := &AnalysisHandler{graphDB: db}
	// Avoid the typed-nil-into-interface trap: only populate the interface
	// fields when the concrete pointer is non-nil so the `!= nil` fallback
	// checks stay correct.
	if findingStore != nil {
		h.findings = findingStore
	}
	if scanStore != nil {
		h.gens = scanStore
	}
	return h
}

var allowedNodeLabels = func() map[string]bool {
	m := make(map[string]bool, len(ingest.AllNodeLabels))
	for _, l := range ingest.AllNodeLabels {
		m[l] = true
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

	maxHops := clamp(req.MaxHops, 1, 20, 10)

	scope, err := resolveGenerationScope(r.Context(), h.gens)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("resolve generation scope: %w", err))
		return
	}
	if h.gens != nil && len(scope.GenerationIDs) == 0 {
		WriteJSON(w, http.StatusOK, map[string]any{"paths": []any{}, "completeness": scope.Completeness})
		return
	}

	srcProp := nodeMatchProp(req.Source)
	var cypher string
	params := map[string]any{
		"source": req.Source,
	}

	const pathReturn = `RETURN [n IN nodes(p) | {id: n.objectid, name: n.name, kinds: labels(n)}] AS nodes, ` +
		`[r IN relationships(p) | {kind: type(r), source: startNode(r).objectid, target: endNode(r).objectid}] AS edges, ` +
		`length(p) AS hops ORDER BY hops ASC LIMIT 10`

	if targetKind != "" && targetName != "" {
		tgtProp := nodeMatchProp(targetName)
		cypher = fmt.Sprintf(
			`MATCH (src:%s {%s: $source}), (tgt:%s {%s: $target}), `+
				`p = shortestPath((src)-[*1..%d]-(tgt)) WHERE src <> tgt `+
				pathReturn,
			req.SourceKind, srcProp, targetKind, tgtProp, maxHops,
		)
		params["target"] = targetName
	} else if targetKind != "" && targetName == "" {
		cypher = fmt.Sprintf(
			`MATCH (src:%s {%s: $source}), (tgt:%s), `+
				`p = shortestPath((src)-[*1..%d]-(tgt)) WHERE src <> tgt `+
				pathReturn,
			req.SourceKind, srcProp, targetKind, maxHops,
		)
	} else if targetName != "" {
		tgtProp := nodeMatchProp(targetName)
		cypher = fmt.Sprintf(
			`MATCH (src:%s {%s: $source}), (tgt {%s: $target}), `+
				`p = shortestPath((src)-[*1..%d]-(tgt)) WHERE src <> tgt `+
				pathReturn,
			req.SourceKind, srcProp, tgtProp, maxHops,
		)
		params["target"] = targetName
	} else {
		cypher = fmt.Sprintf(
			`MATCH (src:%s {%s: $source}), (tgt), `+
				`p = shortestPath((src)-[*1..%d]-(tgt)) WHERE src <> tgt `+
				pathReturn,
			req.SourceKind, srcProp, maxHops,
		)
	}

	cypher = applyPathScope(cypher, scope.GenerationIDs, params)

	rows, err := h.graphDB.Query(r.Context(), cypher, params)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("shortest path query: %w", err))
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"paths": rows, "completeness": scope.Completeness})
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

	maxHops := clamp(req.MaxHops, 1, 20, 10)
	limit := clamp(req.Limit, 1, 100, 10)

	scope, err := resolveGenerationScope(r.Context(), h.gens)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("resolve generation scope: %w", err))
		return
	}
	if h.gens != nil && len(scope.GenerationIDs) == 0 {
		WriteJSON(w, http.StatusOK, map[string]any{"paths": []any{}, "completeness": scope.Completeness})
		return
	}

	srcProp := nodeMatchProp(req.Source)
	var cypher string
	params := map[string]any{
		"source": req.Source,
		"limit":  limit,
	}

	const allPathReturn = `RETURN [n IN nodes(p) | {id: n.objectid, name: n.name, kinds: labels(n)}] AS nodes, ` +
		`[r IN relationships(p) | {kind: type(r), source: startNode(r).objectid, target: endNode(r).objectid}] AS edges, ` +
		`length(p) AS hops ORDER BY hops ASC LIMIT $limit`

	if targetKind != "" && targetName != "" {
		tgtProp := nodeMatchProp(targetName)
		cypher = fmt.Sprintf(
			`MATCH (src:%s {%s: $source}), (tgt:%s {%s: $target}), `+
				`p = (src)-[*1..%d]-(tgt) WHERE src <> tgt `+
				allPathReturn,
			req.SourceKind, srcProp, targetKind, tgtProp, maxHops,
		)
		params["target"] = targetName
	} else if targetKind != "" && targetName == "" {
		cypher = fmt.Sprintf(
			`MATCH (src:%s {%s: $source}), (tgt:%s), `+
				`p = (src)-[*1..%d]-(tgt) WHERE src <> tgt `+
				allPathReturn,
			req.SourceKind, srcProp, targetKind, maxHops,
		)
	} else if targetName != "" {
		tgtProp := nodeMatchProp(targetName)
		cypher = fmt.Sprintf(
			`MATCH (src:%s {%s: $source}), (tgt {%s: $target}), `+
				`p = (src)-[*1..%d]-(tgt) WHERE src <> tgt `+
				allPathReturn,
			req.SourceKind, srcProp, tgtProp, maxHops,
		)
		params["target"] = targetName
	} else {
		cypher = fmt.Sprintf(
			`MATCH (src:%s {%s: $source}), (tgt), `+
				`p = (src)-[*1..%d]-(tgt) WHERE src <> tgt `+
				allPathReturn,
			req.SourceKind, srcProp, maxHops,
		)
	}

	cypher = applyPathScope(cypher, scope.GenerationIDs, params)

	rows, err := h.graphDB.Query(r.Context(), cypher, params)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("all paths query: %w", err))
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"paths": rows, "completeness": scope.Completeness})
}

// HandleWeightedPath returns the minimum-total-weight attack path from source
// to target using the single bounded, forward-directed traversal in
// analysis.BoundedMinWeightPath. This replaces the previous APOC-dijkstra /
// undirected-shortestPath split: no dependency on APOC, no path that crosses
// an edge backwards, and an honest nullable total (unknown when any edge on
// the chosen path lacks a risk_weight) instead of substituting 1.0 for missing
// weights.
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

	scope, err := resolveGenerationScope(r.Context(), h.gens)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("resolve generation scope: %w", err))
		return
	}
	if h.gens != nil && len(scope.GenerationIDs) == 0 {
		WriteJSON(w, http.StatusOK, map[string]any{
			"paths": []*analysis.AttackPath{}, "algorithm": "bounded-min-weight",
			"completeness": scope.Completeness,
		})
		return
	}

	policy := analysis.DefaultTraversalPolicy()
	policy.MaxHops = clamp(req.MaxHops, 1, 20, 10)
	policy.Generations = scope.GenerationIDs
	// The endpoint accepts either objectids or human-readable names; match on
	// the appropriate property per endpoint. Composite edges are allowed here
	// (this is an operator-driven "how does A reach B" query, not evidence
	// reconstruction), so the min-weight walk can use inferred reach edges.
	policy.SourceProp = nodeMatchProp(req.Source)
	policy.TargetProp = nodeMatchProp(targetName)
	policy.ExcludeComposite = false

	path, err := analysis.BoundedMinWeightPath(r.Context(), h.graphDB, req.Source, targetName, policy)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("weighted path traversal: %w", err))
		return
	}

	paths := []*analysis.AttackPath{}
	if path != nil {
		paths = append(paths, path)
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"paths":        paths,
		"algorithm":    "bounded-min-weight",
		"direction":    string(policy.Direction),
		"max_hops":     policy.MaxHops,
		"completeness": scope.Completeness,
	})
}

func (h *AnalysisHandler) HandleFindings(w http.ResponseWriter, r *http.Request) {
	severity := r.URL.Query().Get("severity")
	includeSuppressed := r.URL.Query().Get("include_suppressed") == "true"
	limit := parseIntParamWithMax(r, "limit", 50, 1000)
	offset := parseIntParam(r, "offset", 0)

	scope, err := resolveGenerationScope(r.Context(), h.gens)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("resolve generation scope: %w", err))
		return
	}

	if h.findings != nil {
		// Default source: persisted occurrences scoped to the current
		// generations, with triage joined and suppressed findings hidden
		// unless include_suppressed=true. Totals/pagination reflect the
		// scoped set; completeness discloses whether the scope is authoritative.
		items, total, err := h.findings.ListCurrentFindings(r.Context(), appdb.FindingQuery{
			GenerationIDs:     scope.GenerationIDs,
			Severity:          severity,
			IncludeSuppressed: includeSuppressed,
			Limit:             limit,
			Offset:            offset,
		})
		if err != nil {
			WriteInternalError(w, r, fmt.Errorf("findings query: %w", err))
			return
		}
		c := scope.Completeness
		c.Truncated = len(items) == limit && offset+len(items) < total
		WriteJSON(w, http.StatusOK, newPage(items, total, limit, offset, c))
		return
	}

	// Fallback for setups without a Postgres snapshot (unit tests): read live
	// composite edges directly from the graph. This path is not
	// generation-scoped, so completeness stays non-authoritative and the total
	// is suppressed.
	findings, err := analysis.QueryFindings(r.Context(), h.graphDB, severity)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("findings query: %w", err))
		return
	}
	WriteJSON(w, http.StatusOK, newPage(findings, len(findings), limit, offset, scope.Completeness))
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

	var finding *model.Finding
	var err error
	fromStore := false
	if h.findings != nil {
		// Parity: detail reads the SAME persisted occurrence the list returns,
		// scoped to the current generations.
		scope, serr := resolveGenerationScope(r.Context(), h.gens)
		if serr != nil {
			WriteInternalError(w, r, fmt.Errorf("resolve generation scope: %w", serr))
			return
		}
		finding, err = h.findings.GetCurrentFinding(r.Context(), scope.GenerationIDs, findingID)
		fromStore = true
	} else {
		// Fallback (no Postgres store): reconstruct from live composite edges.
		finding, err = analysis.GetFindingByID(r.Context(), h.graphDB, findingID)
	}
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("get finding: %w", err))
		return
	}
	if finding == nil {
		WriteNotFound(w, "finding not found: "+findingID)
		return
	}

	var (
		compositeProps map[string]any
		attackPath     *analysis.AttackPath
		evidenceDAG    *analysis.EvidenceDAG
	)

	// Evidence parity: when the finding came from the persisted store and
	// carries a snapshotted evidence DAG, the detail MUST report that same
	// evidence rather than recompute it against the (mutable, possibly
	// re-ingested) live graph — otherwise list and detail can disagree, and
	// detail can assert evidence the current graph no longer supports. The
	// attack path shown is rebuilt from the persisted DAG so remediation and
	// impact are derived from the identical evidence set.
	if persisted, ok := analysis.EvidenceDAGFromPersisted(finding); fromStore && ok {
		evidenceDAG = persisted
		attackPath = analysis.AttackPathFromEvidenceDAG(persisted)
		compositeProps = finding.CompositeProps
	} else {
		// No persisted evidence (Postgres-less fallback, or a legacy occurrence
		// with no DAG): reconstruct from the live graph.
		compositeProps, err = analysis.GetCompositeEdgeProps(r.Context(), h.graphDB, finding)
		if err != nil {
			slog.Warn("failed to get composite edge props", "error", err)
		}
		attackPath, err = analysis.ReconstructAttackPath(r.Context(), h.graphDB, finding, compositeProps)
		if err != nil {
			slog.Warn("attack path reconstruction failed", "error", err)
		}
		evidenceDAG = analysis.BuildEvidenceDAG(finding, attackPath, compositeProps)
	}

	remediation := analysis.BuildRemediation(attackPath, finding)
	impact := analysis.BuildImpact(finding, attackPath, compositeProps)

	WriteJSON(w, http.StatusOK, analysis.FindingDetail{
		Finding:        *finding,
		CompositeProps: compositeProps,
		AttackPath:     attackPath,
		EvidenceDAG:    evidenceDAG,
		Remediation:    remediation,
		Impact:         impact,
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

	scope, err := resolveGenerationScope(r.Context(), h.gens)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("resolve generation scope: %w", err))
		return
	}
	// Prebuilt Cypher is scoped to the current generations via $gens. With no
	// promoted generation there is nothing current to analyse, so return an
	// empty (but disclosed-incomplete) result rather than an unscoped read that
	// would leak retained facts.
	if h.gens != nil && len(scope.GenerationIDs) == 0 {
		WriteJSON(w, http.StatusOK, map[string]any{
			"query": q, "rows": []map[string]any{}, "completeness": scope.Completeness,
		})
		return
	}

	rows, err := h.graphDB.Query(r.Context(), q.Cypher, map[string]any{"gens": scope.GenerationIDs})
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("prebuilt query %s: %w", id, err))
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"query":        q,
		"rows":         rows,
		"completeness": scope.Completeness,
	})
}

// applyPathScope restricts a shortest/all-paths query to the current logical
// generations: every node AND relationship on the returned path must be
// observed by one of the promoted generations, so a path that traverses a
// retained (demoted) generation's facts is never reported. The predicate is
// injected into the shared `WHERE src <> tgt` clause and Neo4j pushes the
// nodes(p)/relationships(p) predicates into the path search. An empty scope
// (unit tests without a scan store) leaves the query unscoped.
func applyPathScope(cypher string, gens []string, params map[string]any) string {
	if len(gens) == 0 {
		return cypher
	}
	params["gens"] = gens
	predicate := "WHERE src <> tgt " +
		"AND ALL(n IN nodes(p) WHERE ANY(g IN coalesce(n.generations, []) WHERE g IN $gens)) " +
		"AND ALL(rel IN relationships(p) WHERE ANY(g IN coalesce(rel.generations, []) WHERE g IN $gens)) "
	return strings.Replace(cypher, "WHERE src <> tgt ", predicate, 1)
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
