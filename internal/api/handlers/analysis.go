package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"

	"github.com/adithyan-ak/agenthound/internal/analysis"
	"github.com/adithyan-ak/agenthound/internal/analysis/prebuilt"
	"github.com/adithyan-ak/agenthound/internal/audit"
	"github.com/adithyan-ak/agenthound/internal/graph"
	"github.com/adithyan-ak/agenthound/internal/model"
	"github.com/go-chi/chi/v5"
)

type AnalysisHandler struct {
	graphDB graph.GraphDB
	audit   *audit.Logger
}

func NewAnalysisHandler(db graph.GraphDB, auditLog *audit.Logger) *AnalysisHandler {
	return &AnalysisHandler{graphDB: db, audit: auditLog}
}

var allowedNodeLabels = func() map[string]bool {
	m := make(map[string]bool, len(model.AllNodeLabels))
	for _, l := range model.AllNodeLabels {
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

	h.auditLog(r, "analysis.shortest_path", map[string]any{
		"source": req.Source, "target": req.Target, "source_kind": req.SourceKind,
	})

	maxHops := clamp(req.MaxHops, 1, 20, 10)

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

	rows, err := h.graphDB.Query(r.Context(), cypher, params)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("shortest path query: %w", err))
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"paths": rows})
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

	rows, err := h.graphDB.Query(r.Context(), cypher, params)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("all paths query: %w", err))
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"paths": rows})
}

const dijkstraRelTypes = "TRUSTS_SERVER|PROVIDES_TOOL|HAS_ACCESS_TO|CAN_EXECUTE|DELEGATES_TO|CAN_REACH"

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

	maxHops := clamp(req.MaxHops, 1, 20, 10)
	ctx := r.Context()

	srcProp := nodeMatchProp(req.Source)
	tgtProp := nodeMatchProp(targetName)

	if h.graphDB.HasAPOC(ctx) {
		var cypher string
		params := map[string]any{
			"source": req.Source,
			"target": targetName,
		}

		if targetKind != "" {
			cypher = fmt.Sprintf(
				`MATCH (src:%s {%s: $source}), (tgt:%s {%s: $target}) `+
					`CALL apoc.algo.dijkstra(src, tgt, '%s', 'risk_weight') YIELD path, weight `+
					`RETURN [n IN nodes(path) | {id: n.objectid, name: n.name, kinds: labels(n)}] AS nodes, `+
					`[r IN relationships(path) | {kind: type(r), source: startNode(r).objectid, target: endNode(r).objectid, risk_weight: r.risk_weight}] AS edges, `+
					`weight LIMIT 10`,
				req.SourceKind, srcProp, targetKind, tgtProp, dijkstraRelTypes,
			)
		} else {
			cypher = fmt.Sprintf(
				`MATCH (src:%s {%s: $source}), (tgt {%s: $target}) `+
					`CALL apoc.algo.dijkstra(src, tgt, '%s', 'risk_weight') YIELD path, weight `+
					`RETURN [n IN nodes(path) | {id: n.objectid, name: n.name, kinds: labels(n)}] AS nodes, `+
					`[r IN relationships(path) | {kind: type(r), source: startNode(r).objectid, target: endNode(r).objectid, risk_weight: r.risk_weight}] AS edges, `+
					`weight LIMIT 10`,
				req.SourceKind, srcProp, tgtProp, dijkstraRelTypes,
			)
		}

		rows, err := h.graphDB.Query(ctx, cypher, params)
		if err != nil {
			WriteInternalError(w, r, fmt.Errorf("dijkstra query: %w", err))
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"paths": rows, "algorithm": "dijkstra"})
		return
	}

	// Fallback: shortestPath + manual risk_weight sum
	var cypher string
	params := map[string]any{
		"source": req.Source,
		"target": targetName,
	}

	if targetKind != "" {
		cypher = fmt.Sprintf(
			`MATCH (src:%s {%s: $source}), (tgt:%s {%s: $target}), `+
				`p = shortestPath((src)-[*1..%d]-(tgt)) WHERE src <> tgt `+
				`RETURN [n IN nodes(p) | {id: n.objectid, name: n.name, kinds: labels(n)}] AS nodes, `+
				`[r IN relationships(p) | {kind: type(r), source: startNode(r).objectid, target: endNode(r).objectid, risk_weight: r.risk_weight}] AS edges, `+
				`reduce(w = 0.0, r IN relationships(p) | w + coalesce(r.risk_weight, 1.0)) AS weight, `+
				`length(p) AS hops ORDER BY weight ASC LIMIT 10`,
			req.SourceKind, srcProp, targetKind, tgtProp, maxHops,
		)
	} else {
		cypher = fmt.Sprintf(
			`MATCH (src:%s {%s: $source}), (tgt {%s: $target}), `+
				`p = shortestPath((src)-[*1..%d]-(tgt)) WHERE src <> tgt `+
				`RETURN [n IN nodes(p) | {id: n.objectid, name: n.name, kinds: labels(n)}] AS nodes, `+
				`[r IN relationships(p) | {kind: type(r), source: startNode(r).objectid, target: endNode(r).objectid, risk_weight: r.risk_weight}] AS edges, `+
				`reduce(w = 0.0, r IN relationships(p) | w + coalesce(r.risk_weight, 1.0)) AS weight, `+
				`length(p) AS hops ORDER BY weight ASC LIMIT 10`,
			req.SourceKind, srcProp, tgtProp, maxHops,
		)
	}

	rows, err := h.graphDB.Query(ctx, cypher, params)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("weighted path query: %w", err))
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{"paths": rows, "algorithm": "shortestPath+reduce"})
}

func (h *AnalysisHandler) HandleFindings(w http.ResponseWriter, r *http.Request) {
	severity := r.URL.Query().Get("severity")

	findings, err := analysis.QueryFindings(r.Context(), h.graphDB, severity)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("findings query: %w", err))
		return
	}
	if findings == nil {
		findings = []analysis.Finding{}
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
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			WriteValidationError(w, "finding ID must be a 16-character hex string")
			return
		}
	}

	h.auditLog(r, "analysis.finding_detail", map[string]any{"finding_id": findingID})

	finding, err := analysis.GetFindingByID(r.Context(), h.graphDB, findingID)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("get finding: %w", err))
		return
	}
	if finding == nil {
		WriteNotFound(w, "finding not found: "+findingID)
		return
	}

	compositeProps, err := analysis.GetCompositeEdgeProps(r.Context(), h.graphDB, finding)
	if err != nil {
		slog.Warn("failed to get composite edge props", "error", err)
	}

	attackPath, err := analysis.ReconstructAttackPath(r.Context(), h.graphDB, finding, compositeProps)
	if err != nil {
		slog.Warn("attack path reconstruction failed", "error", err)
	}

	remediation := analysis.BuildRemediation(attackPath, finding)
	impact := analysis.BuildImpact(finding, attackPath, compositeProps)

	WriteJSON(w, http.StatusOK, analysis.FindingDetail{
		Finding:        *finding,
		CompositeProps: compositeProps,
		AttackPath:     attackPath,
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

	h.auditLog(r, "query.prebuilt", map[string]any{"query_id": id})

	rows, err := h.graphDB.Query(r.Context(), q.Cypher, nil)
	if err != nil {
		WriteInternalError(w, r, fmt.Errorf("prebuilt query %s: %w", id, err))
		return
	}
	WriteJSON(w, http.StatusOK, map[string]any{
		"query": q,
		"rows":  rows,
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
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
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

func (h *AnalysisHandler) auditLog(r *http.Request, action string, details map[string]any) {
	if h.audit == nil {
		return
	}
	if err := h.audit.Log(r.Context(), action, details); err != nil {
		slog.Warn("audit log failed", "action", action, "error", err)
	}
}
