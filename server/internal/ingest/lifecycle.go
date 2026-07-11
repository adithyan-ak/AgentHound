package ingest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	sdkingest "github.com/adithyan-ak/agenthound/sdk/ingest"
	"github.com/adithyan-ak/agenthound/server/internal/graph"
	"github.com/adithyan-ak/agenthound/server/model"
)

const countSemanticsWriteRowsV1 = "neo4j_write_rows_v1"

func coverageKeys(report *sdkingest.CollectionReport) []string {
	if report == nil {
		return []string{}
	}
	seen := make(map[string]bool, len(report.CoverageKeys))
	keys := make([]string, 0, len(report.CoverageKeys))
	for _, key := range report.CoverageKeys {
		key = strings.TrimSpace(key)
		if key == "" || seen[key] {
			continue
		}
		seen[key] = true
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func collectionState(report *sdkingest.CollectionReport) sdkingest.OutcomeState {
	if report == nil {
		return sdkingest.OutcomeUnknown
	}
	if report.State != "" {
		return report.State
	}
	return sdkingest.AggregateOutcomeState(report.Outcomes)
}

func incompleteCoverageDomains(report *sdkingest.CollectionReport) []string {
	states := sdkingest.CoverageStates(report)
	domains := make([]string, 0, len(states))
	for domain, state := range states {
		if state != sdkingest.OutcomeComplete {
			domains = append(domains, domain)
		}
	}
	sort.Strings(domains)
	return domains
}

func mergeCoverage(groups ...[]string) []string {
	seen := make(map[string]bool)
	var merged []string
	for _, group := range groups {
		for _, key := range group {
			key = strings.TrimSpace(key)
			if key == "" || seen[key] {
				continue
			}
			seen[key] = true
			merged = append(merged, key)
		}
	}
	sort.Strings(merged)
	return merged
}

func subtractCoverage(keys []string, replaced ...[]string) []string {
	remove := make(map[string]bool)
	for _, group := range replaced {
		for _, key := range group {
			if key = strings.TrimSpace(key); key != "" {
				remove[key] = true
			}
		}
	}
	var remaining []string
	for _, key := range mergeCoverage(keys) {
		if !remove[key] {
			remaining = append(remaining, key)
		}
	}
	return remaining
}

func coverageCollectors(keys []string) []string {
	collectors := make([]string, 0, len(keys))
	for _, key := range keys {
		collector := key
		if separator := strings.IndexByte(key, ':'); separator >= 0 {
			collector = key[:separator]
		}
		collectors = mergeCoverage(collectors, []string{collector})
	}
	return collectors
}

// prepareObservationDomains supplies the unambiguous single-domain fallback
// for additive compatibility. Multi-domain artifacts must carry per-fact tags;
// missing tags make reconciliation unsafe and therefore non-destructive.
func prepareObservationDomains(data *sdkingest.IngestData) bool {
	keys := coverageKeys(data.Meta.Collection)
	if len(keys) == 1 {
		sdkingest.TagObservationDomain(&data.Graph, keys[0])
	}
	allowed := make(map[string]bool, len(keys))
	for _, key := range keys {
		allowed[key] = true
	}
	for _, node := range data.Graph.Nodes {
		if len(node.ObservationDomains) == 0 {
			return false
		}
		for _, domain := range node.ObservationDomains {
			if !allowed[domain] {
				return false
			}
		}
	}
	for _, edge := range data.Graph.Edges {
		if len(edge.ObservationDomains) == 0 {
			return false
		}
		for _, domain := range edge.ObservationDomains {
			if !allowed[domain] {
				return false
			}
		}
	}
	return len(keys) > 0
}

func coalesceObservationGraph(graph sdkingest.GraphData) sdkingest.GraphData {
	merged := sdkingest.GraphData{
		Nodes: make([]sdkingest.Node, 0, len(graph.Nodes)),
		Edges: make([]sdkingest.Edge, 0, len(graph.Edges)),
	}
	nodeIndex := make(map[string]int, len(graph.Nodes))
	for _, node := range graph.Nodes {
		if index, exists := nodeIndex[node.ID]; exists {
			current := &merged.Nodes[index]
			current.Kinds = mergeStringsPreservingOrder(current.Kinds, node.Kinds)
			current.ObservationDomains = sdkingest.MergeObservationDomains(
				current.ObservationDomains,
				node.ObservationDomains,
			)
			if current.Properties == nil {
				current.Properties = make(map[string]any)
			}
			for key, value := range node.Properties {
				current.Properties[key] = value
			}
			continue
		}
		node.Properties = cloneProperties(node.Properties)
		node.ObservationDomains = sdkingest.MergeObservationDomains(node.ObservationDomains)
		nodeIndex[node.ID] = len(merged.Nodes)
		merged.Nodes = append(merged.Nodes, node)
	}

	edgeIndex := make(map[string]int, len(graph.Edges))
	for _, edge := range graph.Edges {
		key := edge.Source + "\x00" + edge.Kind + "\x00" + edge.Target
		if index, exists := edgeIndex[key]; exists {
			current := &merged.Edges[index]
			current.ObservationDomains = sdkingest.MergeObservationDomains(
				current.ObservationDomains,
				edge.ObservationDomains,
			)
			if current.SourceKind == "" {
				current.SourceKind = edge.SourceKind
			}
			if current.TargetKind == "" {
				current.TargetKind = edge.TargetKind
			}
			if current.Properties == nil {
				current.Properties = make(map[string]any)
			}
			for property, value := range edge.Properties {
				current.Properties[property] = value
			}
			continue
		}
		edge.Properties = cloneProperties(edge.Properties)
		edge.ObservationDomains = sdkingest.MergeObservationDomains(edge.ObservationDomains)
		edgeIndex[key] = len(merged.Edges)
		merged.Edges = append(merged.Edges, edge)
	}
	return merged
}

func mergeStringsPreservingOrder(first, second []string) []string {
	merged := append([]string(nil), first...)
	seen := make(map[string]bool, len(merged)+len(second))
	for _, value := range merged {
		seen[value] = true
	}
	for _, value := range second {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		merged = append(merged, value)
	}
	return merged
}

func cloneProperties(properties map[string]any) map[string]any {
	if properties == nil {
		return map[string]any{}
	}
	cloned := make(map[string]any, len(properties))
	for key, value := range properties {
		cloned[key] = value
	}
	return cloned
}

func parseArtifactObservedAt(value string) (*time.Time, error) {
	if strings.TrimSpace(value) == "" {
		return nil, nil
	}
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return nil, fmt.Errorf("artifact timestamp is not RFC3339: %w", err)
	}
	parsed = parsed.UTC()
	return &parsed, nil
}

func modelGraphSnapshot(stats *graph.GraphStats) *model.GraphSnapshot {
	if stats == nil {
		return nil
	}
	return &model.GraphSnapshot{
		NodeCounts: cloneInt64Map(stats.NodeCounts),
		EdgeCounts: cloneInt64Map(stats.EdgeCounts),
		TotalNodes: stats.TotalNodes,
		TotalEdges: stats.TotalEdges,
	}
}

func modelObservationCompleteness(
	completeness graph.ObservationCompleteness,
) model.PostureObservationCompleteness {
	return model.PostureObservationCompleteness{
		LegacyNodes:                     completeness.LegacyNodes,
		LegacyRelationships:             completeness.LegacyRelationships,
		UnscopedNodes:                   completeness.UnscopedNodes,
		UnscopedRelationships:           completeness.UnscopedRelationships,
		IncompletePropertyNodes:         completeness.IncompletePropertyNodes,
		IncompletePropertyRelationships: completeness.IncompletePropertyRelationships,
		IdentityQuarantinedNodes:        completeness.IdentityQuarantinedNodes,
	}
}

func sdkGraphTotals(snapshot *model.GraphSnapshot) *sdkingest.GraphTotals {
	if snapshot == nil {
		return nil
	}
	return &sdkingest.GraphTotals{
		NodeCounts: cloneInt64Map(snapshot.NodeCounts),
		EdgeCounts: cloneInt64Map(snapshot.EdgeCounts),
		TotalNodes: snapshot.TotalNodes,
		TotalEdges: snapshot.TotalEdges,
	}
}

func cloneInt64Map(values map[string]int64) map[string]int64 {
	out := make(map[string]int64, len(values))
	for key, value := range values {
		out[key] = value
	}
	return out
}

func comparisonKey(data *sdkingest.IngestData, attributionComplete bool) string {
	if !attributionComplete ||
		!sdkingest.CollectionCoverageComplete(data.Meta.Collection) ||
		data.Meta.Ruleset == nil ||
		data.Meta.Ruleset.LoadState != sdkingest.OutcomeComplete ||
		data.Meta.Ruleset.Digest == "" ||
		len(data.Meta.IdentitySchemes) == 0 {
		return ""
	}
	identity := append([]sdkingest.IdentityScheme(nil), data.Meta.IdentitySchemes...)
	sort.Slice(identity, func(i, j int) bool {
		left := identity[i].EntityKind + "\x00" + identity[i].Transport + "\x00" + identity[i].Scheme
		right := identity[j].EntityKind + "\x00" + identity[j].Transport + "\x00" + identity[j].Scheme
		if left == right {
			return identity[i].Version < identity[j].Version
		}
		return left < right
	})
	payload := struct {
		Coverage []string                   `json:"coverage"`
		Rules    string                     `json:"rules"`
		Identity []sdkingest.IdentityScheme `json:"identity"`
	}{
		Coverage: coverageKeys(data.Meta.Collection),
		Rules:    data.Meta.Ruleset.Digest,
		Identity: identity,
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(encoded)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func appendStage(
	result *sdkingest.IngestResult,
	name string,
	state sdkingest.OutcomeState,
	required bool,
	started time.Time,
	err error,
) {
	stage := sdkingest.StageResult{
		Name:     name,
		State:    state,
		Required: required,
		Duration: time.Since(started),
	}
	if err != nil {
		stage.Error = err.Error()
	}
	result.Stages = append(result.Stages, stage)
}

func buildScanMetadata(
	data *sdkingest.IngestData,
	result *sdkingest.IngestResult,
	graphBefore, graphAfter *model.GraphSnapshot,
	reconciliation graph.ReconciliationStats,
	observation graph.ObservationCompleteness,
	completeDomains []string,
) map[string]any {
	metadata := map[string]any{
		"collection":               data.Meta.Collection,
		"ruleset":                  data.Meta.Ruleset,
		"identity_schemes":         data.Meta.IdentitySchemes,
		"identity_aliases":         data.Meta.IdentityAliases,
		"stages":                   result.Stages,
		"count_semantics":          countSemanticsWriteRowsV1,
		"nodes_submitted":          result.NodesSubmitted,
		"edges_submitted":          result.EdgesSubmitted,
		"normalization_status":     result.NormalizationStatus,
		"normalization_warnings":   result.NormalizationWarnings,
		"complete_domains":         completeDomains,
		"reconciliation":           reconciliation,
		"observation_completeness": observation,
		"graph_stats_before":       graphBefore,
		"graph_stats_after":        graphAfter,
		"collector_version":        data.Meta.CollectorVersion,
		"artifact_extra":           data.Meta.Extra,
	}
	return metadata
}

func joinedStageErrors(errs ...error) string {
	var messages []string
	for _, err := range errs {
		if err != nil {
			messages = append(messages, err.Error())
		}
	}
	return strings.Join(messages, "; ")
}
