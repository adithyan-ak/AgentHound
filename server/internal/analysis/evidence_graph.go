package analysis

import (
	"encoding/json"
	"math"
	"sort"
	"strconv"
)

func finalizeEvidenceGraph(path *AttackPath, issues []string) {
	if path.Nodes == nil {
		path.Nodes = []PathNode{}
	}
	if path.Edges == nil {
		path.Edges = []PathEdge{}
	}

	nodeIDs := make(map[string]struct{}, len(path.Nodes))
	for _, node := range path.Nodes {
		nodeIDs[node.ID] = struct{}{}
	}

	adjacency := make(map[string]map[string]struct{}, len(nodeIDs))
	degree := make(map[string]int, len(nodeIDs))
	for id := range nodeIDs {
		adjacency[id] = make(map[string]struct{})
	}
	missing := make(map[string]struct{})
	for i, edge := range path.Edges {
		_, sourceOK := nodeIDs[edge.Source]
		_, targetOK := nodeIDs[edge.Target]
		if !sourceOK {
			missing[edge.Source] = struct{}{}
			issues = append(issues, indexedReason("edge_source_missing_node", i))
		}
		if !targetOK {
			missing[edge.Target] = struct{}{}
			issues = append(issues, indexedReason("edge_target_missing_node", i))
		}
		if !sourceOK || !targetOK {
			continue
		}
		adjacency[edge.Source][edge.Target] = struct{}{}
		adjacency[edge.Target][edge.Source] = struct{}{}
		degree[edge.Source]++
		degree[edge.Target]++
	}

	path.Continuity = EvidenceContinuity{
		State:          EvidenceContinuityContinuous,
		ComponentCount: componentCount(nodeIDs, adjacency),
		MissingNodeIDs: sortedSet(missing),
	}

	switch {
	case len(path.Edges) == 0:
		path.Shape = EvidenceShapeNodesOnly
		path.Continuity.State = EvidenceContinuityNotApplicable
		path.Direction = EvidenceDirectionNotApplicable
	case len(missing) > 0 || path.Continuity.ComponentCount > 1:
		path.Shape = EvidenceShapeDisconnected
		path.Continuity.State = EvidenceContinuityDiscontinuous
		path.Direction = EvidenceDirectionNonLinear
	case graphHasCycle(path.Nodes, path.Edges):
		path.Shape = EvidenceShapeCyclic
		path.Direction = EvidenceDirectionNonLinear
	case isUndirectedLinear(path.Nodes, path.Edges, degree):
		path.Shape = EvidenceShapeLinear
		if linearization := directedLinearization(path.Nodes, path.Edges); linearization != nil {
			path.Linearization = linearization
			path.Direction = EvidenceDirectionForward
		} else {
			// The relationships form one undirected chain, but their recorded
			// directions cannot be walked continuously. Keep the exact graph
			// and withhold a path-like ordering.
			path.Direction = EvidenceDirectionMixed
		}
	default:
		path.Shape = EvidenceShapeBranched
		path.Direction = EvidenceDirectionNonLinear
	}

	setEvidenceCompleteness(path, issues)
	switch {
	case len(path.Edges) == 0:
		path.Cost = calculateAttackCost(path.Edges)
	case path.Shape != EvidenceShapeLinear || path.Linearization == nil:
		path.Cost = notApplicableAttackCost("non_linear_evidence")
	case path.Completeness.State != EvidenceStateComplete:
		path.Cost = incompleteAttackCost("evidence_incomplete")
	default:
		path.Cost = calculateAttackCost(path.Edges)
	}
	path.TotalRiskWeight = path.Cost.Value
}

func markExpectedEvidenceEndpoints(path *AttackPath, sourceID, targetID string) {
	if path == nil {
		return
	}
	nodeIDs := make(map[string]struct{}, len(path.Nodes))
	for _, node := range path.Nodes {
		nodeIDs[node.ID] = struct{}{}
	}

	var reasons []string
	missing := make(map[string]struct{}, len(path.Continuity.MissingNodeIDs)+2)
	for _, id := range path.Continuity.MissingNodeIDs {
		missing[id] = struct{}{}
	}
	for _, endpoint := range []struct {
		role string
		id   string
	}{
		{role: "source", id: sourceID},
		{role: "target", id: targetID},
	} {
		if endpoint.id == "" {
			continue
		}
		if _, ok := nodeIDs[endpoint.id]; !ok {
			missing[endpoint.id] = struct{}{}
			reasons = append(reasons, "finding_"+endpoint.role+"_missing")
		}
	}
	if len(reasons) > 0 {
		path.Continuity.State = EvidenceContinuityDiscontinuous
		path.Continuity.MissingNodeIDs = sortedSet(missing)
		path.Shape = EvidenceShapeDisconnected
		path.Direction = EvidenceDirectionNonLinear
		setEvidenceCompleteness(path, append(path.Completeness.Reasons, reasons...))
		path.Cost = incompleteAttackCost("finding_endpoint_missing")
		path.TotalRiskWeight = nil
		return
	}

	if path.Linearization == nil || len(path.Linearization.NodeIDs) == 0 {
		return
	}
	first := path.Linearization.NodeIDs[0]
	last := path.Linearization.NodeIDs[len(path.Linearization.NodeIDs)-1]
	switch {
	case first == sourceID && last == targetID:
		path.Direction = EvidenceDirectionForward
	case first == targetID && last == sourceID:
		path.Direction = EvidenceDirectionReverse
		path.Linearization = nil
		path.Cost = notApplicableAttackCost("reverse_to_finding_direction")
		path.TotalRiskWeight = nil
	default:
		// The graph is linear, but not a source-to-target path for this
		// finding. Do not let the UI present it as one.
		path.Direction = EvidenceDirectionMixed
		path.Linearization = nil
		path.Cost = notApplicableAttackCost("not_a_source_to_target_path")
		path.TotalRiskWeight = nil
	}
}

func calculateAttackCost(edges []PathEdge) AttackCost {
	cost := AttackCost{
		State:                    EvidenceStateNotApplicable,
		Reasons:                  []string{},
		MissingWeightEdgeIndexes: []int{},
	}
	if len(edges) == 0 {
		cost.Reasons = []string{"no_relationships"}
		return cost
	}

	var total float64
	for i, edge := range edges {
		weight, ok := evidenceFloat(edge.Properties["risk_weight"])
		if !ok || weight < 0 || math.IsNaN(weight) || math.IsInf(weight, 0) {
			cost.MissingWeightEdgeIndexes = append(cost.MissingWeightEdgeIndexes, i)
			continue
		}
		total += weight
	}
	if len(cost.MissingWeightEdgeIndexes) > 0 {
		cost.State = EvidenceStateIncomplete
		cost.Reasons = []string{"missing_risk_weight"}
		return cost
	}
	cost.State = EvidenceStateComplete
	cost.Value = &total
	return cost
}

func notApplicableAttackCost(reason string) AttackCost {
	return AttackCost{
		State:                    EvidenceStateNotApplicable,
		Reasons:                  []string{reason},
		MissingWeightEdgeIndexes: []int{},
	}
}

func incompleteAttackCost(reason string) AttackCost {
	return AttackCost{
		State:                    EvidenceStateIncomplete,
		Reasons:                  []string{reason},
		MissingWeightEdgeIndexes: []int{},
	}
}

func evidenceFloat(value any) (float64, bool) {
	switch number := value.(type) {
	case float64:
		return number, true
	case float32:
		return float64(number), true
	case int:
		return float64(number), true
	case int8:
		return float64(number), true
	case int16:
		return float64(number), true
	case int32:
		return float64(number), true
	case int64:
		return float64(number), true
	case uint:
		return float64(number), true
	case uint8:
		return float64(number), true
	case uint16:
		return float64(number), true
	case uint32:
		return float64(number), true
	case uint64:
		return float64(number), true
	case json.Number:
		parsed, err := number.Float64()
		return parsed, err == nil
	default:
		return 0, false
	}
}

func setEvidenceCompleteness(path *AttackPath, reasons []string) {
	reasons = sortedUnique(reasons)
	state := EvidenceStateComplete
	if len(reasons) > 0 {
		state = EvidenceStateIncomplete
	}
	path.Completeness = EvidenceCompleteness{
		State:   state,
		Reasons: reasons,
	}
}

func componentCount(
	nodeIDs map[string]struct{},
	adjacency map[string]map[string]struct{},
) int {
	visited := make(map[string]bool, len(nodeIDs))
	components := 0
	for id := range nodeIDs {
		if visited[id] {
			continue
		}
		components++
		queue := []string{id}
		visited[id] = true
		for len(queue) > 0 {
			current := queue[0]
			queue = queue[1:]
			for next := range adjacency[current] {
				if visited[next] {
					continue
				}
				visited[next] = true
				queue = append(queue, next)
			}
		}
	}
	return components
}

func graphHasCycle(nodes []PathNode, edges []PathEdge) bool {
	if len(edges) >= len(nodes) {
		return true
	}
	for _, edge := range edges {
		if edge.Source == edge.Target {
			return true
		}
	}
	return false
}

func isUndirectedLinear(nodes []PathNode, edges []PathEdge, degree map[string]int) bool {
	if len(nodes) < 2 || len(edges) != len(nodes)-1 {
		return false
	}
	endpoints := 0
	for _, node := range nodes {
		switch degree[node.ID] {
		case 1:
			endpoints++
		case 2:
		default:
			return false
		}
	}
	return endpoints == 2
}

func directedLinearization(nodes []PathNode, edges []PathEdge) *EvidenceLinearization {
	if len(nodes) < 2 || len(edges) != len(nodes)-1 {
		return nil
	}
	inDegree := make(map[string]int, len(nodes))
	outgoing := make(map[string][]int, len(nodes))
	for _, node := range nodes {
		inDegree[node.ID] = 0
	}
	for i, edge := range edges {
		inDegree[edge.Target]++
		outgoing[edge.Source] = append(outgoing[edge.Source], i)
	}

	start := ""
	endCount := 0
	for _, node := range nodes {
		in := inDegree[node.ID]
		out := len(outgoing[node.ID])
		switch {
		case in == 0 && out == 1:
			if start != "" {
				return nil
			}
			start = node.ID
		case in == 1 && out == 0:
			endCount++
		case in == 1 && out == 1:
		default:
			return nil
		}
	}
	if start == "" || endCount != 1 {
		return nil
	}

	linearization := &EvidenceLinearization{
		NodeIDs:     []string{start},
		EdgeIndexes: make([]int, 0, len(edges)),
	}
	visited := make(map[int]bool, len(edges))
	current := start
	for len(outgoing[current]) == 1 {
		edgeIndex := outgoing[current][0]
		if visited[edgeIndex] {
			return nil
		}
		visited[edgeIndex] = true
		linearization.EdgeIndexes = append(linearization.EdgeIndexes, edgeIndex)
		current = edges[edgeIndex].Target
		linearization.NodeIDs = append(linearization.NodeIDs, current)
	}
	if len(visited) != len(edges) || len(linearization.NodeIDs) != len(nodes) {
		return nil
	}
	return linearization
}

func indexedReason(reason string, index int) string {
	return reason + "_" + strconv.Itoa(index)
}

func sortedSet(values map[string]struct{}) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		if value != "" {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}

func sortedUnique(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			set[value] = struct{}{}
		}
	}
	return sortedSet(set)
}
