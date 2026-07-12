package analysis

import (
	"context"
	"fmt"
	"strings"

	"github.com/adithyan-ak/agenthound/server/internal/graph"
)

// Direction is the explicit allowed-direction policy for a traversal. It
// replaces the previous undirected shortestPath behaviour, where a path could
// be reported that no attacker could actually walk because it crossed one or
// more edges backwards.
type Direction string

const (
	// DirectionForward follows relationships only in their stored
	// source→target direction. This is the honest default: composite and raw
	// edges are emitted with attacker-flow orientation, so a forward-only walk
	// is one an attacker can actually take.
	DirectionForward Direction = "forward"
	// DirectionAny ignores orientation. Provided for callers that explicitly
	// want reachability regardless of direction; never the default.
	DirectionAny Direction = "any"
)

// TraversalPolicy bounds and shapes a minimum-weight path search.
type TraversalPolicy struct {
	// MaxHops caps the relationship depth. Must be >= 1.
	MaxHops int
	// Direction is the allowed-direction policy.
	Direction Direction
	// ExcludeComposite skips post-processor-inferred composite edges so the
	// reconstructed path is made only of observed collector facts.
	ExcludeComposite bool
	// CandidateLimit bounds how many candidate paths Neo4j returns for
	// in-process minimum-weight selection. Keeps the bounded walk cheap on
	// large graphs.
	CandidateLimit int
	// SourceProp / TargetProp are the node properties the source/target are
	// matched on. Default "objectid"; the HTTP weighted-path endpoint sets
	// "name" when the caller passed a human-readable identifier.
	SourceProp string
	TargetProp string
	// Generations, when non-empty, restricts the traversal to the current
	// logical generations: every node and relationship on a candidate path
	// must be observed by one of these generations, so a min-weight path never
	// crosses a retained (demoted) generation's facts.
	Generations []string
}

// DefaultTraversalPolicy is the single policy used to reconstruct an attack
// path when no dedicated per-edge-kind query applies: a forward-directed,
// hop-bounded walk over observed (non-composite) edges.
func DefaultTraversalPolicy() TraversalPolicy {
	return TraversalPolicy{
		MaxHops:          8,
		Direction:        DirectionForward,
		ExcludeComposite: true,
		CandidateLimit:   25,
	}
}

func (p TraversalPolicy) normalized() TraversalPolicy {
	if p.MaxHops < 1 {
		p.MaxHops = 1
	}
	if p.Direction == "" {
		p.Direction = DirectionForward
	}
	if p.CandidateLimit < 1 {
		p.CandidateLimit = 1
	}
	if p.SourceProp == "" {
		p.SourceProp = "objectid"
	}
	if p.TargetProp == "" {
		p.TargetProp = "objectid"
	}
	return p
}

// BoundedMinWeightPath runs one bounded, directed traversal from source to
// target and returns the minimum-total-weight path among the candidates.
//
// Selection policy (explicit, so callers can reason about it):
//   - Prefer fully-weighted paths. A path whose cost is fully known is
//     comparable; a path with any missing weight is not, and we do not let an
//     understated (missing-treated-as-zero) cost win.
//   - Among fully-weighted paths, choose the minimum total weight.
//   - If no fully-weighted path exists, choose the one with the fewest missing
//     weights (tie-break: fewest hops) and report its total as unknown (nil)
//     with the missing count, never a benign zero.
func BoundedMinWeightPath(ctx context.Context, db graph.GraphDB, source, target string, policy TraversalPolicy) (*AttackPath, error) {
	policy = policy.normalized()

	params := map[string]any{
		"source": source,
		"target": target,
	}
	if len(policy.Generations) > 0 {
		params["gens"] = policy.Generations
	}
	rows, err := db.Query(ctx, buildBoundedPathQuery(policy), params)
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, nil
	}

	var best *AttackPath
	for _, row := range rows {
		cand, perr := parseAttackPath(row)
		if perr != nil || cand == nil {
			continue
		}
		if best == nil || lessPath(cand, best) {
			best = cand
		}
	}
	return best, nil
}

// lessPath reports whether candidate a is a better (lower-cost) path than b
// under the selection policy documented on BoundedMinWeightPath.
func lessPath(a, b *AttackPath) bool {
	aComplete := a.WeightMissingCount == 0
	bComplete := b.WeightMissingCount == 0

	if aComplete != bComplete {
		return aComplete // a fully-weighted path always beats an unknown one
	}
	if aComplete && bComplete {
		return derefWeight(a.TotalRiskWeight) < derefWeight(b.TotalRiskWeight)
	}
	// Both incomplete: prefer fewer missing weights, then fewer hops.
	if a.WeightMissingCount != b.WeightMissingCount {
		return a.WeightMissingCount < b.WeightMissingCount
	}
	return len(a.Edges) < len(b.Edges)
}

func derefWeight(w *float64) float64 {
	if w == nil {
		return 0
	}
	return *w
}

// buildBoundedPathQuery renders the traversal Cypher. The hop bound and
// candidate limit are formatted as literals (Cypher forbids parameterised
// variable-length bounds); source/target are passed as parameters. The
// direction policy controls whether the pattern is directed (->) or undirected.
func buildBoundedPathQuery(policy TraversalPolicy) string {
	arrow := "->"
	if policy.Direction == DirectionAny {
		arrow = "-"
	}

	var filters []string
	if policy.ExcludeComposite {
		filters = append(filters, "ALL(r IN rels WHERE NOT coalesce(r.is_composite, false))")
	}
	if len(policy.Generations) > 0 {
		// Every node and relationship on the path must be in the current
		// generations, so a min-weight path never crosses retained facts.
		filters = append(filters, "ALL(n IN nodes(p) WHERE ANY(g IN coalesce(n.generations, []) WHERE g IN $gens))")
		filters = append(filters, "ALL(r IN rels WHERE ANY(g IN coalesce(r.generations, []) WHERE g IN $gens))")
	}
	compositeFilter := ""
	if len(filters) > 0 {
		compositeFilter = "WHERE " + strings.Join(filters, " AND ") + "\n"
	}

	return fmt.Sprintf(`MATCH p = (src {%s: $source})-[rels*1..%d]%s(tgt {%s: $target})
%sRETURN [n IN nodes(p) | {id: n.objectid, name: n.name, kinds: labels(n), properties: properties(n)}] AS nodes,
       [r IN relationships(p) | {kind: type(r), source: startNode(r).objectid, target: endNode(r).objectid, properties: properties(r)}] AS edges
LIMIT %d`, policy.SourceProp, policy.MaxHops, arrow, policy.TargetProp, compositeFilter, policy.CandidateLimit)
}
